/*
 * Copyright (c) 2015-2016 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include "../core/accel_core_sdk.h"
#include "ipsec.h"
#include "ipsec_sysfs.h"
#include "ipsec_hw.h"
#include <linux/netdevice.h>
#include <linux/mlx5/qp.h>
#include <crypto/aead.h>

static LIST_HEAD(mlx_ipsec_devs);
static DEFINE_MUTEX(mlx_ipsec_mutex);
static int mlx_xfrm_add_state(struct xfrm_state *x);
static void mlx_xfrm_del_state(struct xfrm_state *x);
static void mlx_xfrm_free_state(struct xfrm_state *x);
static bool mlx_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x);
static struct sk_buff *mlx_ipsec_rx_handler(struct sk_buff *skb);
static struct sk_buff *mlx_ipsec_tx_handler(struct sk_buff *,
					    struct mlx5e_swp_info *swp_info);
static u16             mlx_ipsec_mtu_handler(u16 mtu, bool is_sw2hw);
static netdev_features_t mlx_ipsec_feature_chk(struct sk_buff *skb,
					       struct net_device *netdev,
					       netdev_features_t features,
					       bool *done);

#define MAX_LSO_MSS 2048
/* Pre-calculated (Q0.16) fixed-point inverse 1/x function */
static __be16 inverse_table[MAX_LSO_MSS];

static const struct xfrmdev_ops mlx_xfrmdev_ops = {
	.xdo_dev_state_add	= mlx_xfrm_add_state,
	.xdo_dev_state_delete	= mlx_xfrm_del_state,
	.xdo_dev_state_free	= mlx_xfrm_free_state,
	.xdo_dev_offload_ok	= mlx_ipsec_offload_ok,
};

static struct mlx5e_accel_client_ops mlx_ipsec_client_ops = {
	.rx_handler   = mlx_ipsec_rx_handler,
	.tx_handler   = mlx_ipsec_tx_handler,
	.feature_chk  = mlx_ipsec_feature_chk,
	.mtu_handler  = mlx_ipsec_mtu_handler,
	.get_count    = mlx_ipsec_get_count,
	.get_strings  = mlx_ipsec_get_strings,
	.get_stats    = mlx_ipsec_get_stats,
};

/* must hold mlx_ipsec_mutex to call this function */
static struct mlx_ipsec_dev *find_mlx_ipsec_dev_by_netdev(
		struct net_device *netdev)
{
	struct mlx_ipsec_dev *dev;

	list_for_each_entry(dev, &mlx_ipsec_devs, accel_dev_list) {
		if (dev->netdev == netdev)
			return dev;
	}

	return NULL;
}

struct mlx_ipsec_dev *mlx_ipsec_find_dev_by_netdev(struct net_device *netdev)
{
	struct mlx_ipsec_dev *dev;

	mutex_lock(&mlx_ipsec_mutex);
	dev = find_mlx_ipsec_dev_by_netdev(netdev);
	mutex_unlock(&mlx_ipsec_mutex);
	return dev;
}

static void mlx_ipsec_set_clear_bypass(struct mlx_ipsec_dev *dev, bool set)
{
	int res;
	u32 dw;

	res = mlx_accel_core_mem_read(dev->accel_device, 4,
				      IPSEC_BYPASS_ADDR, &dw,
				      MLX_ACCEL_ACCESS_TYPE_DONTCARE);
	if (res != 4) {
		pr_warn("IPSec bypass clear failed on read\n");
		return;
	}

	dw = set ? dw | IPSEC_BYPASS_BIT : dw & ~IPSEC_BYPASS_BIT;
	res = mlx_accel_core_mem_write(dev->accel_device, 4,
				       IPSEC_BYPASS_ADDR, &dw,
				       MLX_ACCEL_ACCESS_TYPE_DONTCARE);
	if (res != 4) {
		pr_warn("IPSec bypass clear failed on write\n");
		return;
	}
}

/*
 * returns 0 on success, negative error if failed to send message to FPGA
 * positive error if FPGA returned a bad response
 */
static int mlx_xfrm_add_state(struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.dev;
	struct mlx_ipsec_dev *dev;
	struct mlx_ipsec_sa_entry *sa_entry = NULL;
	unsigned long flags;
	int res;

	if (x->props.mode != XFRM_MODE_TUNNEL) {
		dev_info(&netdev->dev, "Only tunnel xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.aalgo != SADB_AALG_NONE) {
		dev_info(&netdev->dev, "Cannot offload authenticated xfrm states\n");
		return -EINVAL;
	}
	if (x->props.ealgo != SADB_X_EALG_AES_GCM_ICV16) {
		dev_info(&netdev->dev, "Only AES-GCM-ICV16 xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.calgo != SADB_X_CALG_NONE) {
		dev_info(&netdev->dev, "Cannot offload compressed xfrm states\n");
		return -EINVAL;
	}
	if (x->props.flags & XFRM_STATE_ESN) {
		dev_info(&netdev->dev, "Cannot offload ESN xfrm states\n");
		return -EINVAL;
	}
	if (x->props.family != AF_INET) {
		dev_info(&netdev->dev, "Only IPv4 xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->id.proto != IPPROTO_ESP) {
		dev_info(&netdev->dev, "Only ESP xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->encap) {
		dev_info(&netdev->dev, "Encapsulated xfrm state may not be offloaded\n");
		return -EINVAL;
	}
	if (!x->aead) {
		dev_info(&netdev->dev, "Cannot offload xfrm states without aead\n");
		return -EINVAL;
	}
	if (x->aead->alg_icv_len != 128) {
		dev_info(&netdev->dev, "Cannot offload xfrm states with AEAD ICV length other than 128bit\n");
		return -EINVAL;
	}
	if ((x->aead->alg_key_len != 128 + 32) &&
	    (x->aead->alg_key_len != 256 + 32)) {
		dev_info(&netdev->dev, "Cannot offload xfrm states with AEAD key length other than 128/256 bit\n");
		return -EINVAL;
	}
	if (x->tfcpad) {
		dev_info(&netdev->dev, "Cannot offload xfrm states without tfc padding\n");
		return -EINVAL;
	}
	if (!x->geniv) {
		dev_info(&netdev->dev, "Cannot offload xfrm states without geniv\n");
		return -EINVAL;
	}
	if (strcmp(x->geniv, "seqiv")) {
		dev_info(&netdev->dev, "Cannot offload xfrm states with geniv other than seqiv\n");
		return -EINVAL;
	}

	dev = mlx_ipsec_find_dev_by_netdev(netdev);
	if (!dev) {
		res = -EINVAL;
		goto out;
	}

	sa_entry = kzalloc(sizeof(struct mlx_ipsec_sa_entry), GFP_ATOMIC);
	if (!sa_entry) {
		res = -ENOMEM;
		goto out;
	}

	sa_entry->hw_sa_id = UNASSIGNED_SA_ID;
	sa_entry->sw_sa_id = atomic_inc_return(&dev->next_sw_sa_id);
	sa_entry->x = x;
	sa_entry->dev = dev;

	/* Add the SA to handle processed incoming packets before the add SA
	 * completion was received
	 */
	if (x->xso.flags & XFRM_OFFLOAD_INBOUND) {
		spin_lock_irqsave(&dev->sw_sa_id2xfrm_state_lock, flags);
		hash_add_rcu(dev->sw_sa_id2xfrm_state_table, &sa_entry->hlist,
				sa_entry->sw_sa_id);
		spin_unlock_irqrestore(&dev->sw_sa_id2xfrm_state_lock, flags);
	}

	res = mlx_ipsec_hw_sadb_add(sa_entry);
	if (res)
		goto err_hash_rcu;

	x->xso.offload_handle = (unsigned long)sa_entry;
	try_module_get(THIS_MODULE);
	goto out;

err_hash_rcu:
	if (x->xso.flags & XFRM_OFFLOAD_INBOUND) {
		spin_lock_irqsave(
				&dev->sw_sa_id2xfrm_state_lock,
				flags);
		hash_del_rcu(&sa_entry->hlist);
		spin_unlock_irqrestore(
				&dev->sw_sa_id2xfrm_state_lock,
				flags);
		synchronize_rcu();
	}

	kfree(sa_entry);
	sa_entry = NULL;
out:
	return res;
}

static void mlx_xfrm_del_state(struct xfrm_state *x)
{
	struct mlx_ipsec_sa_entry *sa_entry;

	if (!x->xso.offload_handle)
		return;

	sa_entry = (struct mlx_ipsec_sa_entry *)x->xso.offload_handle;
	WARN_ON(sa_entry->x != x);

	if (x->xso.flags & XFRM_OFFLOAD_INBOUND)
		hash_del_rcu(&sa_entry->hlist);
}

static void mlx_xfrm_free_state(struct xfrm_state *x)
{
	struct mlx_ipsec_sa_entry *sa_entry;

	if (!x->xso.offload_handle)
		return;

	sa_entry = (struct mlx_ipsec_sa_entry *)x->xso.offload_handle;
	WARN_ON(sa_entry->x != x);

	mlx_ipsec_hw_sadb_del(sa_entry);

	if (x->xso.flags & XFRM_OFFLOAD_INBOUND)
		synchronize_rcu();

	kfree(sa_entry);
	module_put(THIS_MODULE);
}

static struct xfrm_state *mlx_sw_sa_id_to_xfrm_state(struct mlx_ipsec_dev *dev,
		unsigned int sw_sa_id) {
	struct mlx_ipsec_sa_entry *sa_entry;

	rcu_read_lock();
	hash_for_each_possible_rcu(dev->sw_sa_id2xfrm_state_table, sa_entry,
				hlist, sw_sa_id) {
		if (sa_entry->sw_sa_id == sw_sa_id) {
			rcu_read_unlock();
			return sa_entry->x;
		}
	}
	rcu_read_unlock();
	pr_warn("mlx_sw_sa_id_to_xfrm_state(): didn't find SA entry for %x\n",
		sw_sa_id);
	return NULL;
}

static void remove_pet(struct sk_buff *skb, struct pet *pet)
{
	struct ethhdr *old_eth;
	struct ethhdr *new_eth;

	memcpy(pet, skb->data, sizeof(*pet));
	old_eth = (struct ethhdr *)(skb->data - sizeof(struct ethhdr));
	new_eth = (struct ethhdr *)(skb_pull_inline(skb, sizeof(struct pet)) -
		sizeof(struct ethhdr));
	skb->mac_header += sizeof(struct pet);

	memmove(new_eth, old_eth, 2 * ETH_ALEN);
	/* Ethertype is already in its new place */
}

static void remove_dummy_dword(struct sk_buff *skb)
{
	struct iphdr *iphdr = (struct iphdr *)skb->data;
	unsigned char *old;
	unsigned char *new;
	unsigned int iphdr_len = iphdr->ihl * 4;

	/* We expect IP header right after the PET
	 * with no IP options, all other are not offloaded for now
	 */
	if (be16_to_cpu(skb->protocol) != ETH_P_IP)
		pr_warn("expected ETH_P_IP but received %04x\n",
			be16_to_cpu(skb->protocol));
	if (iphdr_len > sizeof(struct iphdr))
		pr_warn("expected ETH_P_IP without IP options\n");

	if (iphdr->protocol != IPPROTO_DUMMY_DWORD)
		return;

	old = skb->data - sizeof(struct ethhdr);
	new = skb_pull_inline(skb, sizeof(struct dummy_dword)) -
			      sizeof(struct ethhdr);
	iphdr->protocol = IPPROTO_ESP; /* TODO */
	iphdr->tot_len = htons(ntohs(iphdr->tot_len) - 4);
	iphdr->check = htons(~(~ntohs(iphdr->check) - 0xd1));

	memmove(new, old, ETH_HLEN + iphdr_len);

	skb->mac_header += sizeof(struct dummy_dword);
}

static struct pet *insert_pet(struct sk_buff *skb)
{
	struct ethhdr *eth;
	struct pet *pet;

	if (skb_cow_head(skb, sizeof(struct pet)))
		return ERR_PTR(-ENOMEM);

	eth = (struct ethhdr *)skb_push(skb, sizeof(struct pet));
	skb->mac_header -= sizeof(struct pet);
	pet = (struct pet *)(eth+1);

	memmove(skb->data, skb->data + sizeof(struct pet), 2 * ETH_ALEN);

	eth->h_proto = cpu_to_be16(MLX_IPSEC_PET_ETHERTYPE);

	memset(pet->content.raw, 0, sizeof(pet->content.raw));

	return pet;
}

static bool mlx_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	return true;
}

static u16 mlx_ipsec_mtu_handler(u16 mtu, bool is_sw2hw)
{
	u16 mtu_diff = sizeof(struct pet) + sizeof(struct dummy_dword);

	if (is_sw2hw)
		return mtu + mtu_diff;
	else
		return mtu - mtu_diff;
}

static __be16 mlx_ipsec_mss_inv(struct sk_buff *skb)
{
	return inverse_table[skb_shinfo(skb)->gso_size];
}

static netdev_features_t mlx_ipsec_feature_chk(struct sk_buff *skb,
					       struct net_device *netdev,
					       netdev_features_t features,
					       bool *done)
{
	struct xfrm_state *x;

	if (skb->sp && skb->sp->len) {
		x = skb->sp->xvec[0];
		if (x && x->xso.offload_handle)
			*done = true;
	}
	return features;
}

static void remove_trailer(struct sk_buff *skb, struct xfrm_state *x,
			   u8 *proto)
{
	skb_frag_t *frag;
	u8 *vaddr;
	u8 *trailer;
	unsigned char last_frag;
	struct crypto_aead *aead = x->data;
	int alen = crypto_aead_authsize(aead);
	int plen;
	unsigned int trailer_len = alen;
	struct iphdr *iphdr = (struct iphdr *)skb_network_header(skb);

	if (skb_is_nonlinear(skb) && skb_shinfo(skb)->nr_frags) {
		last_frag = skb_shinfo(skb)->nr_frags - 1;
		frag = &skb_shinfo(skb)->frags[last_frag];

		skb_frag_ref(skb, last_frag);
		vaddr = kmap_atomic(skb_frag_page(frag));

		trailer = vaddr + frag->page_offset;
		plen = trailer[skb_frag_size(frag) - alen - 2];
		dev_dbg(&skb->dev->dev, "   Last frag page addr %p offset %u size %u\n",
			vaddr, frag->page_offset, frag->size);
		print_hex_dump_bytes("Last frag ", DUMP_PREFIX_OFFSET,
				     trailer, frag->size);

		*proto = trailer[skb_frag_size(frag) - alen - 1];

		kunmap_atomic(vaddr);
		skb_frag_unref(skb, last_frag);

		dev_dbg(&skb->dev->dev, "   Frag pad len is %u bytes; alen is %u\n",
			plen, alen);
	} else {
		plen = *(skb_tail_pointer(skb) - alen - 2);
		*proto = *(skb_tail_pointer(skb) - alen - 1);
		dev_dbg(&skb->dev->dev, "   Pad len is %u bytes; alen is %u\n",
			plen, alen);
	}
	trailer_len += plen + 2;

	dev_dbg(&skb->dev->dev, "   Removing trailer %u bytes\n", trailer_len);
	pskb_trim(skb, skb->len - trailer_len);
	iphdr->tot_len = htons(ntohs(iphdr->tot_len) - trailer_len);
	iphdr->check = htons(~(~ntohs(iphdr->check) - trailer_len));
}

static struct sk_buff *mlx_ipsec_tx_handler(struct sk_buff *skb,
					    struct mlx5e_swp_info *swp_info)
{
	struct tcphdr *tcph;
	struct ip_esp_hdr *esph;
	struct iphdr *iiph;
	struct xfrm_state *x;
	struct pet *pet;
	int iv_offset;
	__be64 seqno;

	dev_dbg(&skb->dev->dev, ">> tx_handler %u bytes\n", skb->len);

	if (!skb->sp) {
		dev_dbg(&skb->dev->dev, "   no sp\n");
		goto out;
	}

	if (skb->sp->len != 1) {
		pr_warn_ratelimited("Cannot offload crypto for a bundle of %u XFRM states\n",
				    skb->sp->len);
		goto out;
	}

	x = skb->sp->xvec[0];
	if (!x) {
		pr_warn_ratelimited("Crypto-offload packet has no xfrm_state\n");
		goto out;
	}

	if (x->xso.offload_handle &&
	    skb->protocol == htons(ETH_P_IP)) {
		iiph = (struct iphdr *)skb_inner_network_header(skb);
		pet = insert_pet(skb);
		if (IS_ERR(pet)) {
			pr_warn("insert_pet failed: %ld\n", PTR_ERR(pet));
			kfree_skb(skb);
			skb = NULL;
			goto out;
		}

		/* Offsets are in 2-byte words, counting from start of frame */
		swp_info->outer_l3_ofs = skb_network_offset(skb) / 2;
		swp_info->inner_l3_ofs = skb_inner_network_offset(skb) / 2;
		switch (iiph->protocol) {
		case IPPROTO_UDP:
			swp_info->swp_flags |= MLX5_ETH_WQE_SWP_INNER_L4_UDP;
			/* Fall through */
		case IPPROTO_TCP:
			swp_info->inner_l4_ofs =
				skb_inner_transport_offset(skb) / 2;
			break;
		}

		/* Place the SN in the IV field */
		seqno = cpu_to_be64(XFRM_SKB_CB(skb)->seq.output.low +
			    ((u64)XFRM_SKB_CB(skb)->seq.output.hi << 32));
		iv_offset = skb->transport_header + sizeof(struct ip_esp_hdr)
					- skb_headroom(skb);
		skb_store_bits(skb, iv_offset, &seqno, 8);

		if (skb_is_gso(skb)) {
			/* Add LSO PET indication */
			esph = (struct ip_esp_hdr *)skb_transport_header(skb);
			tcph = inner_tcp_hdr(skb);
			dev_dbg(&skb->dev->dev, "   Offloading GSO packet of len %u; mss %u; TCP sp %u dp %u seq 0x%x ESP seq 0x%x\n",
				skb->len, skb_shinfo(skb)->gso_size,
				ntohs(tcph->source), ntohs(tcph->dest),
				ntohl(tcph->seq), ntohl(esph->seq_no));
			pet->syndrome = PET_SYNDROME_OFFLOAD_WITH_LSO_TCP;
			pet->content.send.mss_inv = mlx_ipsec_mss_inv(skb);
			pet->content.send.seq = htons(ntohl(tcph->seq) &
						0xFFFF);
			pet->content.send.esp_next_proto = skb->sp->proto;
		} else {
			pet->syndrome = PET_SYNDROME_OFFLOAD;
			remove_trailer(skb, x,
				       &pet->content.send.esp_next_proto);
		}

		dev_dbg(&skb->dev->dev, "   TX PKT len %u linear %u bytes + %u bytes in %u frags\n",
			skb->len, skb_headlen(skb), skb->data_len,
			skb->data_len ? skb_shinfo(skb)->nr_frags : 0);
		dev_dbg(&skb->dev->dev, "   TX PET syndrome %u proto %u mss_inv %04x seq %04x\n",
			pet->syndrome, pet->content.send.esp_next_proto,
			ntohs(pet->content.send.mss_inv),
			ntohs(pet->content.send.seq));
	}
out:
	dev_dbg(&skb->dev->dev, "<< tx_handler\n");
	return skb;
}

static struct sk_buff *mlx_ipsec_rx_handler(struct sk_buff *skb)
{
	struct pet pet;
	struct xfrm_offload_state *xos;
	struct mlx_ipsec_dev *dev;
	struct net_device *netdev = skb->dev;
	struct xfrm_state *xs;

	if (skb->protocol != cpu_to_be16(MLX_IPSEC_PET_ETHERTYPE))
		goto out;

	dev_dbg(&netdev->dev, ">> rx_handler %u bytes\n", skb->len);
	remove_pet(skb, &pet);
	dev_dbg(&netdev->dev, "   RX PET: size %lu, etherType %04X, syndrome %02x, sw_sa_id %x\n",
		sizeof(pet), be16_to_cpu(pet.ethertype), pet.syndrome,
		be32_to_cpu(pet.content.rcv.sa_id));

	skb->protocol = pet.ethertype;

	remove_dummy_dword(skb);

	WARN_ON(skb->sp != NULL);
	skb->sp = secpath_dup(skb->sp);
	if (unlikely(!skb->sp)) { /* drop */
		pr_warn("Failed to allocate secpath - dropping!\n");
		goto drop;
	}

	dev = find_mlx_ipsec_dev_by_netdev(netdev);
	xs = mlx_sw_sa_id_to_xfrm_state(dev,
			be32_to_cpu(pet.content.rcv.sa_id));

	if (!xs) {
		pr_warn("No xfrm_state found for processed packet\n");
		goto drop;
	}

	/* xfrm_input expects us to hold the xfrm_state */
	xfrm_state_hold(xs);
	skb->sp->xvec[skb->sp->len++] = xs;

	xos = xfrm_offload_input(skb);
	xos->flags = CRYPTO_DONE;
	switch (pet.syndrome) {
	case PET_SYNDROME_DECRYPTED:
		xos->status = CRYPTO_SUCCESS;
		break;
	case PET_SYNDROME_AUTH_FAILED:
		xos->status = CRYPTO_TUNNEL_ESP_AUTH_FAILED;
		break;
	default:
		pr_warn("Unknown metadata syndrom %d\n", pet.syndrome);
		goto drop;
	}
	goto out;

drop:
	kfree_skb(skb);
	dev_dbg(&netdev->dev, "   rx_handler: dropping packet\n");
	skb = NULL;
out:
	dev_dbg(&netdev->dev, "<< rx_handler\n");
	return skb;
}

/* Must hold mlx_ipsec_mutex to call this function.
 * Assumes that dev->core_ctx is destroyed be the caller
 */
static void mlx_ipsec_free(struct mlx_ipsec_dev *dev)
{
	list_del(&dev->accel_dev_list);
	kobject_put(&dev->kobj);
}

void mlx_ipsec_dev_release(struct kobject *kobj)
{
	struct mlx_ipsec_dev *ipsec_dev =
			container_of(kobj, struct mlx_ipsec_dev, kobj);

	/*
	 * [BP]: TODO - Test the corner case of removing the last reference
	 * while receiving packets that should be handled by the rx_handler.
	 * Do we need some sync here?
	 */

	dev_put(ipsec_dev->netdev);

	kfree(ipsec_dev);
}

int mlx_ipsec_netdev_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct mlx_ipsec_dev *accel_dev = NULL;

	if (!netdev)
		goto out;

	pr_debug("mlx_ipsec_netdev_event: %lu\n", event);

	/* We are interested only in net devices going down */
	if (event != NETDEV_UNREGISTER)
		goto out;

	/* Take down all connections using a netdev that is going down */
	mutex_lock(&mlx_ipsec_mutex);
	accel_dev = find_mlx_ipsec_dev_by_netdev(netdev);
	if (!accel_dev) {
		pr_debug("mlx_ipsec_netdev_event: Failed to find ipsec device for net device\n");
		goto unlock;
	}
	mlx_accel_core_client_ops_unregister(netdev);
	mlx_ipsec_free(accel_dev);

unlock:
	mutex_unlock(&mlx_ipsec_mutex);
out:
	return NOTIFY_DONE;
}

int mlx_ipsec_add_one(struct mlx_accel_core_device *accel_device)
{
	int ret = 0;
	int i;
	struct mlx_ipsec_dev *dev = NULL;
	struct net_device *netdev = NULL;
#ifdef MLX_IPSEC_SADB_RDMA
	struct mlx_accel_core_conn_init_attr init_attr = {0};
#endif

	pr_debug("mlx_ipsec_add_one called for %s\n", accel_device->name);

	if (MLX5_CAP_FPGA(accel_device->hw_dev, sandbox_product_id) !=
			MLX5_FPGA_CAP_SANDBOX_PRODUCT_ID_IPSEC) {
		ret = -EINVAL;
		goto out;
	}

	dev = kzalloc(sizeof(struct mlx_ipsec_dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mlx_accel_get_sbu_caps(accel_device, sizeof(dev->ipsec_caps),
				     (void *)dev->ipsec_caps);
	if (ret) {
		pr_err("Failed to retrieve ipsec extended capabilities\n");
		goto err_dev;
	}
	/*Need to reverse endianness to use MLX5_GET macros*/
	for (i = 0; i < sizeof(dev->ipsec_caps) / 4; i++)
		dev->ipsec_caps[i] = cpu_to_be32(dev->ipsec_caps[i]);

	init_waitqueue_head(&dev->wq);
	INIT_LIST_HEAD(&dev->accel_dev_list);
	INIT_KFIFO(dev->fifo_sa_cmds);
	hash_init(dev->sw_sa_id2xfrm_state_table);
	spin_lock_init(&dev->sw_sa_id2xfrm_state_lock);
	spin_lock_init(&dev->fifo_sa_cmds_lock);
	atomic_set(&dev->next_sw_sa_id, 0);
	dev->accel_device = accel_device;

#ifdef MLX_IPSEC_SADB_RDMA
	/* [BP]: TODO: Move these constants to a header */
	init_attr.rx_size = 8;
	init_attr.tx_size = 8;
	init_attr.recv_cb = mlx_ipsec_hw_qp_recv_cb;
	init_attr.cb_arg = dev;
	/* [AY]: TODO: fix port 1 issue */
	dev->conn = mlx_accel_core_conn_create(accel_device, &init_attr);
	if (IS_ERR(dev->conn)) {
		ret = PTR_ERR(dev->conn);
		pr_err("mlx_ipsec_add_one(): Got error while creating connection %d\n",
				ret);
		goto err_dev;
	}
	ret = mlx_accel_core_connect(dev->conn);
	if (ret) {
		pr_err("Failed to connect IPSec QP: %d\n", ret);
		goto err_conn;
	}
#endif
	netdev = accel_device->ib_dev->get_netdev(accel_device->ib_dev,
						  accel_device->port);
	if (!netdev) {
		pr_err("mlx_ipsec_add_one(): Failed to retrieve net device from ib device\n");
		ret = -EINVAL;
		goto err_conn;
	}
	dev->netdev = netdev;

	netif_keep_dst(dev->netdev);

	ret = mlx_accel_core_client_ops_register(netdev, &mlx_ipsec_client_ops);
	if (ret) {
		pr_err("mlx_ipsec_add_one(): Failed to register client ops %d\n",
		       ret);
		goto err_netdev;
	}

	ret = ipsec_sysfs_init_and_add(&dev->kobj,
			mlx_accel_core_kobj(dev->accel_device),
			"%s",
			"accel_dev");
	if (ret) {
		pr_err("mlx_ipsec_add_one(): Got error from kobject_init_and_add %d\n", ret);
		goto err_ops_register;
	}

	mutex_lock(&mlx_ipsec_mutex);
	list_add(&dev->accel_dev_list, &mlx_ipsec_devs);
	mutex_unlock(&mlx_ipsec_mutex);

	dev->netdev->xfrmdev_ops = &mlx_xfrmdev_ops;
	if (MLX5_GET(ipsec_extended_cap, dev->ipsec_caps, esp)) {
		dev->netdev->wanted_features |= NETIF_F_HW_ESP |
						NETIF_F_HW_ESP_TX_CSUM;
		dev->netdev->hw_features |= NETIF_F_HW_ESP |
					    NETIF_F_HW_ESP_TX_CSUM;
		if (MLX5_GET(ipsec_extended_cap, dev->ipsec_caps, lso)) {
			dev_dbg(&dev->netdev->dev, "ESP GSO capability turned on\n");
			dev->netdev->wanted_features |= NETIF_F_GSO_ESP;
			dev->netdev->hw_features |= NETIF_F_GSO_ESP;
			dev->netdev->hw_enc_features |= NETIF_F_GSO_ESP;
		}
	}

	rtnl_lock();
	netdev_change_features(dev->netdev);
	rtnl_unlock();

	mlx_ipsec_set_clear_bypass(dev, false);
	dev_info(&dev->netdev->dev, "mlx_ipsec added on device %s\n",
		 accel_device->name);
	goto out;

err_ops_register:
	mlx_accel_core_client_ops_unregister(netdev);
err_netdev:
	dev_put(netdev);
err_conn:
#ifdef MLX_IPSEC_SADB_RDMA
	mlx_accel_core_conn_destroy(dev->conn);
#endif
err_dev:
	kfree(dev);
out:
	return ret;
}

/* [BP]: TODO - Remove all SA entries on mlx_xfrm_del_state */
/* [BP]: TODO - How do we make sure that all packets inflight are dropped? */
void mlx_ipsec_remove_one(struct mlx_accel_core_device *accel_device)
{
	struct mlx_ipsec_dev *dev;
	struct net_device *netdev = NULL;

	pr_debug("mlx_ipsec_remove_one called for %s\n", accel_device->name);

	mutex_lock(&mlx_ipsec_mutex);

	list_for_each_entry(dev, &mlx_ipsec_devs, accel_dev_list) {
		if (dev->accel_device == accel_device) {
			dev->netdev->wanted_features &= ~(NETIF_F_HW_ESP |
				NETIF_F_HW_ESP_TX_CSUM | NETIF_F_GSO_ESP);
			dev->netdev->hw_enc_features &= ~NETIF_F_GSO_ESP;
			netdev = dev->netdev;
#ifdef MLX_IPSEC_SADB_RDMA
			mlx_accel_core_conn_destroy(dev->conn);
#endif
			mlx_ipsec_set_clear_bypass(dev, true);
			mlx_accel_core_client_ops_unregister(netdev);
			mlx_ipsec_free(dev);
			break;
		}
	}
	mutex_unlock(&mlx_ipsec_mutex);

	/* Remove NETIF_F_HW_ESP feature.
	 * We assume that xfrm ops are assigned by xfrm_dev notifier callback
	 */
	if (netdev) {
		rtnl_lock();
		netdev_change_features(netdev);
		rtnl_unlock();
	}
}

void mlx_ipsec_init_inverse_table(void)
{
	u32 mss;

	inverse_table[1] = 0xFFFF;
	for (mss = 2; mss < MAX_LSO_MSS; mss++)
		inverse_table[mss] = htons(((1ULL << 32) / mss) >> 16);
}
