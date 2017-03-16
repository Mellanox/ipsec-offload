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

#include <crypto/internal/geniv.h>
#include <crypto/aead.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <net/esp.h>

#include "en.h"
#include "fpga/core.h"
#include "en_ipsec/ipsec.h"
#include "en_ipsec/cmds.h"

#define MAX_LSO_MSS 2048
#define SBU_QP_QUEUE_SIZE 8
/* Pre-calculated (Q0.16) fixed-point inverse 1/x function */
static __be16 inverse_table[MAX_LSO_MSS];

struct mlx5_ipsec_sa_entry {
	struct hlist_node hlist; /* Item in SADB_RX hashtable */
	unsigned int handle; /* Handle in SADB_RX */
	struct xfrm_state *x;
	enum mlx5_ipsec_response_syndrome status;
	struct completion complete;
	struct mlx5_ipsec_dev *dev;
	struct list_head list; /* Item in pending_cmds */
};

struct ipsec_command_buf {
	struct mlx5_fpga_dma_buf buf;
	struct mlx5_ipsec_sa_entry *sa_entry;
};

static int sadb_rx_add(struct mlx5_ipsec_sa_entry *sa_entry)
{
	int ret;
	struct mlx5_ipsec_dev *dev = sa_entry->dev;
	unsigned long flags;

	spin_lock_irqsave(&dev->sadb_rx_lock, flags);
	ret = ida_simple_get(&dev->halloc, 1, 0, GFP_KERNEL);
	if (ret < 0)
		goto out;

	sa_entry->handle = ret;
	hash_add_rcu(dev->sadb_rx, &sa_entry->hlist, sa_entry->handle);
	ret = 0;

out:
	spin_unlock_irqrestore(&dev->sadb_rx_lock, flags);
	return ret;
}

static void sadb_rx_del(struct mlx5_ipsec_sa_entry *sa_entry)
{
	struct mlx5_ipsec_dev *dev = sa_entry->dev;
	unsigned long flags;

	spin_lock_irqsave(&dev->sadb_rx_lock, flags);
	hash_del_rcu(&sa_entry->hlist);
	spin_unlock_irqrestore(&dev->sadb_rx_lock, flags);
}

static void sadb_rx_free(struct mlx5_ipsec_sa_entry *sa_entry)
{
	struct mlx5_ipsec_dev *dev = sa_entry->dev;
	unsigned long flags;

	synchronize_rcu();
	spin_lock_irqsave(&dev->sadb_rx_lock, flags);
	ida_simple_remove(&dev->halloc, sa_entry->handle);
	spin_unlock_irqrestore(&dev->sadb_rx_lock, flags);
}

static enum mlx5_ipsec_enc_mode mlx5_ipsec_enc_mode(struct xfrm_state *x)
{
	unsigned int key_len = (x->aead->alg_key_len + 7) / 8 - 4;

	switch (key_len) {
	case 16:
		return SADB_MODE_AES_GCM_128_AUTH_128;
	case 32:
		return SADB_MODE_AES_GCM_256_AUTH_128;
	default:
		netdev_warn(x->xso.dev, "Bad key len: %d for alg %s\n",
			    key_len, x->aead->alg_name);
		return -1;
	}
}

static void mlx5_ipsec_build_sadb_cmd(struct xfrm_state *x, unsigned int handle,
				      struct mlx5_ipsec_sadb_cmd *hw_cmd)
{
	unsigned int crypto_data_len;
	unsigned int key_len;
	struct crypto_aead *aead;
	struct aead_geniv_ctx *geniv_ctx;
	int ivsize;

	BUILD_BUG_ON((sizeof(struct mlx5_ipsec_sadb_cmd) & 3) != 0);

	if (hw_cmd->cmd == MLX5_IPSEC_CMD_ADD_SA) {
		crypto_data_len = (x->aead->alg_key_len + 7) / 8;
		key_len = crypto_data_len - 4; /* 4 bytes salt at end */
		aead = x->data;
		geniv_ctx = crypto_aead_ctx(aead);
		ivsize = crypto_aead_ivsize(aead);

		memcpy(&hw_cmd->key_enc, x->aead->alg_key, key_len);
		/* Duplicate 128 bit key twice according to HW layout */
		if (key_len == 16)
			memcpy(&hw_cmd->key_enc[16], x->aead->alg_key, key_len);
		memcpy(&hw_cmd->gcm.salt_iv, geniv_ctx->salt, ivsize);
		hw_cmd->gcm.salt = *((__be32 *)(x->aead->alg_key + key_len));
	}

	hw_cmd->flags |= MLX5_IPSEC_SADB_SA_VALID | MLX5_IPSEC_SADB_SPI_EN;
	hw_cmd->sip[3] = x->props.saddr.a4;
	hw_cmd->sip_masklen = 32;
	hw_cmd->dip[3] = x->id.daddr.a4;
	hw_cmd->dip_masklen = 32;
	hw_cmd->spi = x->id.spi;
	hw_cmd->sw_sa_handle = htonl(handle);
	switch (x->id.proto) {
	case IPPROTO_ESP:
		hw_cmd->flags |= MLX5_IPSEC_SADB_IP_ESP;
		break;
	case IPPROTO_AH:
		hw_cmd->flags |= MLX5_IPSEC_SADB_IP_AH;
		break;
	default:
		break;
	}
	hw_cmd->enc_mode = mlx5_ipsec_enc_mode(x);
	if (!(x->xso.flags & XFRM_OFFLOAD_INBOUND))
		hw_cmd->flags |= MLX5_IPSEC_SADB_DIR_SX;
}

void mlx5_ipsec_hw_send_complete(struct mlx5_fpga_device *fdev,
				 struct mlx5_fpga_conn *conn,
				 struct mlx5_fpga_dma_buf *buf, u8 status)
{
	struct ipsec_command_buf *cmd_buf;

	cmd_buf = container_of(buf, struct ipsec_command_buf, buf);
	if (status) {
		mlx5_core_warn(fdev->mdev, "IPSec command send failed with status %u\n",
			       status);
		cmd_buf->sa_entry->status = MLX5_IPSEC_SA_SEND_FAIL;
		complete(&cmd_buf->sa_entry->complete);
	}
	kfree(cmd_buf);
}

int mlx5_ipsec_hw_sadb_wait(struct mlx5_ipsec_sa_entry *sa)
{
	int res;

	res = wait_for_completion_killable(&sa->complete);
	if (res) {
		netdev_warn(sa->dev->en_priv->netdev, "Failure waiting for IPSec command response\n");
		return -EINTR;
	}
	return 0;
}

static int mlx5_ipsec_hw_cmd(struct mlx5_ipsec_sa_entry *sa, u32 cmd_id)
{
	struct ipsec_command_buf *buf = NULL;
	struct mlx5_ipsec_sadb_cmd *cmd;
	int res = 0;
	unsigned long flags;

	buf = kzalloc(sizeof(*buf) + sizeof(*cmd), GFP_ATOMIC);
	if (!buf)
		return -ENOMEM;

	buf->sa_entry = sa;
	buf->buf.complete = mlx5_ipsec_hw_send_complete;
	buf->buf.sg[0].size = sizeof(*cmd);
	buf->buf.sg[0].data = buf + 1;
	cmd = buf->buf.sg[0].data;
	cmd->cmd = htonl(cmd_id);

	mlx5_ipsec_build_sadb_cmd(sa->x, sa->handle, cmd);

	netdev_dbg(sa->dev->en_priv->netdev, "adding cmd: sa %p handle 0x%08x\n",
		   sa, sa->handle);
	spin_lock_irqsave(&sa->dev->pending_cmds_lock, flags);
	list_add_tail(&sa->list, &sa->dev->pending_cmds);
	spin_unlock_irqrestore(&sa->dev->pending_cmds_lock, flags);
	init_completion(&sa->complete);

	sa->status = MLX5_IPSEC_SA_PENDING;
	res = mlx5_fpga_sbu_conn_sendmsg(sa->dev->en_priv->mdev->fpga,
					 &buf->buf);
	if (res) {
		netdev_warn(sa->dev->en_priv->netdev, "Failure sending IPSec command: %d\n",
			    res);
		spin_lock_irqsave(&sa->dev->pending_cmds_lock, flags);
		list_del(&sa->list);
		spin_unlock_irqrestore(&sa->dev->pending_cmds_lock, flags);
		kfree(buf);
	}
	/* If successful, buf will be freed by completion */
	return res;
}

int mlx5_ipsec_errno(enum mlx5_ipsec_response_syndrome status)
{
	int ret = 0;

	switch (status) {
	case MLX5_IPSEC_RESPONSE_SUCCESS:
		break;
	case MLX5_IPSEC_RESPONSE_SADB_ISSUE:
		ret = -EEXIST;
		break;
	case MLX5_IPSEC_RESPONSE_ILLEGAL_REQUEST:
	case MLX5_IPSEC_RESPONSE_WRITE_RESPONSE_ISSUE:
	default:
		ret = -EIO;
		break;
	}
	return ret;
}

int mlx5_ipsec_hw_sadb_add(struct mlx5_ipsec_sa_entry *sa)
{
	int res;

	res = mlx5_ipsec_hw_cmd(sa, MLX5_IPSEC_CMD_ADD_SA);
	if (res)
		goto out;

	res = mlx5_ipsec_hw_sadb_wait(sa);
	if (res)
		goto out;

	res = mlx5_ipsec_errno(sa->status);
	if (res)
		netdev_warn(sa->dev->en_priv->netdev, "IPSec SADB add command failed with error %08x\n",
			    sa->status);
out:
	return res;
}

int mlx5_ipsec_hw_sadb_del(struct mlx5_ipsec_sa_entry *sa)
{
	return mlx5_ipsec_hw_cmd(sa, MLX5_IPSEC_CMD_DEL_SA);
}

void mlx5_ipsec_qp_recv(void *cb_arg, struct mlx5_fpga_dma_buf *buf)
{
	struct mlx5_ipsec_dev *dev = cb_arg;
	struct mlx5_ipsec_sadb_resp *resp = buf->sg[0].data;
	struct mlx5_ipsec_sa_entry *sa;
	unsigned long flags;

	if (buf->sg[0].size < sizeof(*resp)) {
		netdev_warn(dev->en_priv->netdev, "Short receive from FPGA IPSec: %u < %lu bytes\n",
			    buf->sg[0].size, sizeof(*resp));
		return;
	}

	netdev_dbg(dev->en_priv->netdev, "mlx5_ipsec recv_cb syndrome %08x sa_id %x\n",
		   ntohl(resp->syndrome), ntohl(resp->sw_sa_handle));

	spin_lock_irqsave(&dev->pending_cmds_lock, flags);
	sa = list_first_entry_or_null(&dev->pending_cmds,
				      struct mlx5_ipsec_sa_entry, list);
	if (sa)
		list_del(&sa->list);
	spin_unlock_irqrestore(&dev->pending_cmds_lock, flags);

	if (!sa) {
		netdev_warn(dev->en_priv->netdev, "Received IPSec offload response without pending command request\n");
		return;
	}
	netdev_dbg(dev->en_priv->netdev, "Handling response for sa %p handle 0x%08x\n",
		   sa, sa->handle);

	if (sa->handle != ntohl(resp->sw_sa_handle)) {
		netdev_warn(dev->en_priv->netdev, "mismatch SA handle. cmd 0x%08x vs resp 0x%08x\n",
			    sa->handle, ntohl(resp->sw_sa_handle));
	}

	sa->status = ntohl(resp->syndrome);
	complete(&sa->complete);
}

/* returns 0 on success, negative error if failed to send message to FPGA
 * positive error if FPGA returned a bad response
 */
static int mlx5_xfrm_add_state(struct xfrm_state *x)
{
	struct mlx5_ipsec_sa_entry *sa_entry = NULL;
	struct net_device *netdev = x->xso.dev;
	struct mlx5e_priv *priv;
	int res;

	if (x->props.aalgo != SADB_AALG_NONE) {
		netdev_info(netdev, "Cannot offload authenticated xfrm states\n");
		return -EINVAL;
	}
	if (x->props.ealgo != SADB_X_EALG_AES_GCM_ICV16) {
		netdev_info(netdev, "Only AES-GCM-ICV16 xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.calgo != SADB_X_CALG_NONE) {
		netdev_info(netdev, "Cannot offload compressed xfrm states\n");
		return -EINVAL;
	}
	if (x->props.flags & XFRM_STATE_ESN) {
		netdev_info(netdev, "Cannot offload ESN xfrm states\n");
		return -EINVAL;
	}
	if (x->props.family != AF_INET &&
	    x->props.family != AF_INET6) {
		netdev_info(netdev, "Only IPv4/6 xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.family == AF_INET6 &&
	    x->props.mode == XFRM_MODE_TRANSPORT) {
		netdev_info(netdev, "Cannot offload IPv6 transport xfrm state\n");
		return -EINVAL;
	}
	if (x->props.mode != XFRM_MODE_TRANSPORT &&
	    x->props.mode != XFRM_MODE_TUNNEL) {
		dev_info(&netdev->dev, "Only transport and tunnel xfrm states may be offloaded\n");
		return -EINVAL;
	}
	if (x->id.proto != IPPROTO_ESP) {
		netdev_info(netdev, "Only ESP xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->encap) {
		netdev_info(netdev, "Encapsulated xfrm state may not be offloaded\n");
		return -EINVAL;
	}
	if (!x->aead) {
		netdev_info(netdev, "Cannot offload xfrm states without aead\n");
		return -EINVAL;
	}
	if (x->aead->alg_icv_len != 128) {
		netdev_info(netdev, "Cannot offload xfrm states with AEAD ICV length other than 128bit\n");
		return -EINVAL;
	}
	if ((x->aead->alg_key_len != 128 + 32) &&
	    (x->aead->alg_key_len != 256 + 32)) {
		netdev_info(netdev, "Cannot offload xfrm states with AEAD key length other than 128/256 bit\n");
		return -EINVAL;
	}
	if (x->tfcpad) {
		netdev_info(netdev, "Cannot offload xfrm states with tfc padding\n");
		return -EINVAL;
	}
	if (!x->geniv) {
		netdev_info(netdev, "Cannot offload xfrm states without geniv\n");
		return -EINVAL;
	}
	if (strcmp(x->geniv, "seqiv")) {
		netdev_info(netdev, "Cannot offload xfrm states with geniv other than seqiv\n");
		return -EINVAL;
	}

	priv = netdev_priv(netdev);
	sa_entry = kzalloc(sizeof(*sa_entry), GFP_KERNEL);
	if (!sa_entry) {
		res = -ENOMEM;
		goto out;
	}

	sa_entry->x = x;
	sa_entry->dev = priv->ipsec;

	/* Add the SA to handle processed incoming packets before the add SA
	 * completion was received
	 */
	if (x->xso.flags & XFRM_OFFLOAD_INBOUND) {
		res = sadb_rx_add(sa_entry);
		if (res) {
			netdev_info(netdev, "Failed adding to SADB_RX: %d\n",
				    res);
			goto err_entry;
		}
	}

	res = mlx5_ipsec_hw_sadb_add(sa_entry);
	if (res)
		goto err_sadb_rx;

	x->xso.offload_handle = (unsigned long)sa_entry;
	try_module_get(THIS_MODULE);
	goto out;

err_sadb_rx:
	if (x->xso.flags & XFRM_OFFLOAD_INBOUND) {
		sadb_rx_del(sa_entry);
		sadb_rx_free(sa_entry);
	}
err_entry:
	kfree(sa_entry);
out:
	return res;
}

static void mlx5_xfrm_del_state(struct xfrm_state *x)
{
	struct mlx5_ipsec_sa_entry *sa_entry;
	int res;

	if (!x->xso.offload_handle)
		return;

	sa_entry = (struct mlx5_ipsec_sa_entry *)x->xso.offload_handle;
	WARN_ON(sa_entry->x != x);

	if (x->xso.flags & XFRM_OFFLOAD_INBOUND)
		sadb_rx_del(sa_entry);

	res = mlx5_ipsec_hw_sadb_del(sa_entry);
	if (res) {
		netdev_warn(sa_entry->dev->en_priv->netdev,
			    "Failed to delete HW SADB entry: %d\n", res);
		return;
	}
}

static void mlx_xfrm_free_state(struct xfrm_state *x)
{
	struct mlx5_ipsec_sa_entry *sa_entry;
	int res;

	if (!x->xso.offload_handle)
		return;

	sa_entry = (struct mlx5_ipsec_sa_entry *)x->xso.offload_handle;
	WARN_ON(sa_entry->x != x);

	res = mlx5_ipsec_hw_sadb_wait(sa_entry);
	if (res) {
		/* Leftover object will leak */
		netdev_warn(sa_entry->dev->en_priv->netdev,
			    "Failed to wait for HW SADB delete response: %d\n",
			    res);
		return;
	}
	res = mlx5_ipsec_errno(sa_entry->status);
	if (res) {
		/* Leftover SA entry in HW will stay */
		netdev_warn(sa_entry->dev->en_priv->netdev,
			    "Failed to delete HW SADB entry: %d\n",
			    sa_entry->status);
	}

	if (x->xso.flags & XFRM_OFFLOAD_INBOUND)
		sadb_rx_free(sa_entry);

	kfree(sa_entry);
	module_put(THIS_MODULE);
}

static struct xfrm_state *sadb_rx_lookup(struct mlx5_ipsec_dev *dev,
					 unsigned int handle) {
	struct mlx5_ipsec_sa_entry *sa_entry;
	struct xfrm_state *ret = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(dev->sadb_rx, sa_entry, hlist, handle)
		if (sa_entry->handle == handle) {
			ret = sa_entry->x;
			xfrm_state_hold(ret);
			break;
		}
	rcu_read_unlock();

	return ret;
}

static struct mlx5_ipsec_metadata *insert_metadata(struct sk_buff *skb)
{
	struct ethhdr *eth;
	struct mlx5_ipsec_metadata *mdata;

	if (skb_cow_head(skb, sizeof(*mdata)))
		return ERR_PTR(-ENOMEM);

	eth = (struct ethhdr *)skb_push(skb, sizeof(*mdata));
	skb->mac_header -= sizeof(*mdata);
	mdata = (struct mlx5_ipsec_metadata *)(eth + 1);

	memmove(skb->data, skb->data + sizeof(*mdata),
		2 * ETH_ALEN);

	eth->h_proto = cpu_to_be16(MLX5_METADATA_ETHER_TYPE);

	memset(mdata->content.raw, 0, sizeof(mdata->content.raw));
	return mdata;
}

static bool mlx5_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	if (x->props.family == AF_INET) {
		/* Offload with IPv4 options is not supported yet */
		if (ip_hdr(skb)->ihl > 5)
			return false;
	} else {
		/* Offload with IPv6 extension headers is not support yet */
		if (ipv6_ext_hdr(ipv6_hdr(skb)->nexthdr))
			return false;
	}

	return true;
}

static __be16 mlx5_ipsec_mss_inv(struct sk_buff *skb)
{
	return inverse_table[skb_shinfo(skb)->gso_size];
}

bool mlx5_ipsec_feature_check(struct sk_buff *skb, struct net_device *netdev,
			      netdev_features_t features)
{
	struct xfrm_state *x;

	if (skb->sp && skb->sp->len) {
		x = skb->sp->xvec[0];
		if (x && x->xso.offload_handle)
			return true;
	}
	return false;
}

static int remove_trailer(struct sk_buff *skb, struct xfrm_state *x)
{
	unsigned int alen = crypto_aead_authsize(x->data);
	struct ipv6hdr *ipv6hdr = ipv6_hdr(skb);
	struct iphdr *ipv4hdr = ip_hdr(skb);
	unsigned int trailer_len;
	u8 plen;
	int ret;

	ret = skb_copy_bits(skb, skb->len - alen - 2, &plen, 1);
	if (ret)
		return ret;

	trailer_len = alen + plen + 2;

	netdev_dbg(skb->dev, "   Removing trailer %u bytes\n", trailer_len);
	pskb_trim(skb, skb->len - trailer_len);
	if (skb->protocol == htons(ETH_P_IP)) {
		ipv4hdr->tot_len = htons(ntohs(ipv4hdr->tot_len) - trailer_len);
		ip_send_check(ipv4hdr);
	} else {
		ipv6hdr->payload_len = htons(ntohs(ipv6hdr->payload_len) -
					     trailer_len);
	}
	return 0;
}

static void set_swp(struct sk_buff *skb, struct mlx5_swp_info *swp_info,
		    bool tunnel, struct xfrm_offload *xo)
{
	u8 proto;

	/* Tunnel Mode:
	 * SWP:      OutL3       InL3  InL4
	 * Pkt: MAC  IP     ESP  IP    L4
	 *
	 * Transport Mode:
	 * SWP:      OutL3       InL4
	 *           InL3
	 * Pkt: MAC  IP     ESP  L4
	 *
	 * Offsets are in 2-byte words, counting from start of frame
	 */
	swp_info->use_swp = true;
	swp_info->outer_l3_ofs = skb_network_offset(skb) / 2;
	if (skb->protocol == htons(ETH_P_IPV6))
		swp_info->swp_flags |= MLX5_ETH_WQE_SWP_OUTER_L3_IPV6;

	if (tunnel) {
		swp_info->inner_l3_ofs = skb_inner_network_offset(skb) / 2;
		if (xo->proto == IPPROTO_IPV6) {
			swp_info->swp_flags |= MLX5_ETH_WQE_SWP_INNER_L3_IPV6;
			proto = inner_ipv6_hdr(skb)->nexthdr;
		} else {
			proto = inner_ip_hdr(skb)->protocol;
		}
	} else {
		swp_info->inner_l3_ofs = skb_network_offset(skb) / 2;
		if (skb->protocol == htons(ETH_P_IPV6))
			swp_info->swp_flags |= MLX5_ETH_WQE_SWP_INNER_L3_IPV6;
		proto = xo->proto;
	}
	switch (proto) {
	case IPPROTO_UDP:
		swp_info->swp_flags |= MLX5_ETH_WQE_SWP_INNER_L4_UDP;
		/* Fall through */
	case IPPROTO_TCP:
		swp_info->inner_l4_ofs = skb_inner_transport_offset(skb) / 2;
		break;
	}
	netdev_dbg(skb->dev, "   TX SWP Outer L3 %u L4 %u; Inner L3 %u L4 %u; Flags 0x%x\n",
		   swp_info->outer_l3_ofs, swp_info->outer_l4_ofs,
		   swp_info->inner_l3_ofs, swp_info->inner_l4_ofs,
		   swp_info->swp_flags);
}

static void set_iv(struct sk_buff *skb, struct xfrm_offload *xo)
{
	int iv_offset;
	__be64 seqno;

	/* Place the SN in the IV field */
	seqno = cpu_to_be64(xo->seq.low + ((u64)xo->seq.hi << 32));
	iv_offset = skb_transport_offset(skb) + sizeof(struct ip_esp_hdr);
	skb_store_bits(skb, iv_offset, &seqno, 8);
}

static void set_metadata(struct sk_buff *skb, struct mlx5_ipsec_metadata *mdata,
			 struct xfrm_offload *xo)
{
	struct tcphdr *tcph;
	struct ip_esp_hdr *esph;

	if (skb_is_gso(skb)) {
		/* Add LSO metadata indication */
		esph = ip_esp_hdr(skb);
		tcph = inner_tcp_hdr(skb);
		netdev_dbg(skb->dev, "   Offloading GSO packet outer L3 %u; L4 %u; Inner L3 %u; L4 %u\n",
			   skb->network_header,
			   skb->transport_header,
			   skb->inner_network_header,
			   skb->inner_transport_header);
		netdev_dbg(skb->dev, "   Offloading GSO packet of len %u; mss %u; TCP sp %u dp %u seq 0x%x ESP seq 0x%x\n",
			   skb->len, skb_shinfo(skb)->gso_size,
			   ntohs(tcph->source), ntohs(tcph->dest),
			   ntohl(tcph->seq), ntohl(esph->seq_no));
		mdata->syndrome = MLX5_IPSEC_TX_SYNDROME_OFFLOAD_WITH_LSO_TCP;
		mdata->content.tx.mss_inv = mlx5_ipsec_mss_inv(skb);
		mdata->content.tx.seq = htons(ntohl(tcph->seq) & 0xFFFF);
	} else {
		mdata->syndrome = MLX5_IPSEC_TX_SYNDROME_OFFLOAD;
	}
	mdata->content.tx.esp_next_proto = xo->proto;

	netdev_dbg(skb->dev, "   TX metadata syndrome %u proto %u mss_inv %04x seq %04x\n",
		   mdata->syndrome, mdata->content.tx.esp_next_proto,
		   ntohs(mdata->content.tx.mss_inv),
		   ntohs(mdata->content.tx.seq));
}

static bool is_ipsec_device(struct mlx5_core_dev *mdev)
{
	if (!mdev->fpga || !MLX5_CAP_GEN(mdev, fpga))
		return false;

	if (MLX5_CAP_FPGA(mdev, ieee_vendor_id) !=
	    MLX5_FPGA_CAP_SANDBOX_VENDOR_ID_MLNX)
		return false;

	if (MLX5_CAP_FPGA(mdev, sandbox_product_id) !=
	    MLX5_FPGA_CAP_SANDBOX_PRODUCT_ID_IPSEC)
		return false;
	return true;
}

int mlx5_ipsec_init_one(struct mlx5_core_dev *mdev, struct net_device *netdev)
{
	struct mlx5_fpga_conn_attr init_attr = {0};
	struct mlx5_ipsec_dev *dev = NULL;
	int ret = 0;

	netdev_dbg(netdev, "mlx5_ipsec_init_one\n");

	if (!is_ipsec_device(mdev)) {
		netdev_dbg(netdev, "Not an Innova IPSec device\n");
		goto out;
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mlx5_fpga_get_sbu_caps(mdev->fpga, sizeof(dev->ipsec_caps),
				     dev->ipsec_caps);
	if (ret) {
		netdev_err(netdev, "Failed to retrieve ipsec extended capabilities\n");
		goto err_dev;
	}

	INIT_LIST_HEAD(&dev->pending_cmds);
	hash_init(dev->sadb_rx);
	spin_lock_init(&dev->sadb_rx_lock);
	spin_lock_init(&dev->pending_cmds_lock);
	ida_init(&dev->halloc);
	dev->en_priv = netdev_priv(netdev);

	init_attr.rx_size = SBU_QP_QUEUE_SIZE;
	init_attr.tx_size = SBU_QP_QUEUE_SIZE;
	init_attr.recv_cb = mlx5_ipsec_qp_recv;
	init_attr.cb_arg = dev;
	ret = mlx5_fpga_sbu_conn_init(mdev->fpga, &init_attr);
	if (ret) {
		netdev_err(netdev, "Error creating IPSec command connection %d\n",
			   ret);
		goto err_dev;
	}

	ret = mlx5_ipsec_sysfs_add(&dev->kobj, mlx5_fpga_kobj(mdev->fpga));
	if (ret) {
		netdev_err(netdev, "ipsec_sysfs_add failed: %d\n", ret);
		goto err_conn;
	}

	dev->en_priv->ipsec = dev;
	dev->en_priv->mtu_extra = sizeof(struct mlx5_ipsec_metadata);
	netdev_dbg(netdev, "IPSec attached to netdev\n");
	goto out;

err_conn:
	mlx5_fpga_sbu_conn_deinit(mdev->fpga);
err_dev:
	kfree(dev);
out:
	return ret;
}

void mlx5_ipsec_dev_release(struct kobject *kobj)
{
	struct mlx5_ipsec_dev *dev;

	dev = container_of(kobj, struct mlx5_ipsec_dev, kobj);
	kfree(dev);
}

void mlx5_ipsec_deinit_one(struct mlx5_core_dev *mdev,
			   struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_ipsec_dev *dev = priv->ipsec;

	netdev_dbg(netdev, "mlx5_ipsec_deinit_one\n");
	mlx5_fpga_sbu_conn_deinit(mdev->fpga);
	ida_destroy(&dev->halloc);
	kobject_put(&dev->kobj);
	priv->ipsec = NULL;
}

static const struct xfrmdev_ops mlx5_xfrmdev_ops = {
	.xdo_dev_state_add	= mlx5_xfrm_add_state,
	.xdo_dev_state_delete	= mlx5_xfrm_del_state,
	.xdo_dev_state_free	= mlx_xfrm_free_state,
	.xdo_dev_offload_ok	= mlx5_ipsec_offload_ok,
};

static netdev_tx_t mlx5_ipsec_sq_xmit(struct mlx5e_sq *sq, struct sk_buff *skb,
				      struct mlx5_swp_info *swp_info)
{
	struct xfrm_offload *xo = xfrm_offload(skb);
	struct xfrm_state *x;
	struct mlx5_ipsec_metadata *mdata;

	netdev_dbg(skb->dev, ">> mlx5e_ipsec_sq_xmit %u bytes\n", skb->len);

	if (!xo) {
		netdev_dbg(skb->dev, "   no xo\n");
		goto xmit;
	}

	if (skb->sp->len != 1) {
		netdev_warn(skb->dev, "Cannot offload crypto for a bundle of %u XFRM states\n",
			    skb->sp->len);
		goto xmit;
	}

	x = xfrm_input_state(skb);
	if (!x) {
		netdev_warn(skb->dev, "Crypto-offload packet has no xfrm_state\n");
		goto xmit;
	}

	if (x->xso.offload_handle &&
	    (skb->protocol == htons(ETH_P_IP) ||
	     skb->protocol == htons(ETH_P_IPV6))) {
		if (!skb_is_gso(skb))
			if (remove_trailer(skb, x))
				goto drop;
		mdata = insert_metadata(skb);
		if (IS_ERR(mdata)) {
			netdev_warn(skb->dev, "insert_metadata failed: %ld\n",
				    PTR_ERR(mdata));
			goto drop;
		}
		set_swp(skb, swp_info, x->props.mode == XFRM_MODE_TUNNEL, xo);
		set_iv(skb, xo);
		set_metadata(skb, mdata, xo);

		netdev_dbg(skb->dev, "   TX PKT len %u linear %u bytes + %u bytes in %u frags\n",
			   skb->len, skb_headlen(skb), skb->data_len,
			   skb->data_len ? skb_shinfo(skb)->nr_frags : 0);
	}
xmit:
	netdev_dbg(skb->dev, "<< mlx5e_ipsec_sq_xmit\n");
	return mlx5e_sq_xmit(sq, skb, swp_info);

drop:
	netdev_dbg(skb->dev, "<< mlx5e_ipsec_sq_xmit drop\n");
	kfree_skb(skb);
	return NETDEV_TX_OK;
}

void mlx5_ipsec_create_sq(struct mlx5e_channel *c, struct mlx5e_sq *sq)
{
	if (!is_ipsec_device(c->priv->mdev))
		return;

	sq->sq_xmit = mlx5_ipsec_sq_xmit;
}

static inline unsigned int parse_metadata(u8 *va, u16 byte_cnt,
					  struct mlx5_ipsec_metadata *metadata)
{
	struct ethhdr *old_eth;
	struct ethhdr *new_eth;
	__be16 *ethtype;

	if (byte_cnt < ETH_HLEN)
		return 0;

	ethtype = (__be16 *)(va + ETH_ALEN * 2);
	if (*ethtype != cpu_to_be16(MLX5_METADATA_ETHER_TYPE))
		return 0;

	memcpy(metadata, ethtype + 1, MLX5_METADATA_ETHER_LEN);
	old_eth = (struct ethhdr *)va;
	new_eth = (struct ethhdr *)(va + MLX5_METADATA_ETHER_LEN);
	memmove(new_eth, old_eth, 2 * ETH_ALEN);
	/* Ethertype is already in its new place */

	return MLX5_METADATA_ETHER_LEN;
}

static inline
struct sk_buff *skb_ipsec_cqe(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe,
			      u16 wqe_counter, u32 cqe_bcnt,
			      struct mlx5_ipsec_metadata *mdata,
			      unsigned int *mdatalen)
{
	struct mlx5e_dma_info *di;
	struct sk_buff *skb;
	void *va, *data;
	int headlen;

	di             = &rq->dma_info[wqe_counter];
	va             = page_address(di->page);
	data           = va + MLX5_RX_HEADROOM;

	dma_sync_single_range_for_cpu(rq->pdev,
				      di->addr,
				      MLX5_RX_HEADROOM,
				      rq->buff.wqe_sz,
				      DMA_FROM_DEVICE);
	prefetch(data);

	if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
		rq->stats.wqe_err++;
		mlx5e_page_release(rq, di, true);
		return NULL;
	}

#if 0
	rcu_read_lock();
	consumed = mlx5e_xdp_handle(rq, READ_ONCE(rq->xdp_prog), di, data,
				    cqe_bcnt);
	rcu_read_unlock();
	if (consumed)
		return NULL; /* page/packet was consumed by XDP */
#endif

	*mdatalen = parse_metadata(data, cqe_bcnt, mdata);
	data += *mdatalen;
	cqe_bcnt -= *mdatalen;

	skb = napi_alloc_skb(rq->cq.napi, 256);
	if (unlikely(!skb)) {
		rq->stats.buff_alloc_err++;
		mlx5e_page_release(rq, di, true);
		return NULL;
	}

	headlen = eth_get_headlen(data, cqe_bcnt);
	skb_reserve(skb, MLX5_RX_HEADROOM);
	skb_put(skb, headlen);
	skb_copy_to_linear_data(skb, data, headlen);

	if (cqe_bcnt > headlen) {
		page_ref_inc(di->page);
		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
				di->page, data - va + headlen,
				cqe_bcnt - headlen, RQ_PAGE_SIZE(rq));
	}

	/* queue up for recycling ..*/
	mlx5e_page_release(rq, di, true);
	return skb;
}

static void mlx5_ipsec_handle_rx_cqe(struct mlx5e_rq *rq,
				     struct mlx5_cqe64 *cqe)
{
	struct mlx5_ipsec_metadata mdata;
	unsigned int mdatalen = 0;
	struct mlx5e_rx_wqe *wqe;
	struct xfrm_offload *xo;
	struct xfrm_state *xs;
	__be16 wqe_counter_be;
	struct sk_buff *skb;
	u16 wqe_counter;
	u32 sa_handle;
	u32 cqe_bcnt;

	wqe_counter_be = cqe->wqe_counter;
	wqe_counter    = be16_to_cpu(wqe_counter_be);
	wqe            = mlx5_wq_ll_get_wqe(&rq->wq, wqe_counter);
	cqe_bcnt       = be32_to_cpu(cqe->byte_cnt);

	skb = skb_ipsec_cqe(rq, cqe, wqe_counter, cqe_bcnt, &mdata, &mdatalen);
	if (!skb)
		goto wq_ll_pop;

	mlx5e_complete_rx_cqe(rq, cqe, cqe_bcnt, skb);

	if (mdatalen == sizeof(mdata)) {
		netdev_dbg(rq->netdev, "RX metadata: size %d, etherType %04X, syndrome %02x, handle %x\n",
			   mdatalen, be16_to_cpu(mdata.ethertype),
			   mdata.syndrome,
			   be32_to_cpu(mdata.content.rx.sa_handle));

		skb->sp = secpath_dup(skb->sp);
		if (unlikely(!skb->sp)) { /* drop */
			netdev_warn(rq->netdev, "Failed to allocate secpath\n");
			goto drop;
		}

		sa_handle = be32_to_cpu(mdata.content.rx.sa_handle);
		xs = sadb_rx_lookup(rq->priv->ipsec, sa_handle);
		if (!xs) {
			netdev_warn(rq->netdev, "SADB_RX lookup miss handle 0x%x\n",
				    sa_handle);
			goto drop;
		}

		skb->sp->xvec[skb->sp->len++] = xs;
		skb->sp->olen++;

		xo = xfrm_offload(skb);
		xo->flags = CRYPTO_DONE;
		switch (mdata.syndrome) {
		case MLX5_IPSEC_RX_SYNDROME_DECRYPTED:
			xo->status = CRYPTO_SUCCESS;
			break;
		case MLX5_IPSEC_RX_SYNDROME_AUTH_FAILED:
			xo->status = CRYPTO_TUNNEL_ESP_AUTH_FAILED;
			break;
		default:
			netdev_warn(rq->netdev, "Unknown metadata syndrom %d\n",
				    mdata.syndrome);
			goto drop;
		}
	}

	napi_gro_receive(rq->cq.napi, skb);
	netdev_dbg(rq->netdev, "<< rx_handler\n");
	goto wq_ll_pop;

drop:
	kfree_skb(skb);
	netdev_dbg(rq->netdev, "<< rx_handler: dropping packet\n");
	goto wq_ll_pop;

wq_ll_pop:
	mlx5_wq_ll_pop(&rq->wq, wqe_counter_be, &wqe->next.next_wqe_index);
}

void mlx5_ipsec_create_rq(struct mlx5e_channel *c, struct mlx5e_rq *rq)
{
	if (!is_ipsec_device(c->priv->mdev))
		return;

	rq->handle_rx_cqe = mlx5_ipsec_handle_rx_cqe;
}

void mlx5_ipsec_build_netdev(struct mlx5_core_dev *mdev,
			     struct net_device *netdev)
{
	u32 ipsec_caps[MLX5_ST_SZ_DW(ipsec_extended_cap)];
	int ret;

	if (!is_ipsec_device(mdev))
		return;

	ret = mlx5_fpga_get_sbu_caps(mdev->fpga, sizeof(ipsec_caps),
				     ipsec_caps);
	if (ret) {
		mlx5_core_err(mdev, "Failed to read IPSec extended caps: %d\n",
			      ret);
		return;
	}

	netdev->xfrmdev_ops = &mlx5_xfrmdev_ops;
	if (MLX5_GET(ipsec_extended_cap, ipsec_caps, esp)) {
		mlx5_core_info(mdev, "IPSec ESP acceleration enabled\n");
		netdev->features |= NETIF_F_HW_ESP | NETIF_F_HW_ESP_TX_CSUM;
		netdev->hw_enc_features |= NETIF_F_HW_ESP |
					   NETIF_F_HW_ESP_TX_CSUM;
		if (MLX5_GET(ipsec_extended_cap, ipsec_caps, lso)) {
			mlx5_core_dbg(mdev, "ESP GSO capability turned on\n");
			netdev->features |= NETIF_F_GSO_ESP;
			netdev->hw_features |= NETIF_F_GSO_ESP;
			netdev->hw_enc_features |= NETIF_F_GSO_ESP;
		}
	}
}

void mlx5_ipsec_init(void)
{
	u32 mss;

	inverse_table[1] = 0xFFFF;
	for (mss = 2; mss < MAX_LSO_MSS; mss++)
		inverse_table[mss] = htons(((1ULL << 32) / mss) >> 16);
}
