/*
 * IPV4 GSO/GRO offload support
 * Linux INET implementation
 *
 * Copyright (C) 2016 secunet Security Networks AG
 * Author: Steffen Klassert <steffen.klassert@secunet.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * ESP GRO support
 */

#include <linux/skbuff.h>
#include <linux/init.h>
#include <net/protocol.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/esp.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/udp.h>

static struct sk_buff **esp4_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	int err;
	if (NAPI_GRO_CB(skb)->flush)
		goto out;

	skb_pull(skb, skb_gro_offset(skb));
	skb->xfrm_gro = 1;

	err = xfrm4_rcv_encap(skb, IPPROTO_ESP, 0, -2);
	if (err == -EOPNOTSUPP) {
		skb_push(skb, skb_gro_offset(skb));
		NAPI_GRO_CB(skb)->same_flow = 0;
		NAPI_GRO_CB(skb)->flush = 1;
		skb->xfrm_gro = 0;
		goto out;
	}

	return ERR_PTR(-EINPROGRESS);
out:
	return NULL;
}

static int esp4_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct xfrm_state *x = xfrm_input_state(skb);
	struct crypto_aead *aead = x->data;
	struct ip_esp_hdr *esph = (struct ip_esp_hdr *)(skb->data + nhoff);
	struct packet_offload *ptype;
	int err = -ENOENT;
	__be16 type = skb->protocol;

	rcu_read_lock();
	ptype = gro_find_complete_by_type(type);
	if (ptype != NULL)
		err = ptype->callbacks.gro_complete(skb, nhoff + sizeof(*esph) + crypto_aead_ivsize(aead));

	rcu_read_unlock();

	return err;
}

static void esp4_gso_encap(struct xfrm_state *x, struct sk_buff *skb)
{
	struct ip_esp_hdr *esph;
	struct iphdr *iph = ip_hdr(skb);
	struct xfrm_offload *xo = xfrm_offload(skb);
	int proto = iph->protocol;

	skb_push(skb, -skb_network_offset(skb));
	esph = ip_esp_hdr(skb);
	*skb_mac_header(skb) = IPPROTO_ESP;

	esph->spi = x->id.spi;
	esph->seq_no = htonl(XFRM_SKB_CB(skb)->seq.output.low);

	xo->proto = proto;
}

static struct sk_buff *esp4_gso_segment(struct sk_buff *skb,
				        netdev_features_t features)
{
	__u32 seq;
	int err = 0;
	struct sk_buff *skb2;
	struct xfrm_state *x;
	struct ip_esp_hdr *esph;
	struct crypto_aead *aead;
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	netdev_features_t esp_features = features;
	struct xfrm_offload *xo = xfrm_offload(skb);

	if (!xo)
		goto out;

	seq = xo->seq.low;

	x = skb->sp->xvec[skb->sp->len - 1];
	aead = x->data;
	esph = ip_esp_hdr(skb);

	if (esph->spi != x->id.spi)
		goto out;

	if (!pskb_may_pull(skb, sizeof(*esph) + crypto_aead_ivsize(aead)))
		goto out;

	__skb_pull(skb, sizeof(*esph) + crypto_aead_ivsize(aead));

	skb->encap_hdr_csum = 1;

	if (!(features & NETIF_F_HW_ESP))
		esp_features = features & ~(NETIF_F_SG | NETIF_F_CSUM_MASK);

	segs = x->outer_mode->gso_segment(x, skb, esp_features);
	if (IS_ERR(segs))
		goto out;
	if (segs == NULL)
		return ERR_PTR(-EINVAL);
	__skb_pull(skb, skb->data - skb_mac_header(skb));

	skb2 = segs;
	do {
		struct sk_buff *nskb = skb2->next;

		xo = xfrm_offload(skb2);
		xo->flags |= XFRM_GSO_SEGMENT;
		xo->seq.low = seq;
		xo->seq.hi = xfrm_replay_seqhi(x, seq);

		if (!(features & NETIF_F_HW_ESP) ||
		    (x->xso.offload_handle && x->xso.dev != skb->dev))
			xo->flags |= CRYPTO_FALLBACK;

		x->outer_mode->xmit(x, skb2);

		err = x->type_offload->xmit(x, skb2, esp_features);
		if (err) {
			kfree_skb_list(segs);
			return ERR_PTR(err);
		}

		seq++;

		skb_push(skb2, skb2->mac_len);
		skb2 = nskb;
	} while (skb2);

out:
	return segs;
}

static int esp_input_tail(struct xfrm_state *x, struct sk_buff *skb)
{
	struct crypto_aead *aead = x->data;
	struct xfrm_offload *xo = xfrm_offload(skb);

	if (!pskb_may_pull(skb, sizeof(struct ip_esp_hdr) + crypto_aead_ivsize(aead)))
		return -EINVAL;

	if (!(xo->flags & CRYPTO_DONE))
		skb->ip_summed = CHECKSUM_NONE;

	return esp_input_done2(skb, 0);
}

static int esp_xmit(struct xfrm_state *x, struct sk_buff *skb,  netdev_features_t features)
{
	int err;
	struct xfrm_offload *xo;
	struct ip_esp_hdr *esph;
	struct crypto_aead *aead;
	int blksize;
	int clen;
	int alen;
	int plen;
	int tfclen;
	int nfrags;
	int tailen;
	__be64 seqno;
	__u8 proto;
	bool inplace = true;

	xo = xfrm_offload(skb);

	if (!xo)
		return -EINVAL;

	if (!(features & NETIF_F_HW_ESP) ||
	    (x->xso.offload_handle &&  x->xso.dev != skb->dev)) {
		xo->flags |= CRYPTO_FALLBACK;
	}

	proto = xo->proto;

	/* skb is pure payload to encrypt */

	aead = x->data;
	alen = crypto_aead_authsize(aead);

	tfclen = 0;
	/* XXX: Add support for tfc padding here. */

	blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	clen = ALIGN(skb->len + 2 + tfclen, blksize);
	plen = clen - skb->len - tfclen;
	tailen = tfclen + plen + alen;

	nfrags = esp_output_head(x, skb, proto, tfclen, tailen, plen, &inplace);
	if (nfrags < 0)
		return nfrags;

	esph = ip_esp_hdr(skb);
	esph->spi = x->id.spi;

	skb_push(skb, -skb_network_offset(skb));

	if (xo->flags & XFRM_GSO_SEGMENT) {
		esph->seq_no = htonl(xo->seq.low);
	} else {
		ip_hdr(skb)->tot_len = htons(skb->len);
		ip_send_check(ip_hdr(skb));
	}

	if (x->xso.offload_handle && !(xo->flags & CRYPTO_FALLBACK))
		return 0;

	seqno = cpu_to_be64(xo->seq.low + ((u64)xo->seq.hi << 32));

	err = esp_output_tail(x, skb, seqno, clen, nfrags, inplace);
	if (err < 0)
		return err;

	secpath_reset(skb);

	return 0;
}

static const struct net_offload esp4_offload = {
	.callbacks = {
		.gro_receive = esp4_gro_receive,
		.gro_complete = esp4_gro_complete,
		.gso_segment = esp4_gso_segment,
	},
};

static const struct xfrm_type_offload esp_type_offload = {
	.description	= "ESP4 OFFLOAD",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_ESP,
	.input_tail	= esp_input_tail,
	.xmit		= esp_xmit,
	.encap		= esp4_gso_encap,
};

static int __init esp4_offload_init(void)
{
	if (xfrm_register_type_offload(&esp_type_offload, AF_INET) < 0) {
		pr_info("%s: can't add xfrm type offload\n", __func__);
		return -EAGAIN;
	}

	return inet_add_offload(&esp4_offload, IPPROTO_ESP);
}

static void __exit esp4_offload_exit(void)
{
	if (xfrm_unregister_type_offload(&esp_type_offload, AF_INET) < 0)
		pr_info("%s: can't remove xfrm type offload\n", __func__);

	inet_del_offload(&esp4_offload, IPPROTO_ESP);
}

module_init(esp4_offload_init);
module_exit(esp4_offload_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steffen Klassert <steffen.klassert@secunet.com>");
