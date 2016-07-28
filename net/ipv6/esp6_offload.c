/*
 * IPV6 GSO/GRO offload support
 * Linux INET implementation
 *
 * Copyright (C) 2015 secunet Security Networks AG
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
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <linux/icmpv6.h>

static struct sk_buff **esp6_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	int err;
	if (NAPI_GRO_CB(skb)->flush)
		goto out;

	skb_pull(skb, skb_gro_offset(skb));
	skb->xfrm_gro = 1;

	XFRM_SPI_SKB_CB(skb)->family = AF_INET6;
	XFRM_SPI_SKB_CB(skb)->daddroff = offsetof(struct ipv6hdr, daddr);
	err = xfrm_input(skb, IPPROTO_ESP, 0, -2);
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

static int esp6_gro_complete(struct sk_buff *skb, int nhoff)
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

static struct sk_buff *esp6_gso_segment(struct sk_buff *skb,
				        netdev_features_t features)
{
	struct ip_esp_hdr *esph;
	struct sk_buff *skb2;
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct xfrm_state *x;
	struct sec_path *sp;
	struct crypto_aead *aead;
	int err = 0;
	const struct net_offload *ops;
	int omaclen;
	__u32 seq;
	__u32 seqhi;

	sp = skb->sp;
	if (!sp && !sp->len)
		goto out;

	seq = sp->seq.low;
	seqhi = sp->seq.hi;

	x = sp->xvec[sp->len - 1];
	aead = x->data;
	esph = ip_esp_hdr(skb);

	omaclen = skb->mac_len;
	if (esph->spi != x->id.spi)
		goto out;

	if (!pskb_may_pull(skb, sizeof(*esph) + crypto_aead_ivsize(aead)))
		goto out;

	__skb_pull(skb, sizeof(*esph) + crypto_aead_ivsize(aead));

	skb->encap_hdr_csum = 1;

	if (x->props.mode == XFRM_MODE_TUNNEL) {
		__skb_push(skb, skb->mac_len);
		segs = skb_mac_gso_segment(skb, features);
	} else {
		skb->transport_header += x->props.header_len;
		ops = rcu_dereference(inet_offloads[sp->proto]);
		if (likely(ops && ops->callbacks.gso_segment))
			segs = ops->callbacks.gso_segment(skb, features);
	}
	if (IS_ERR(segs))
		goto out;
	if (segs == NULL)
		return ERR_PTR(-EINVAL);
	__skb_pull(skb, skb->data - skb_mac_header(skb));

	skb2 = segs;
	do {
		struct sk_buff *nskb = skb2->next;

		if (x->props.mode == XFRM_MODE_TUNNEL) {
			skb2->network_header = skb2->network_header - x->props.header_len;
			skb2->transport_header = skb2->network_header + sizeof(struct ipv6hdr);
			skb_reset_mac_len(skb2);
			skb_pull(skb2, skb2->mac_len + x->props.header_len);
		} else {
			/* skb2 mac and data are pointing at the start of
			 * mac address. Pull data forward to point to IP
			 * payload past ESP header (i.e., transport data
			 * that needs to be encrypted).
			 * When IPsec transport mode is stacked with a tunnel,
			 * the skb2->data needs to point at the inner IP
			 * header for tunnelled packets. After ->gso_segment,
			 * the skb2 wil have the network/ip header pointing
			 * at the inner IP header, and the transport_header
			 * will be pointing at the inner IP payload. Thus we
			 * need to use omaclen and the outer iphdr length to
			 * make sure that pointers are set up correctly in
			 * every case.
			 */

			 __skb_pull(skb2, omaclen + sizeof(struct ipv6hdr) + x->props.header_len);

			/* move ->transport_header to point to esp header */
			skb_reset_transport_header(skb2);
			skb2->transport_header -= x->props.header_len;
		}

		skb2->sp->flags |= SKB_GSO_SEGMENT;
		skb2->sp->seq.low = seq;
		skb2->sp->seq.hi = xfrm_replay_seqhi(x, ntohl(seq));

		err = x->type->output(x, skb2);
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


static const struct net_offload esp6_offload = {
	.callbacks = {
		.gro_receive = esp6_gro_receive,
		.gro_complete = esp6_gro_complete,
		.gso_segment = esp6_gso_segment,
	},
};

static int __init esp6_offload_init(void)
{
	return inet6_add_offload(&esp6_offload, IPPROTO_ESP);
}
device_initcall(esp6_offload_init);
