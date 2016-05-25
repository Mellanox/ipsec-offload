/*
 * IPV4 GSO/GRO offload support
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
#include <net/udp.h>

static struct sk_buff **esp4_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	if (NAPI_GRO_CB(skb)->flush)
		goto out;

	skb_pull(skb, skb_gro_offset(skb));
	skb->xfrm_gro = 1;

	xfrm4_rcv_encap(skb, IPPROTO_ESP, 0, 0);

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

static struct sk_buff *esp4_gso_segment(struct sk_buff *skb,
				        netdev_features_t features)
{
	struct ip_esp_hdr *esph;
	struct sk_buff *skb2;
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x;
	struct crypto_aead *aead;
	int err = 0;
	const struct net_offload *ops;
	int proto;
	int omaclen;

	if (!dst || !dst->xfrm)
		goto out;

	x = dst->xfrm;
	aead = x->data;
	esph = ip_esp_hdr(skb);

	omaclen = skb->mac_len;
	proto = esph->seq_no;
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
		ops = rcu_dereference(inet_offloads[proto]);
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
			skb2->transport_header = skb2->network_header + sizeof(struct iphdr);
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
			struct iphdr *oiph =
				(struct iphdr *)(skb2->data + omaclen);
			int ihl = oiph->ihl * 4;

			 __skb_pull(skb2, omaclen + ihl + x->props.header_len);

			/* move ->transport_header to point to esp header */
			skb_reset_transport_header(skb2);
			skb2->transport_header -= x->props.header_len;
		}

		/* Set up eshp->seq_no to be used by esp_output()
		 * for initializing trailer.
		 */
		ip_esp_hdr(skb2)->seq_no = proto;

		err = dst->dev->xfrmdev_ops->xdo_dev_prepare(skb2);
		if (err) {
			kfree_skb_list(segs);
			return ERR_PTR(err);
		}

		skb_push(skb2, skb2->mac_len);
		skb2 = nskb;
	} while (skb2);

out:
	return segs;
}

static const struct net_offload esp4_offload = {
	.callbacks = {
		.gro_receive = esp4_gro_receive,
		.gro_complete = esp4_gro_complete,
		.gso_segment = esp4_gso_segment,
	},
};

static int __init esp4_offload_init(void)
{
	return inet_add_offload(&esp4_offload, IPPROTO_ESP);
}
device_initcall(esp4_offload_init);
