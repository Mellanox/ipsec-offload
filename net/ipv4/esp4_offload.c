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

static const struct net_offload esp4_offload = {
	.callbacks = {
		.gro_receive = esp4_gro_receive,
		.gro_complete = esp4_gro_complete,
	},
};

static int __init esp4_offload_init(void)
{
	return inet_add_offload(&esp4_offload, IPPROTO_ESP);
}
device_initcall(esp4_offload_init);
