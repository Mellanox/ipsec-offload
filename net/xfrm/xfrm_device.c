/*
 * xfrm_device.c - IPsec device offloading code.
 *
 * Copyright (c) 2015 secunet Security Networks AG
 *
 * Author:
 * Steffen Klassert <steffen.klassert@secunet.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <linux/notifier.h>

static int xfrm_skb_check_space(struct sk_buff *skb, struct dst_entry *dst)
{
	int nhead = dst->header_len + LL_RESERVED_SPACE(dst->dev)
		- skb_headroom(skb);
	int ntail =  0;

	if (!(skb_shinfo(skb)->gso_type & SKB_GSO_ESP))
		ntail = dst->dev->needed_tailroom - skb_tailroom(skb);

	if (nhead <= 0) {
		if (ntail <= 0)
			return 0;
		nhead = 0;
	} else if (ntail < 0)
		ntail = 0;

	return pskb_expand_head(skb, nhead, ntail, GFP_ATOMIC);
}

int xfrm_dev_prepare(struct sk_buff *skb)
{
	int err;
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x = dst->xfrm;
	struct net *net = xs_net(x);

	skb_dst_force(skb);

	err = x->type->output(x, skb);
	if (err) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEPROTOERROR);
		goto error;
	}

	dst = dst->child;
	if (!dst) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
		err = -EHOSTUNREACH;
		goto error;
	}

	return 0;

error:
	kfree_skb(skb);
	return err;
}
EXPORT_SYMBOL(xfrm_dev_prepare);

int xfrm_dev_encap(struct sk_buff *skb)
{
	int err;
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x = dst->xfrm;
	struct net *net = xs_net(x);

	/* We support only one transformation. */
	if (dst->child && dst->child->xfrm) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
		kfree_skb(skb);
		return -EHOSTUNREACH;
	}

	err = xfrm_skb_check_space(skb, dst);
	if (err) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
		kfree_skb(skb);
		return err;
	}

	err = x->outer_mode->output(x, skb);
	if (err) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEMODEERROR);
		kfree_skb(skb);
		return err;
	}

	spin_lock_bh(&x->lock);

	if (unlikely(x->km.state != XFRM_STATE_VALID)) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEINVALID);
		err = -EINVAL;
		goto error;
	}

	err = xfrm_state_check_expire(x);
	if (err) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEEXPIRED);
		goto error;
	}

	err = x->repl->overflow(x, skb);
	if (err) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATESEQERROR);
		goto error;
	}

	x->curlft.bytes += skb->len;
	x->curlft.packets++;

	spin_unlock_bh(&x->lock);

	x->type->encap(x, skb);

	return 0;
error:
	spin_unlock_bh(&x->lock);
	kfree_skb(skb);

	return err;
}
EXPORT_SYMBOL(xfrm_dev_encap);

static int xfrm_dev_register(struct net_device *dev)
{
	if ((dev->features & NETIF_F_HW_ESP) && !dev->xfrmdev_ops)
		return NOTIFY_BAD;

	return NOTIFY_DONE;
}

static int xfrm_dev_unregister(struct net_device *dev)
{
	return NOTIFY_DONE;
}

static int xfrm_dev_feat_change(struct net_device *dev)
{
	if ((dev->features & NETIF_F_HW_ESP) && !dev->xfrmdev_ops)
		return NOTIFY_BAD;
	else if (!(dev->features & NETIF_F_HW_ESP))
		dev->xfrmdev_ops = NULL;

	return NOTIFY_DONE;
}

static int xfrm_dev_down(struct net_device *dev)
{
	if (dev->hw_features & NETIF_F_HW_ESP)
		xfrm_dev_state_flush(dev_net(dev), dev, true);

	xfrm_garbage_collect(dev_net(dev));

	return NOTIFY_DONE;
}

static int xfrm_dev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	switch (event) {
	case NETDEV_REGISTER:
		return xfrm_dev_register(dev);

	case NETDEV_UNREGISTER:
		return xfrm_dev_unregister(dev);

	case NETDEV_FEAT_CHANGE:
		return xfrm_dev_feat_change(dev);

	case NETDEV_DOWN:
		return xfrm_dev_down(dev);
	}
	return NOTIFY_DONE;
}

static struct notifier_block xfrm_dev_notifier = {
	.notifier_call	= xfrm_dev_event,
};

void __net_init xfrm_dev_init(void)
{
	register_netdevice_notifier(&xfrm_dev_notifier);
}
