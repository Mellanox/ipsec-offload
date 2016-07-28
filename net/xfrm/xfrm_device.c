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

int xfrm_dev_register(struct net_device *dev)
{
	if ((dev->features & NETIF_F_HW_ESP) && !dev->xfrmdev_ops)
		return NOTIFY_BAD;
	if ((dev->features & NETIF_F_HW_ESP_TX_CSUM) &&
	    !(dev->features & NETIF_F_HW_CSUM))
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

	if ((dev->features & NETIF_F_HW_ESP_TX_CSUM) &&
	    !(dev->features & NETIF_F_HW_CSUM))
		return NOTIFY_BAD;

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
