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

#ifndef __MLX5_EN_IPSEC_H__
#define __MLX5_EN_IPSEC_H__

#ifdef CONFIG_MLX5_IPSEC

#include <linux/mlx5/device.h>
#include <net/xfrm.h>
#include <linux/idr.h>

#define MLX5_IPSEC_SADB_RX_BITS 10

struct mlx5e_priv;
struct mlx5_core_dev;
struct mlx5e_sq;
struct mlx5e_rq;
struct mlx5e_channel;

struct mlx5_ipsec_dev {
	struct kobject kobj;
	struct mlx5e_priv *en_priv;
	struct list_head pending_cmds;
	spinlock_t pending_cmds_lock; /* Protects pending_cmds */
	DECLARE_HASHTABLE(sadb_rx, MLX5_IPSEC_SADB_RX_BITS);
	spinlock_t sadb_rx_lock; /* Protects sadb_rx and halloc */
	struct ida halloc;
	u32 ipsec_caps[MLX5_ST_SZ_DW(ipsec_extended_cap)];
};

void mlx5_ipsec_init(void);
int mlx5_ipsec_init_one(struct mlx5_core_dev *mdev, struct net_device *netdev);
void mlx5_ipsec_deinit_one(struct mlx5_core_dev *mdev,
			   struct net_device *netdev);

void mlx5_ipsec_build_netdev(struct mlx5_core_dev *mdev,
			     struct net_device *netdev);
bool mlx5_ipsec_feature_check(struct sk_buff *skb, struct net_device *netdev,
			      netdev_features_t features);
void mlx5_ipsec_create_sq(struct mlx5e_channel *c, struct mlx5e_sq *sq);
void mlx5_ipsec_create_rq(struct mlx5e_channel *c, struct mlx5e_rq *rq);

int mlx5_ipsec_get_count(struct net_device *netdev);
int mlx5_ipsec_get_strings(struct net_device *netdev, uint8_t *data);
int mlx5_ipsec_get_stats(struct net_device *netdev, u64 *data);

int mlx5_ipsec_sysfs_add(struct kobject *kobj, struct kobject *parent);
void mlx5_ipsec_dev_release(struct kobject *kobj);

#else

static inline void mlx5_ipsec_init(void)
{
}

static inline int mlx5_ipsec_init_one(struct mlx5_core_dev *mdev,
				      struct net_device *netdev)
{
	return 0;
}

static inline void mlx5_ipsec_deinit_one(struct mlx5_core_dev *mdev,
					 struct net_device *netdev)
{
}

static inline void mlx5_ipsec_build_netdev(struct mlx5_core_dev *mdev,
					   struct net_device *netdev)
{
}

static inline bool mlx5_ipsec_feature_check(struct sk_buff *skb,
					    struct net_device *netdev,
					    netdev_features_t features)
{
	return false;
}

static inline void mlx5_ipsec_create_sq(struct mlx5e_channel *c,
					struct mlx5e_sq *sq)
{
}

static inline void mlx5_ipsec_create_rq(struct mlx5e_channel *c,
					struct mlx5e_rq *rq)
{
}

static inline int mlx5_ipsec_get_count(struct net_device *netdev)
{
	return 0;
}

static inline int mlx5_ipsec_get_strings(struct net_device *netdev,
					 uint8_t *data)
{
	return 0;
}

static inline int mlx5_ipsec_get_stats(struct net_device *netdev, u64 *data)
{
	return 0;
}

#endif

#endif	/* __MLX5_EN_IPSEC_H__ */
