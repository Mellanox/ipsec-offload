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

#include <linux/ethtool.h>
#include <net/sock.h>

#include "en.h"
#include "fpga/core.h"
#include "en_ipsec/ipsec.h"

static const char * const ipsec_stats_desc[] = {
	"ipsec_dec_in_packets",
	"ipsec_dec_out_packets",
	"ipsec_dec_bypass_packets",
	"ipsec_enc_in_packets",
	"ipsec_enc_out_packets",
	"ipsec_enc_bypass_packets",
	"ipsec_dec_drop_packets",
	"ipsec_dec_auth_fail_packets",
	"ipsec_enc_drop_packets",
	"ipsec_add_sa_success",
	"ipsec_add_sa_fail",
	"ipsec_del_sa_success",
	"ipsec_del_sa_fail",
	"ipsec_cmd_drop",
};

static int mlx5_ipsec_counters_count(struct mlx5_ipsec_dev *dev)
{
	u32 num_ipsec_cnt = MLX5_GET(ipsec_extended_cap, dev->ipsec_caps,
						number_of_ipsec_counters);
	if (num_ipsec_cnt > ARRAY_SIZE(ipsec_stats_desc))
		num_ipsec_cnt = ARRAY_SIZE(ipsec_stats_desc);

	return num_ipsec_cnt;
}

int mlx5_ipsec_get_count(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	u32 num_ipsec_cnt;

	if (!priv->ipsec)
		return 0;

	num_ipsec_cnt = mlx5_ipsec_counters_count(priv->ipsec);
	return num_ipsec_cnt;
}

int mlx5_ipsec_get_strings(struct net_device *netdev, uint8_t *data)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	u32 num_ipsec_cnt;
	unsigned int i;

	if (!priv->ipsec)
		return 0;

	num_ipsec_cnt = mlx5_ipsec_counters_count(priv->ipsec);
	for (i = 0; i < num_ipsec_cnt; i++)
		strcpy(data + (i * ETH_GSTRING_LEN), ipsec_stats_desc[i]);

	return num_ipsec_cnt;
}

int mlx5_ipsec_get_stats(struct net_device *netdev, u64 *data)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	u32 num_ipsec_cnt = 0;
	unsigned int i;
	u32 *word;
	u64 addr;
	int ret;

	if (!priv->ipsec)
		return 0;

	num_ipsec_cnt = mlx5_ipsec_counters_count(priv->ipsec);
	addr = (u64)MLX5_GET(ipsec_extended_cap, priv->ipsec->ipsec_caps,
			     ipsec_counters_addr_low) +
	       ((u64)MLX5_GET(ipsec_extended_cap, priv->ipsec->ipsec_caps,
			      ipsec_counters_addr_high) << 32);

	ret = mlx5_fpga_mem_read(priv->mdev->fpga,
				 num_ipsec_cnt * sizeof(u64), addr, data,
				 MLX5_FPGA_ACCESS_TYPE_DONTCARE);
	if (ret < 0) {
		netdev_err(netdev, "Failed to read IPSec counters from HW: %d\n",
			   ret);
		goto err;
	}

	/* Each counter is low word, then high. But each word is big-endian */
	for (word = (u32 *)data, i = 0; i < num_ipsec_cnt * 2; i++)
		word[i] = ntohl(word[i]);

	goto out;
err:
	memset(data, 0, sizeof(*data) * num_ipsec_cnt);
out:
	return num_ipsec_cnt;
}
