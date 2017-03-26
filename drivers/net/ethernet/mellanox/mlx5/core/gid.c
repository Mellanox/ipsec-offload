/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
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
 */

#include <linux/mlx5/driver.h>
#include <linux/etherdevice.h>
#include "mlx5_core.h"

int mlx5_core_gid_set(struct mlx5_core_dev *dev, unsigned int index,
		      u8 roce_version, u8 roce_l3_type, const u8 *gid,
		      const u8 *mac, bool vlan, u16 vlan_id)
{
#define MLX5_SET_RA(p, f, v) MLX5_SET(roce_addr_layout, p, f, v)
	u32  in[MLX5_ST_SZ_DW(set_roce_address_in)] = {0};
	u32 out[MLX5_ST_SZ_DW(set_roce_address_out)] = {0};
	void *in_addr = MLX5_ADDR_OF(set_roce_address_in, in, roce_address);
	char *addr_l3_addr = MLX5_ADDR_OF(roce_addr_layout, in_addr,
					  source_l3_address);
	void *addr_mac = MLX5_ADDR_OF(roce_addr_layout, in_addr,
				      source_mac_47_32);
	int gidsz = MLX5_FLD_SZ_BYTES(roce_addr_layout, source_l3_address);

	if (MLX5_CAP_GEN(dev, port_type) != MLX5_CAP_PORT_TYPE_ETH)
		return -EINVAL;

	if (gid) {
		if (vlan) {
			MLX5_SET_RA(in_addr, vlan_valid, 1);
			MLX5_SET_RA(in_addr, vlan_id, vlan_id);
		}

		ether_addr_copy(addr_mac, mac);
		MLX5_SET_RA(in_addr, roce_version, roce_version);
		MLX5_SET_RA(in_addr, roce_l3_type, roce_l3_type);
		memcpy(addr_l3_addr, gid, gidsz);
	}

	MLX5_SET(set_roce_address_in, in, roce_address_index, index);
	MLX5_SET(set_roce_address_in, in, opcode, MLX5_CMD_OP_SET_ROCE_ADDRESS);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}
EXPORT_SYMBOL(mlx5_core_gid_set);
