/*
 * Copyright (c) 2017, Mellanox Technologies, Ltd.  All rights reserved.
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

#ifndef __MLX5_FPGA_H__
#define __MLX5_FPGA_H__

#include <linux/mlx5/driver.h>

enum mlx5_fpga_image {
	MLX5_FPGA_IMAGE_USER = 0,
	MLX5_FPGA_IMAGE_FACTORY,
};

enum mlx5_fpga_status {
	MLX5_FPGA_STATUS_SUCCESS = 0,
	MLX5_FPGA_STATUS_FAILURE = 1,
	MLX5_FPGA_STATUS_IN_PROGRESS = 2,
	MLX5_FPGA_STATUS_NONE = 0xFFFF,
};

struct mlx5_fpga_query {
	enum mlx5_fpga_image admin_image;
	enum mlx5_fpga_image oper_image;
	enum mlx5_fpga_status status;
};

enum mlx5_fpga_qpc_field_select {
	MLX5_FPGA_QPC_STATE = BIT(0),
};

struct mlx5_fpga_qpc {
	enum mlx5_ifc_fpga_qp_state		state;
	enum mlx5_ifc_fpga_qp_type		qp_type;
	enum mlx5_ifc_fpga_qp_service_type	st;
	u8					tclass;
	u16					ether_type;
	u8					pcp;
	u8					dei;
	u16					vlan_id;
	u32					next_rcv_psn;
	u32					next_send_psn;
	u16					pkey;
	u32					remote_qpn;
	u8					rnr_retry;
	u8					retry_count;
	u8					remote_mac[ETH_ALEN];
	struct in6_addr				remote_ip;
	u8					fpga_mac[ETH_ALEN];
	struct in6_addr				fpga_ip;
};

struct mlx5_fpga_qp_counters {
	u64 rx_ack_packets;
	u64 rx_send_packets;
	u64 tx_ack_packets;
	u64 tx_send_packets;
	u64 rx_total_drop;
};

int mlx5_fpga_caps(struct mlx5_core_dev *dev, u32 *caps);
int mlx5_fpga_query(struct mlx5_core_dev *dev, struct mlx5_fpga_query *query);

int mlx5_fpga_create_qp(struct mlx5_core_dev *dev,
			struct mlx5_fpga_qpc *fpga_qpc, u32 *fpga_qpn);
int mlx5_fpga_modify_qp(struct mlx5_core_dev *dev, u32 fpga_qpn,
			enum mlx5_fpga_qpc_field_select fields,
			struct mlx5_fpga_qpc *fpga_qpc);
int mlx5_fpga_query_qp(struct mlx5_core_dev *dev, u32 fpga_qpn,
		       struct mlx5_fpga_qpc *fpga_qpc);
int mlx5_fpga_query_qp_counters(struct mlx5_core_dev *dev, u32 fpga_qpn,
				bool clear, struct mlx5_fpga_qp_counters *data);
int mlx5_fpga_destroy_qp(struct mlx5_core_dev *dev, u32 fpga_qpn);

#endif /* __MLX5_FPGA_H__ */
