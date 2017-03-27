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

#ifndef __MLX5_FPGA_QP_H__
#define __MLX5_FPGA_QP_H__

#include <linux/mlx5/cq.h>
#include <linux/mlx5/qp.h>

#include "fpga.h"
#include "sdk.h"
#include "wq.h"

struct mlx5_fpga_conn {
	struct mlx5_fpga_device *fdev;
	u8 port_num;

	void (*recv_cb)(void *cb_arg, struct mlx5_fpga_dma_buf *buf);
	void *cb_arg;

	struct completion exit_sq_comp;
	struct completion exit_rq_comp;

	struct list_head list;

	/* FPGA QP */
	struct mlx5_fpga_qpc fpga_qpc;
	u32 fpga_qpn;

	/* CQ */
	struct mlx5_cqwq cqwq;
	struct mlx5_frag_wq_ctrl cqwq_ctrl;
	struct mlx5_core_cq mcq;

	/* QP */
	bool qp_active;
	struct mlx5_wq_qp qpwq;
	struct mlx5_wq_ctrl qpwq_ctrl;
	struct mlx5_core_qp mqp;

	/* QP.SQ */
	int sgid_index;
	spinlock_t sq_lock; /* Protects all SQ state */
	unsigned int sq_head;
	unsigned int sq_tail;
	unsigned int sq_size;
	struct mlx5_fpga_dma_buf **sq_bufs;

	/* QP.RQ */
	spinlock_t rq_lock; /* Protects all RQ state */
	unsigned int rq_head;
	unsigned int rq_tail;
	unsigned int rq_size;
	struct mlx5_fpga_dma_buf **rq_bufs;
};

int mlx5_fpga_qp_init(struct mlx5_fpga_device *fdev);
void mlx5_fpga_qp_deinit(struct mlx5_fpga_device *fdev);
int mlx5_fpga_qp_conn_create(struct mlx5_fpga_device *fdev,
			     struct mlx5_fpga_conn_attr *attr,
			     enum mlx5_ifc_fpga_qp_type qp_type,
			     struct mlx5_fpga_conn **connp);
void mlx5_fpga_qp_conn_destroy(struct mlx5_fpga_conn *conn);
int mlx5_fpga_qp_send(struct mlx5_fpga_conn *conn,
		      struct mlx5_fpga_dma_buf *buf);

#endif /* __MLX5_FPGA_QP_H__ */
