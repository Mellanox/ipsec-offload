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

#include <linux/etherdevice.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/vport.h>

#include "core.h"
#include "qp.h"

#define MLX5_FPGA_PKEY 0xFFFF
#define MLX5_FPGA_RECV_SIZE 2048

static int mlx5_fpga_qp_map_buf(struct mlx5_fpga_conn *conn,
				struct mlx5_fpga_dma_buf *buf)
{
	struct device *dma_device;
	int err;

	if (!buf->sg[0].data)
		goto out;

	dma_device = &conn->fdev->mdev->pdev->dev;
	buf->sg[0].dma_addr = dma_map_single(dma_device, buf->sg[0].data,
					     buf->sg[0].size, buf->dma_dir);
	err = dma_mapping_error(dma_device, buf->sg[0].dma_addr);
	if (err) {
		mlx5_fpga_warn(conn->fdev, "DMA error on sg 0: %d\n", err);
		err = -ENOMEM;
		goto out;
	}

	if (!buf->sg[1].data)
		goto out;

	buf->sg[1].dma_addr = dma_map_single(dma_device, buf->sg[1].data,
					     buf->sg[1].size, buf->dma_dir);
	err = dma_mapping_error(dma_device, buf->sg[1].dma_addr);
	if (err) {
		mlx5_fpga_warn(conn->fdev, "DMA error on sg 1: %d\n", err);
		dma_unmap_single(dma_device, buf->sg[0].dma_addr,
				 buf->sg[0].size, buf->dma_dir);
		err = -ENOMEM;
	}

out:
	return err;
}

static void mlx5_fpga_qp_unmap_buf(struct mlx5_fpga_conn *conn,
				   struct mlx5_fpga_dma_buf *buf)
{
	struct device *dma_device;

	dma_device = &conn->fdev->mdev->pdev->dev;
	if (buf->sg[1].data)
		dma_unmap_single(dma_device, buf->sg[1].dma_addr,
				 buf->sg[1].size, buf->dma_dir);

	if (buf->sg[0].data)
		dma_unmap_single(dma_device, buf->sg[0].dma_addr,
				 buf->sg[0].size, buf->dma_dir);
}

static int mlx5_fpga_qp_post_recv(struct mlx5_fpga_conn *conn,
				  struct mlx5_fpga_dma_buf *buf)
{
	struct mlx5_wqe_data_seg *data;
	unsigned long flags;
	unsigned int ix;
	int err = 0;

	/* Splitting the RX buffer is not supported */
	WARN_ON(buf->sg[1].data);

	if (!conn->qp_active) {
		err = -ENOTCONN;
		goto out;
	}

	err = mlx5_fpga_qp_map_buf(conn, buf);
	if (err)
		goto out;

	spin_lock_irqsave(&conn->rq_lock, flags);

	if (conn->rq_head - conn->rq_tail >= conn->rq_size) {
		err = -ENOMEM;
		goto out_unlock;
	}

	ix = conn->rq_head & (conn->rq_size - 1);
	data = mlx5_wq_qp_get_rwqe(&conn->qpwq, ix);
	data->byte_count = cpu_to_be32(buf->sg[0].size);
	data->lkey = cpu_to_be32(conn->fdev->mkey.key);
	data->addr = cpu_to_be64(buf->sg[0].dma_addr);
#ifdef DEBUG
	print_hex_dump_bytes("Recv WQE ", DUMP_PREFIX_OFFSET, data, 16);
#endif

	conn->rq_head++;
	conn->rq_bufs[ix] = buf;

	/* Make sure that descriptors are written before doorbell record. */
	wmb();
	conn->qpwq.db[MLX5_RCV_DBR] = cpu_to_be32(conn->rq_head & 0xffff);

out_unlock:
	spin_unlock_irqrestore(&conn->rq_lock, flags);
	mlx5_fpga_qp_unmap_buf(conn, buf);
out:
	return err;
}

static void mlx5_fpga_qp_recv_complete(struct mlx5_fpga_device *fdev,
				       struct mlx5_fpga_conn *conn,
				       struct mlx5_fpga_dma_buf *buf, u8 status)
{
	int err;

	buf->sg[0].size = MLX5_FPGA_RECV_SIZE;
	err = mlx5_fpga_qp_post_recv(conn, buf);
	if (err) {
		if (err != -ENOTCONN)
			mlx5_fpga_warn(conn->fdev,
				       "Failed to re-post recv buf: %d\n", err);
		kfree(buf);
	}
}

static void mlx5_fpga_qp_ring_db(struct mlx5_fpga_device *fdev, void *wqe)
{
	unsigned long flags;

	spin_lock_irqsave(&fdev->bf_lock, flags);
	mlx5_write64(wqe, fdev->uar->map + MLX5_BF_OFFSET + fdev->bf_ofs,
		     NULL);
	/* flush the mapped UAR buffer, to ring HW doorbell */
	wmb();
	fdev->bf_ofs ^= fdev->bf_sz;
	spin_unlock_irqrestore(&fdev->bf_lock, flags);
}

int mlx5_fpga_qp_send(struct mlx5_fpga_conn *conn,
		      struct mlx5_fpga_dma_buf *buf)
{
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_data_seg *data;
	unsigned long flags;
	unsigned int ix;
	int size = 1;
	int err;

	err = mlx5_fpga_qp_map_buf(conn, buf);
	if (err)
		goto out;

	spin_lock_irqsave(&conn->sq_lock, flags);

	if (conn->sq_head - conn->sq_tail >= conn->sq_size) {
		err = -ENOMEM;
		goto out_unlock;
	}

	ix = conn->sq_head & (conn->sq_size - 1);

	ctrl = mlx5_wq_qp_get_swqe(&conn->qpwq, ix);
	data = (void *)(ctrl + 1);

	data->byte_count = cpu_to_be32(buf->sg[0].size);
	data->lkey = cpu_to_be32(conn->fdev->mkey.key);
	data->addr = cpu_to_be64(buf->sg[0].dma_addr);
	data++;
	size++;

	if (buf->sg[1].data) {
		data->byte_count = cpu_to_be32(buf->sg[1].size);
		data->lkey = cpu_to_be32(conn->fdev->mkey.key);
		data->addr = cpu_to_be64(buf->sg[1].dma_addr);
		data++;
		size++;
	}

	ctrl->imm = 0;
	ctrl->fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;
	ctrl->opmod_idx_opcode = cpu_to_be32(((conn->sq_head & 0xffff) << 8) |
					     MLX5_OPCODE_SEND);
	ctrl->qpn_ds = cpu_to_be32(size | (conn->mqp.qpn << 8));
#ifdef DEBUG
	print_hex_dump_bytes("Send WQE ", DUMP_PREFIX_OFFSET, ctrl, size * 16);
#endif

	conn->sq_head++;
	conn->sq_bufs[ix] = buf;
	/* Make sure that descriptors are written before doorbell record. */
	wmb();
	conn->qpwq.db[MLX5_SND_DBR] = cpu_to_be32(conn->sq_head);
	/* Make sure that doorbell record is written before ringing */
	wmb();
	mlx5_fpga_qp_ring_db(conn->fdev, ctrl);

out_unlock:
	spin_unlock_irqrestore(&conn->sq_lock, flags);
out:
	return err;
}

static int mlx5_fpga_qp_post_recv_buf(struct mlx5_fpga_conn *conn)
{
	struct mlx5_fpga_dma_buf *buf;
	int err;

	buf = kzalloc(sizeof(*buf) + MLX5_FPGA_RECV_SIZE, 0);
	if (!buf)
		return -ENOMEM;

	buf->sg[0].data = (void *)(buf + 1);
	buf->sg[0].size = MLX5_FPGA_RECV_SIZE;
	buf->dma_dir = DMA_FROM_DEVICE;
	buf->complete = mlx5_fpga_qp_recv_complete;

	err = mlx5_fpga_qp_post_recv(conn, buf);
	if (err)
		goto err_buf;

	goto out;

err_buf:
	kfree(buf);
out:
	return err;
}

static int mlx5_fpga_qp_find_pkey(struct mlx5_fpga_device *fdev)
{
	int i, err, tblsz;
	u16 pkey;

	tblsz = mlx5_to_sw_pkey_sz(MLX5_CAP_GEN(fdev->mdev, pkey_table_size));
	for (i = 0; i < tblsz; ++i) {
		err = mlx5_query_hca_vport_pkey(fdev->mdev, 0, fdev->port, 0,
						i, &pkey);
		if (err)
			return err;

		if (pkey == MLX5_FPGA_PKEY) {
			fdev->pkey_index = i;
			return 0;
		}
	}
	return -ENOENT;
}

static int mlx5_fpga_qp_create_mkey(struct mlx5_core_dev *mdev, u32 pdn,
				    struct mlx5_core_mkey *mkey)
{
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	void *mkc;
	u32 *in;
	int err;

	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, access_mode, MLX5_MKC_ACCESS_MODE_PA);
	MLX5_SET(mkc, mkc, lw, 1);
	MLX5_SET(mkc, mkc, lr, 1);

	MLX5_SET(mkc, mkc, pd, pdn);
	MLX5_SET(mkc, mkc, length64, 1);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);

	err = mlx5_core_create_mkey(mdev, mkey, in, inlen);

	kvfree(in);
	return err;
}

int mlx5_fpga_qp_init(struct mlx5_fpga_device *fdev)
{
	int err;

	err = mlx5_fpga_qp_find_pkey(fdev);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to find pkey: %d\n", err);
		goto out;
	}
	mlx5_fpga_dbg(fdev, "Found pkey 0x%x at index %u\n",
		      MLX5_FPGA_PKEY, fdev->pkey_index);

	err = mlx5_nic_vport_enable_roce(fdev->mdev);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to enable RoCE: %d\n", err);
		goto out;
	}

	fdev->uar = mlx5_get_uars_page(fdev->mdev);
	if (IS_ERR(fdev->uar)) {
		err = PTR_ERR(fdev->uar);
		mlx5_fpga_err(fdev, "get_uars_page failed, %d\n", err);
		goto err_roce;
	}
	mlx5_fpga_dbg(fdev, "Allocated UAR index %u\n", fdev->uar->index);
	fdev->bf_sz = (1 << MLX5_CAP_GEN(fdev->mdev, log_bf_reg_size)) / 2;

	err = mlx5_core_alloc_pd(fdev->mdev, &fdev->pdn);
	if (err) {
		mlx5_fpga_err(fdev, "alloc pd failed, %d\n", err);
		goto err_uar;
	}
	mlx5_fpga_dbg(fdev, "Allocated PD %u\n", fdev->pdn);

	err = mlx5_fpga_qp_create_mkey(fdev->mdev, fdev->pdn, &fdev->mkey);
	if (err) {
		mlx5_fpga_err(fdev, "create mkey failed, %d\n", err);
		goto err_dealloc_pd;
	}
	mlx5_fpga_dbg(fdev, "Created mkey 0x%x\n", fdev->mkey.key);

	return 0;

err_dealloc_pd:
	mlx5_core_dealloc_pd(fdev->mdev, fdev->pdn);
err_uar:
	mlx5_put_uars_page(fdev->mdev, fdev->uar);
err_roce:
	mlx5_nic_vport_enable_roce(fdev->mdev);
out:
	return err;
}

void mlx5_fpga_qp_deinit(struct mlx5_fpga_device *fdev)
{
	mlx5_core_destroy_mkey(fdev->mdev, &fdev->mkey);
	mlx5_core_dealloc_pd(fdev->mdev, fdev->pdn);
	mlx5_put_uars_page(fdev->mdev, fdev->uar);
	mlx5_nic_vport_enable_roce(fdev->mdev);
}

static void mlx5_fpga_qp_buf_complete(struct mlx5_fpga_conn *conn,
				      struct mlx5_fpga_dma_buf *buf, u8 status)
{
	if (status && (status != MLX5_CQE_SYNDROME_WR_FLUSH_ERR))
		mlx5_fpga_warn(conn->fdev, "buf %p completion status %d\n",
			       buf, status);
	else
		mlx5_fpga_dbg(conn->fdev, "buf %p completion status %d\n",
			      buf, status);

	mlx5_fpga_qp_unmap_buf(conn, buf);

	if (status) {
		conn->qp_active = false;
	} else {
		if (buf->dma_dir == DMA_FROM_DEVICE) {
#ifdef DEBUG
			print_hex_dump_bytes("RECV Data ", DUMP_PREFIX_OFFSET,
					     buf->sg[0].data, buf->sg[0].size);
#endif
			mlx5_fpga_dbg(conn->fdev, "Message with %u bytes received successfully\n",
				      buf->sg[0].size);
			conn->recv_cb(conn->cb_arg, buf);
		} else {
			mlx5_fpga_dbg(conn->fdev, "Message sent\n");
		}
	}

	if (buf->complete)
		buf->complete(conn->fdev, conn, buf, status);
}

static void mlx5_fpga_qp_free_recv_bufs(struct mlx5_fpga_conn *conn)
{
	int ix;

	for (ix = 0; ix < conn->rq_size; ix++) {
		if (!conn->rq_bufs[ix])
			continue;
		mlx5_fpga_qp_buf_complete(conn, conn->rq_bufs[ix],
					  MLX5_CQE_SYNDROME_WR_FLUSH_ERR);
		conn->rq_bufs[ix] = NULL;
	}
}

static struct mlx5_cqe64 *mlx5_fpga_qp_get_cqe(struct mlx5_cqwq *cqwq)
{
	int cqe_ownership, sw_own_val;
	struct mlx5_cqe64 *cqe;
	u32 ci;

	ci = mlx5_cqwq_get_ci(cqwq);
	cqe = mlx5_cqwq_get_wqe(cqwq, ci);
	cqe_ownership = cqe->op_own & MLX5_CQE_OWNER_MASK;
	sw_own_val = mlx5_cqwq_get_wrap_cnt(cqwq) & 1;

	if (cqe_ownership != sw_own_val)
		return NULL;

	/* ensure cqe content is read after cqe ownership bit */
	rmb();

	return cqe;
}

static void mlx5_fpga_qp_rq_cqe(struct mlx5_fpga_conn *conn,
				struct mlx5_cqe64 *cqe, u8 status)
{
	struct mlx5_fpga_dma_buf *buf;
	unsigned long flags;
	int ix;

	spin_lock_irqsave(&conn->rq_lock, flags);

	ix = be16_to_cpu(cqe->wqe_counter) & (conn->rq_size - 1);
	buf = conn->rq_bufs[ix];
	conn->rq_bufs[ix] = NULL;
	if (!status)
		buf->sg[0].size = be32_to_cpu(cqe->byte_cnt);
	conn->rq_tail++;

	spin_unlock_irqrestore(&conn->rq_lock, flags);

	mlx5_fpga_qp_buf_complete(conn, buf, status);
}

static void mlx5_fpga_qp_sq_cqe(struct mlx5_fpga_conn *conn,
				struct mlx5_cqe64 *cqe, u8 status)
{
	struct mlx5_fpga_dma_buf *buf;
	unsigned long flags;
	int ix;

	spin_lock_irqsave(&conn->sq_lock, flags);

	ix = be16_to_cpu(cqe->wqe_counter) & (conn->sq_size - 1);
	buf = conn->sq_bufs[ix];
	conn->sq_tail++;

	spin_unlock_irqrestore(&conn->sq_lock, flags);

	mlx5_fpga_qp_buf_complete(conn, buf, status);
}

static void mlx5_fpga_qp_handle_cqe(struct mlx5_fpga_conn *conn,
				    struct mlx5_cqe64 *cqe)
{
	u8 opcode, status = 0;

	opcode = cqe->op_own >> 4;

	switch (opcode) {
	case MLX5_CQE_REQ_ERR:
		status = ((struct mlx5_err_cqe *)cqe)->syndrome;
		/* Fall through */
	case MLX5_CQE_REQ:
		mlx5_fpga_qp_sq_cqe(conn, cqe, status);
		break;

	case MLX5_CQE_RESP_ERR:
		status = ((struct mlx5_err_cqe *)cqe)->syndrome;
		/* Fall through */
	case MLX5_CQE_RESP_SEND:
		mlx5_fpga_qp_rq_cqe(conn, cqe, status);
		break;
	default:
		mlx5_fpga_warn(conn->fdev, "Unexpected cqe opcode %u\n",
			       opcode);
	}
}

static void mlx5_fpga_qp_arm_cq(struct mlx5_fpga_conn *conn)
{
	mlx5_cq_arm(&conn->mcq, MLX5_CQ_DB_REQ_NOT, conn->fdev->uar->map,
		    conn->cqwq.cc);
}

static void mlx5_fpga_qp_cq_complete(struct mlx5_core_cq *mcq)
{
	struct mlx5_fpga_conn *conn;
	struct mlx5_cqe64 *cqe;

	conn = container_of(mcq, struct mlx5_fpga_conn, mcq);

	while (NULL != (cqe = mlx5_fpga_qp_get_cqe(&conn->cqwq))) {
		mlx5_cqwq_pop(&conn->cqwq);
		mlx5_fpga_qp_handle_cqe(conn, cqe);
		mlx5_cqwq_update_db_record(&conn->cqwq);
	}

	mlx5_fpga_dbg(conn->fdev, "Re-arming CQ with cc# %u\n", conn->cqwq.cc);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

	mlx5_fpga_qp_arm_cq(conn);
}

static void mlx5_fpga_qp_cq_event(struct mlx5_core_cq *mcq,
				  enum mlx5_event event)
{
	struct mlx5_fpga_conn *conn;

	conn = container_of(mcq, struct mlx5_fpga_conn, mcq);
	mlx5_fpga_warn(conn->fdev, "CQ event %u\n", event);
}

static void mlx5_fpga_qp_event(struct mlx5_core_qp *mqp, int event)
{
	struct mlx5_fpga_conn *conn;

	conn = container_of(mqp, struct mlx5_fpga_conn, mqp);
	mlx5_fpga_warn(conn->fdev, "QP event %u\n", event);
}

static int mlx5_fpga_qp_create_cq(struct mlx5_fpga_conn *conn, int cq_size)
{
	struct mlx5_fpga_device *fdev = conn->fdev;
	struct mlx5_core_dev *mdev = fdev->mdev;
	u32 temp_cqc[MLX5_ST_SZ_DW(cqc)] = {0};
	struct mlx5_wq_param wqp;
	struct mlx5_cqe64 *cqe;
	int inlen, err, eqn;
	unsigned int irqn;
	void *cqc, *in;
	__be64 *pas;
	u32 i;

	cq_size = roundup_pow_of_two(cq_size);
	MLX5_SET(cqc, temp_cqc, log_cq_size, ilog2(cq_size));

	wqp.buf_numa_node = mdev->priv.numa_node;
	wqp.db_numa_node  = mdev->priv.numa_node;

	err = mlx5_cqwq_create(mdev, &wqp, temp_cqc, &conn->cqwq,
			       &conn->cqwq_ctrl);
	if (err)
		return err;

	for (i = 0; i < mlx5_cqwq_get_size(&conn->cqwq); i++) {
		cqe = mlx5_cqwq_get_wqe(&conn->cqwq, i);
		cqe->op_own = MLX5_CQE_INVALID << 4 | MLX5_CQE_OWNER_MASK;
	}

	inlen = MLX5_ST_SZ_BYTES(create_cq_in) +
		sizeof(u64) * conn->cqwq_ctrl.frag_buf.npages;
	in = mlx5_vzalloc(inlen);
	if (!in) {
		err = -ENOMEM;
		goto err_cqwq;
	}

	mlx5_vector2eqn(mdev, 0, &eqn, &irqn);

	cqc = MLX5_ADDR_OF(create_cq_in, in, cq_context);
	MLX5_SET(cqc, cqc, log_cq_size, ilog2(cq_size));
	MLX5_SET(cqc, cqc, c_eqn, eqn);
	MLX5_SET(cqc, cqc, uar_page, fdev->uar->index);
	MLX5_SET(cqc, cqc, log_page_size, conn->cqwq_ctrl.frag_buf.page_shift -
			   MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET64(cqc, cqc, dbr_addr, conn->cqwq_ctrl.db.dma);

	pas = (__be64 *)MLX5_ADDR_OF(create_cq_in, in, pas);
	mlx5_fill_page_frag_array(&conn->cqwq_ctrl.frag_buf, pas);

	err = mlx5_core_create_cq(mdev, &conn->mcq, in, inlen);
	kvfree(in);

	if (err)
		goto err_cqwq;

	conn->mcq.cqe_sz     = 64;
	conn->mcq.set_ci_db  = conn->cqwq_ctrl.db.db;
	conn->mcq.arm_db     = conn->cqwq_ctrl.db.db + 1;
	*conn->mcq.set_ci_db = 0;
	*conn->mcq.arm_db    = 0;
	conn->mcq.vector     = 0;
	conn->mcq.comp       = mlx5_fpga_qp_cq_complete;
	conn->mcq.event      = mlx5_fpga_qp_cq_event;
	conn->mcq.irqn       = irqn;
	conn->mcq.uar        = fdev->uar;

	mlx5_fpga_dbg(fdev, "Created CQ #0x%x\n", conn->mcq.cqn);

	goto out;

err_cqwq:
	mlx5_cqwq_destroy(&conn->cqwq_ctrl);
out:
	return err;
}

static void mlx5_fpga_qp_destroy_cq(struct mlx5_fpga_conn *conn)
{
	mlx5_core_destroy_cq(conn->fdev->mdev, &conn->mcq);
	mlx5_cqwq_destroy(&conn->cqwq_ctrl);
}

static int mlx5_fpga_qp_create_wq(struct mlx5_fpga_conn *conn, int rq_size,
				  int sq_size)
{
	struct mlx5_fpga_device *fdev = conn->fdev;
	struct mlx5_core_dev *mdev = fdev->mdev;
	struct mlx5_wq_param wqp;

	wqp.buf_numa_node = mdev->priv.numa_node;
	wqp.db_numa_node  = mdev->priv.numa_node;
	return mlx5_wq_qp_create(mdev, &wqp, ilog2(MLX5_SEND_WQE_DS),
				 ilog2(rq_size), ilog2(sq_size), &conn->qpwq,
				 &conn->qpwq_ctrl);
}

static int mlx5_fpga_qp_create_qp(struct mlx5_fpga_conn *conn,
				  unsigned int tx_size, unsigned int rx_size)
{
	struct mlx5_fpga_device *fdev = conn->fdev;
	struct mlx5_core_dev *mdev = fdev->mdev;
	void *in, *qpc;
	int err, inlen;

	conn->rq_head = 0;
	conn->rq_tail = 0;
	conn->rq_size = roundup_pow_of_two(rx_size);
	conn->sq_head = 0;
	conn->sq_tail = 0;
	conn->sq_size = roundup_pow_of_two(tx_size);

	err = mlx5_fpga_qp_create_wq(conn, conn->rq_size, conn->sq_size);
	if (err)
		goto out;

	conn->rq_bufs = mlx5_vzalloc(sizeof(conn->rq_bufs[0]) * conn->rq_size);
	if (!conn->rq_bufs) {
		err = -ENOMEM;
		goto err_wq;
	}

	conn->sq_bufs = mlx5_vzalloc(sizeof(conn->sq_bufs[0]) * conn->sq_size);
	if (!conn->sq_bufs) {
		err = -ENOMEM;
		goto err_rq_bufs;
	}

	inlen = MLX5_ST_SZ_BYTES(create_qp_in) +
		MLX5_FLD_SZ_BYTES(create_qp_in, pas[0]) *
		conn->qpwq_ctrl.buf.npages;
	in = mlx5_vzalloc(inlen);
	if (!in) {
		err = -ENOMEM;
		goto err_sq_bufs;
	}

	qpc = MLX5_ADDR_OF(create_qp_in, in, qpc);
	MLX5_SET(qpc, qpc, uar_page, fdev->uar->index);
	MLX5_SET(qpc, qpc, log_page_size,
		 conn->qpwq_ctrl.buf.page_shift - MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET(qpc, qpc, fre, 1);
	MLX5_SET(qpc, qpc, rlky, 1);
	MLX5_SET(qpc, qpc, st, MLX5_QP_ST_RC);
	MLX5_SET(qpc, qpc, pm_state, MLX5_QP_PM_MIGRATED);
	MLX5_SET(qpc, qpc, pd, fdev->pdn);
	MLX5_SET(qpc, qpc, log_rq_stride, conn->qpwq.log_stride_rq - 4);
	MLX5_SET(qpc, qpc, log_rq_size, ilog2(conn->rq_size));
	MLX5_SET(qpc, qpc, rq_type, MLX5_NON_ZERO_RQ);
	MLX5_SET(qpc, qpc, log_sq_size, ilog2(conn->sq_size));
	MLX5_SET(qpc, qpc, cqn_snd, conn->mcq.cqn);
	MLX5_SET(qpc, qpc, cqn_rcv, conn->mcq.cqn);
	MLX5_SET64(qpc, qpc, dbr_addr, conn->qpwq_ctrl.db.dma);
	if (MLX5_CAP_GEN(mdev, cqe_version) == 1)
		MLX5_SET(qpc, qpc, user_index, 0xFFFFFF);

	mlx5_fill_page_array(&conn->qpwq_ctrl.buf,
			     (__be64 *)MLX5_ADDR_OF(create_qp_in, in, pas));

	err = mlx5_core_create_qp(mdev, &conn->mqp, in, inlen);
	kvfree(in);

	if (err)
		goto err_sq_bufs;

	conn->mqp.event = mlx5_fpga_qp_event;
	mlx5_fpga_dbg(fdev, "Created QP #0x%x\n", conn->mqp.qpn);

	goto out;

err_sq_bufs:
	kvfree(conn->sq_bufs);
err_rq_bufs:
	kvfree(conn->rq_bufs);
err_wq:
	mlx5_wq_destroy(&conn->qpwq_ctrl);
out:
	return err;
}

static void mlx5_fpga_qp_destroy_qp(struct mlx5_fpga_conn *conn)
{
	mlx5_core_destroy_qp(conn->fdev->mdev, &conn->mqp);
	kvfree(conn->sq_bufs);
	kvfree(conn->rq_bufs);
	mlx5_wq_destroy(&conn->qpwq_ctrl);
}

static inline int mlx5_fpga_qp_reset_qp(struct mlx5_fpga_conn *conn)
{
	struct mlx5_core_dev *mdev = conn->fdev->mdev;

	mlx5_fpga_dbg(conn->fdev, "QP RST\n");

	return mlx5_core_qp_modify(mdev, MLX5_CMD_OP_2RST_QP, 0, NULL,
				   &conn->mqp);
}

static inline int mlx5_fpga_qp_init_qp(struct mlx5_fpga_conn *conn)
{
	struct mlx5_fpga_device *fdev = conn->fdev;
	struct mlx5_core_dev *mdev = fdev->mdev;
	u32 *qpc = NULL;
	int err;

	mlx5_fpga_dbg(conn->fdev, "QP INIT\n");

	qpc = kzalloc(MLX5_ST_SZ_BYTES(qpc), GFP_KERNEL);
	if (!qpc) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(qpc, qpc, st, MLX5_QP_ST_RC);
	MLX5_SET(qpc, qpc, pm_state, MLX5_QP_PM_MIGRATED);
	MLX5_SET(qpc, qpc, primary_address_path.pkey_index,
		 conn->fdev->pkey_index);
	MLX5_SET(qpc, qpc, primary_address_path.port, conn->port_num);
	MLX5_SET(qpc, qpc, pd, conn->fdev->pdn);
	MLX5_SET(qpc, qpc, cqn_snd, conn->mcq.cqn);
	MLX5_SET(qpc, qpc, cqn_rcv, conn->mcq.cqn);
	MLX5_SET64(qpc, qpc, dbr_addr, conn->qpwq_ctrl.db.dma);

	err = mlx5_core_qp_modify(mdev, MLX5_CMD_OP_RST2INIT_QP, 0, qpc,
				  &conn->mqp);
	if (err) {
		mlx5_fpga_warn(fdev, "qp_modify RST2INIT failed: %d\n", err);
		goto out;
	}

out:
	kfree(qpc);
	return err;
}

static inline int mlx5_fpga_qp_rtr_qp(struct mlx5_fpga_conn *conn)
{
	struct mlx5_fpga_device *fdev = conn->fdev;
	struct mlx5_core_dev *mdev = fdev->mdev;
	u32 *qpc = NULL;
	int err;

	mlx5_fpga_dbg(conn->fdev, "QP RTR\n");

	qpc = kzalloc(MLX5_ST_SZ_BYTES(qpc), GFP_KERNEL);
	if (!qpc) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(qpc, qpc, mtu, MLX5_QPC_MTU_1K_BYTES);
	MLX5_SET(qpc, qpc, log_msg_max, (u8)MLX5_CAP_GEN(mdev, log_max_msg));
	MLX5_SET(qpc, qpc, remote_qpn, conn->fpga_qpn);
	MLX5_SET(qpc, qpc, next_rcv_psn, conn->fpga_qpc.next_send_psn);
	MLX5_SET(qpc, qpc, primary_address_path.pkey_index,
		 conn->fdev->pkey_index);
	MLX5_SET(qpc, qpc, primary_address_path.port, conn->port_num);
	ether_addr_copy(MLX5_ADDR_OF(qpc, qpc, primary_address_path.rmac_47_32),
			conn->fpga_qpc.fpga_mac);
	MLX5_SET(qpc, qpc, primary_address_path.udp_sport,
		 MLX5_CAP_ROCE(mdev, r_roce_min_src_udp_port));
	MLX5_SET(qpc, qpc, primary_address_path.src_addr_index,
		 conn->sgid_index);
	MLX5_SET(qpc, qpc, primary_address_path.hop_limit, 0);
	memcpy(MLX5_ADDR_OF(qpc, qpc, primary_address_path.rgid_rip),
	       &conn->fpga_qpc.fpga_ip,
	       MLX5_FLD_SZ_BYTES(qpc, primary_address_path.rgid_rip));

	err = mlx5_core_qp_modify(mdev, MLX5_CMD_OP_INIT2RTR_QP, 0, qpc,
				  &conn->mqp);
	if (err) {
		mlx5_fpga_warn(fdev, "qp_modify RST2INIT failed: %d\n", err);
		goto out;
	}

out:
	kfree(qpc);
	return err;
}

static inline int mlx5_fpga_qp_rts_qp(struct mlx5_fpga_conn *conn)
{
	struct mlx5_fpga_device *fdev = conn->fdev;
	struct mlx5_core_dev *mdev = fdev->mdev;
	u32 *qpc = NULL;
	u32 opt_mask;
	int err;

	mlx5_fpga_dbg(conn->fdev, "QP RTS\n");

	qpc = kzalloc(MLX5_ST_SZ_BYTES(qpc), GFP_KERNEL);
	if (!qpc) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(qpc, qpc, log_ack_req_freq, 8);
	MLX5_SET(qpc, qpc, min_rnr_nak, 0x12);
	MLX5_SET(qpc, qpc, primary_address_path.ack_timeout, 0x12); /* ~1.07s */
	MLX5_SET(qpc, qpc, next_send_psn, conn->fpga_qpc.next_rcv_psn);
	MLX5_SET(qpc, qpc, retry_count, 7);
	MLX5_SET(qpc, qpc, rnr_retry, 7); /* Infinite retry if RNR NACK */

	opt_mask = MLX5_QP_OPTPAR_RNR_TIMEOUT;
	err = mlx5_core_qp_modify(mdev, MLX5_CMD_OP_RTR2RTS_QP, opt_mask, qpc,
				  &conn->mqp);
	if (err) {
		mlx5_fpga_warn(fdev, "qp_modify RST2INIT failed: %d\n", err);
		goto out;
	}

out:
	kfree(qpc);
	return err;
}

static int mlx5_fpga_qp_connect(struct mlx5_fpga_conn *conn)
{
	struct mlx5_fpga_device *fdev = conn->fdev;
	int err;

	conn->fpga_qpc.state = MLX5_FPGA_QPC_STATE_ACTIVE;
	err = mlx5_fpga_modify_qp(conn->fdev->mdev, conn->fpga_qpn,
				  MLX5_FPGA_QPC_STATE, &conn->fpga_qpc);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to activate FPGA RC QP: %d\n", err);
		goto out;
	}

	err = mlx5_fpga_qp_reset_qp(conn);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to change QP state to reset\n");
		goto err_fpga_qp;
	}

	err = mlx5_fpga_qp_init_qp(conn);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to modify QP from RESET to INIT\n");
		goto err_fpga_qp;
	}
	conn->qp_active = true;

	while (!mlx5_fpga_qp_post_recv_buf(conn))
		;

	err = mlx5_fpga_qp_rtr_qp(conn);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to change QP state from INIT to RTR\n");
		goto err_recv_bufs;
	}

	err = mlx5_fpga_qp_rts_qp(conn);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to change QP state from RTR to RTS\n");
		goto err_recv_bufs;
	}
	goto out;

err_recv_bufs:
	mlx5_fpga_qp_free_recv_bufs(conn);
err_fpga_qp:
	conn->fpga_qpc.state = MLX5_FPGA_QPC_STATE_INIT;
	if (mlx5_fpga_modify_qp(conn->fdev->mdev, conn->fpga_qpn,
				MLX5_FPGA_QPC_STATE, &conn->fpga_qpc))
		mlx5_fpga_err(fdev, "Failed to revert FPGA QP to INIT\n");
out:
	return err;
}

int mlx5_fpga_qp_conn_create(struct mlx5_fpga_device *fdev,
			     struct mlx5_fpga_conn_attr *attr,
			     enum mlx5_ifc_fpga_qp_type qp_type,
			     struct mlx5_fpga_conn **connp)
{
	struct mlx5_fpga_conn *conn = NULL;
	int err;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn) {
		err = -ENOMEM;
		goto err;
	}

	if (!attr->recv_cb) {
		err = -EINVAL;
		goto err;
	}

	conn->fdev = fdev;
	conn->port_num = fdev->port;

	spin_lock_init(&conn->sq_lock);
	spin_lock_init(&conn->rq_lock);

	conn->recv_cb = attr->recv_cb;
	conn->cb_arg = attr->cb_arg;

	err = mlx5_query_nic_vport_mac_address(fdev->mdev, 0,
					       conn->fpga_qpc.remote_mac);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to query local MAC: %d\n", err);
		goto err;
	}

	conn->fpga_qpc.remote_ip.s6_addr[0] = 0xfe;
	conn->fpga_qpc.remote_ip.s6_addr[1] = 0x80;
	conn->fpga_qpc.remote_ip.s6_addr[8] = conn->fpga_qpc.remote_mac[0] ^
					      0x02;
	conn->fpga_qpc.remote_ip.s6_addr[9] = conn->fpga_qpc.remote_mac[1];
	conn->fpga_qpc.remote_ip.s6_addr[10] = conn->fpga_qpc.remote_mac[2];
	conn->fpga_qpc.remote_ip.s6_addr[11] = 0xff;
	conn->fpga_qpc.remote_ip.s6_addr[12] = 0xfe;
	conn->fpga_qpc.remote_ip.s6_addr[13] = conn->fpga_qpc.remote_mac[3];
	conn->fpga_qpc.remote_ip.s6_addr[14] = conn->fpga_qpc.remote_mac[4];
	conn->fpga_qpc.remote_ip.s6_addr[15] = conn->fpga_qpc.remote_mac[5];

	err = mlx5_core_reserved_gid_add(fdev->mdev, &conn->sgid_index);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to reserve SGID: %d\n", err);
		goto err;
	}

	err = mlx5_core_gid_set(fdev->mdev, conn->sgid_index,
				MLX5_ROCE_VERSION_2, MLX5_ROCE_L3_TYPE_IPV6,
				conn->fpga_qpc.remote_ip.s6_addr,
				conn->fpga_qpc.remote_mac, true, 0);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to set SGID: %d\n", err);
		goto err_rsvd_gid;
	}
	mlx5_fpga_dbg(fdev, "Reserved SGID index %u\n", conn->sgid_index);

	/* Allow for one cqe per rx/tx wqe, plus one cqe for the next wqe,
	 * created during processing of the cqe
	 */
	err = mlx5_fpga_qp_create_cq(conn, (attr->tx_size + attr->rx_size) * 2);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to create CQ: %d\n", err);
		goto err_gid;
	}

	mlx5_fpga_qp_arm_cq(conn);

	err = mlx5_fpga_qp_create_qp(conn, attr->tx_size, attr->rx_size);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to create QP: %d\n", err);
		goto err_cq;
	}

	conn->fpga_qpc.state = MLX5_FPGA_QPC_STATE_INIT;
	conn->fpga_qpc.qp_type = qp_type;
	conn->fpga_qpc.st = MLX5_FPGA_QPC_ST_RC;
	conn->fpga_qpc.ether_type = ETH_P_8021Q;
	conn->fpga_qpc.pkey = MLX5_FPGA_PKEY;
	conn->fpga_qpc.remote_qpn = conn->mqp.qpn;
	conn->fpga_qpc.rnr_retry = 7;
	conn->fpga_qpc.retry_count = 7;
	conn->fpga_qpc.vlan_id = 0;
	conn->fpga_qpc.next_rcv_psn = 1;
	conn->fpga_qpc.next_send_psn = 0;

	err = mlx5_fpga_create_qp(fdev->mdev, &conn->fpga_qpc,
				  &conn->fpga_qpn);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to create FPGA RC QP: %d\n", err);
		goto err_qp;
	}

	err = mlx5_fpga_qp_connect(conn);
	if (err)
		goto err_conn;

	mlx5_fpga_dbg(fdev, "FPGA QPN is %u\n", conn->fpga_qpn);
	*connp = conn;
	goto out;

err_conn:
	mlx5_fpga_destroy_qp(conn->fdev->mdev, conn->fpga_qpn);
err_qp:
	mlx5_fpga_qp_destroy_qp(conn);
err_cq:
	mlx5_fpga_qp_destroy_cq(conn);
err_gid:
	mlx5_core_gid_set(fdev->mdev, conn->sgid_index, 0, 0, NULL, NULL,
			  false, 0);
err_rsvd_gid:
	mlx5_core_reserved_gid_del(fdev->mdev, conn->sgid_index);
err:
	kfree(conn);
out:
	return err;
}

static void mlx5_fpga_qp_exit_rq_comp(struct mlx5_fpga_device *fdev,
				      struct mlx5_fpga_conn *conn,
				      struct mlx5_fpga_dma_buf *buf, u8 status)
{
	complete(&conn->exit_rq_comp);
}

static void mlx5_fpga_qp_exit_sq_comp(struct mlx5_fpga_device *fdev,
				      struct mlx5_fpga_conn *conn,
				      struct mlx5_fpga_dma_buf *buf, u8 status)
{
	complete(&conn->exit_sq_comp);
}

void mlx5_fpga_qp_conn_destroy(struct mlx5_fpga_conn *conn)
{
	struct mlx5_fpga_dma_buf exit_sq_buf = {0};
	struct mlx5_fpga_dma_buf exit_rq_buf = {0};
	struct mlx5_fpga_device *fdev = conn->fdev;
	struct mlx5_core_dev *mdev = fdev->mdev;
	int err = 0;

	mlx5_fpga_destroy_qp(conn->fdev->mdev, conn->fpga_qpn);

	init_completion(&conn->exit_rq_comp);
	exit_rq_buf.complete = mlx5_fpga_qp_exit_rq_comp;
	err = mlx5_fpga_qp_post_recv(conn, &exit_rq_buf);
	if (err)
		complete(&conn->exit_rq_comp);

	init_completion(&conn->exit_sq_comp);
	exit_sq_buf.complete = mlx5_fpga_qp_exit_sq_comp;
	err = mlx5_fpga_qp_send(conn, &exit_sq_buf);
	if (err)
		complete(&conn->exit_sq_comp);

	err = mlx5_core_qp_modify(mdev, MLX5_CMD_OP_2ERR_QP, 0, NULL,
				  &conn->mqp);
	if (err) {
		mlx5_fpga_warn(fdev, "qp_modify 2ERR failed: %d\n", err);
	} else {
		wait_for_completion(&conn->exit_rq_comp);
		wait_for_completion(&conn->exit_sq_comp);
	}

	mlx5_fpga_qp_destroy_qp(conn);
	mlx5_fpga_qp_destroy_cq(conn);

	mlx5_fpga_qp_free_recv_bufs(conn);
	mlx5_core_gid_set(conn->fdev->mdev, conn->sgid_index, 0, 0, NULL, NULL,
			  false, 0);
	mlx5_core_reserved_gid_del(conn->fdev->mdev, conn->sgid_index);
	kfree(conn);
}
