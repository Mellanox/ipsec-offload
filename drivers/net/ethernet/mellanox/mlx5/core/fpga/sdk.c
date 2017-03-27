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

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/completion.h>
#include <rdma/ib_verbs.h>
#include <linux/mlx5/device.h>

#include "core.h"
#include "qp.h"
#include "xfer.h"
#include "sdk.h"
#include "mlx5_core.h"

struct mem_transfer {
	struct mlx5_fpga_transaction t;
	struct completion comp;
	u8 status;
};

int mlx5_fpga_sbu_conn_init(struct mlx5_fpga_device *fdev,
			    struct mlx5_fpga_conn_attr *attr)
{
	mlx5_fpga_dbg(fdev, "SBU conn init\n");

	if (fdev->sbu_conn) {
		mlx5_fpga_warn(fdev, "SBU connenction already initialized\n");
		return -EEXIST;
	}

	return mlx5_fpga_qp_conn_create(fdev, attr,
					MLX5_FPGA_QPC_QP_TYPE_SANDBOX_QP,
					&fdev->sbu_conn);
}
EXPORT_SYMBOL(mlx5_fpga_sbu_conn_init);

int mlx5_fpga_sbu_conn_deinit(struct mlx5_fpga_device *fdev)
{
	mlx5_fpga_dbg(fdev, "SBU conn deinit\n");

	if (!fdev->sbu_conn) {
		mlx5_fpga_warn(fdev, "SBU connenction not initialized\n");
		return -ENOENT;
	}

	mlx5_fpga_qp_conn_destroy(fdev->sbu_conn);
	return 0;
}
EXPORT_SYMBOL(mlx5_fpga_sbu_conn_deinit);

int mlx5_fpga_sbu_conn_sendmsg(struct mlx5_fpga_device *fdev,
			       struct mlx5_fpga_dma_buf *buf)
{
	if (!fdev->sbu_conn) {
		mlx5_fpga_warn(fdev, "SBU connenction not initialized\n");
		return -ENOENT;
	}

	return mlx5_fpga_qp_send(fdev->sbu_conn, buf);
}
EXPORT_SYMBOL(mlx5_fpga_sbu_conn_sendmsg);

u64 mlx5_fpga_ddr_size_get(struct mlx5_fpga_device *fdev)
{
	return (u64)MLX5_CAP_FPGA(fdev->mdev, fpga_ddr_size) << 10;
}
EXPORT_SYMBOL(mlx5_fpga_ddr_size_get);

u64 mlx5_fpga_ddr_base_get(struct mlx5_fpga_device *fdev)
{
	return MLX5_CAP64_FPGA(fdev->mdev, fpga_ddr_start_addr);
}
EXPORT_SYMBOL(mlx5_fpga_ddr_base_get);

static void mem_complete(const struct mlx5_fpga_transaction *complete,
			 u8 status)
{
	struct mem_transfer *xfer;

	mlx5_fpga_dbg(complete->conn->fdev,
		      "transaction %p complete status %u", complete, status);

	xfer = container_of(complete, struct mem_transfer, t);
	xfer->status = status;
	complete_all(&xfer->comp);
}

static int mem_transaction(struct mlx5_fpga_device *fdev, size_t size, u64 addr,
			   void *buf, enum mlx5_fpga_direction direction)
{
	int ret;
	struct mem_transfer xfer;

	if (!fdev->shell_conn) {
		ret = -ENOTCONN;
		goto out;
	}

	xfer.t.data = buf;
	xfer.t.size = size;
	xfer.t.addr = addr;
	xfer.t.conn = fdev->shell_conn;
	xfer.t.direction = direction;
	xfer.t.complete = mem_complete;
	init_completion(&xfer.comp);
	ret = mlx5_fpga_xfer_exec(&xfer.t);
	if (ret) {
		mlx5_fpga_dbg(fdev, "Transfer execution failed: %d\n", ret);
		goto out;
	}
	wait_for_completion(&xfer.comp);
	if (xfer.status != 0)
		ret = -EIO;

out:
	return ret;
}

static int mem_read_i2c(struct mlx5_fpga_device *fdev, size_t size, u64 addr,
			u8 *buf)
{
	size_t max_size = MLX5_FPGA_ACCESS_REG_SIZE_MAX;
	size_t bytes_done = 0;
	u8 actual_size;
	int err;

	if (!fdev->mdev)
		return -ENOTCONN;

	while (bytes_done < size) {
		actual_size = min(max_size, (size - bytes_done));

		err = mlx5_fpga_access_reg(fdev->mdev, actual_size,
					   addr + bytes_done,
					   buf + bytes_done, false);
		if (err) {
			mlx5_fpga_err(fdev, "Failed to read over I2C: %d\n",
				      err);
			break;
		}

		bytes_done += actual_size;
	}

	return err;
}

static int mem_write_i2c(struct mlx5_fpga_device *fdev, size_t size, u64 addr,
			 u8 *buf)
{
	size_t max_size = MLX5_FPGA_ACCESS_REG_SIZE_MAX;
	size_t bytes_done = 0;
	u8 actual_size;
	int err;

	if (!fdev->mdev)
		return -ENOTCONN;

	while (bytes_done < size) {
		actual_size = min(max_size, (size - bytes_done));

		err = mlx5_fpga_access_reg(fdev->mdev, actual_size,
					   addr + bytes_done,
					   buf + bytes_done, true);
		if (err) {
			mlx5_fpga_err(fdev, "Failed to write FPGA crspace\n");
			break;
		}

		bytes_done += actual_size;
	}

	return err;
}

int mlx5_fpga_mem_read(struct mlx5_fpga_device *fdev, size_t size, u64 addr,
		       void *buf, enum mlx5_fpga_access_type access_type)
{
	int ret;

	if (access_type == MLX5_FPGA_ACCESS_TYPE_DONTCARE)
		access_type = fdev->shell_conn ? MLX5_FPGA_ACCESS_TYPE_RDMA :
						 MLX5_FPGA_ACCESS_TYPE_I2C;

	mlx5_fpga_dbg(fdev, "Reading %lu bytes at 0x%llx over %s",
		      size, addr, access_type ? "RDMA" : "I2C");

	switch (access_type) {
	case MLX5_FPGA_ACCESS_TYPE_RDMA:
		ret = mem_transaction(fdev, size, addr, buf, MLX5_FPGA_READ);
		if (ret)
			return ret;
		break;
	case MLX5_FPGA_ACCESS_TYPE_I2C:
		ret = mem_read_i2c(fdev, size, addr, buf);
		if (ret)
			return ret;
		break;
	default:
		mlx5_fpga_warn(fdev, "Unexpected read access_type %u\n",
			       access_type);
		return -EACCES;
	}

	return size;
}
EXPORT_SYMBOL(mlx5_fpga_mem_read);

int mlx5_fpga_mem_write(struct mlx5_fpga_device *fdev, size_t size, u64 addr,
			void *buf, enum mlx5_fpga_access_type access_type)
{
	int ret;

	if (access_type == MLX5_FPGA_ACCESS_TYPE_DONTCARE)
		access_type = fdev->shell_conn ? MLX5_FPGA_ACCESS_TYPE_RDMA :
						 MLX5_FPGA_ACCESS_TYPE_I2C;

	mlx5_fpga_dbg(fdev, "Writing %lu bytes at 0x%llx over %s",
		      size, addr, access_type ? "RDMA" : "I2C");

	switch (access_type) {
	case MLX5_FPGA_ACCESS_TYPE_RDMA:
		ret = mem_transaction(fdev, size, addr, buf, MLX5_FPGA_WRITE);
		if (ret)
			return ret;
		break;
	case MLX5_FPGA_ACCESS_TYPE_I2C:
		ret = mem_write_i2c(fdev, size, addr, buf);
		if (ret)
			return ret;
		break;
	default:
		mlx5_fpga_warn(fdev, "Unexpected write access_type %u\n",
			       access_type);
		return -EACCES;
	}

	return size;
}
EXPORT_SYMBOL(mlx5_fpga_mem_write);

void mlx5_fpga_client_data_set(struct mlx5_fpga_device *fdev,
			       struct mlx5_fpga_client *client, void *data)
{
	struct mlx5_fpga_client_data *context;

	list_for_each_entry(context, &fdev->client_data_list, list) {
		if (context->client != client)
			continue;
		context->data = data;
		return;
	}

	mlx5_fpga_warn(fdev, "No client context found for %s\n", client->name);
}
EXPORT_SYMBOL(mlx5_fpga_client_data_set);

void *mlx5_fpga_client_data_get(struct mlx5_fpga_device *fdev,
				struct mlx5_fpga_client *client)
{
	struct mlx5_fpga_client_data *context;
	void *ret = NULL;

	list_for_each_entry(context, &fdev->client_data_list, list) {
		if (context->client != client)
			continue;
		ret = context->data;
		goto out;
	}
	mlx5_fpga_warn(fdev, "No client context found for %s\n", client->name);

out:
	return ret;
}
EXPORT_SYMBOL(mlx5_fpga_client_data_get);

struct kobject *mlx5_fpga_kobj(struct mlx5_fpga_device *fdev)
{
	return fdev->class_kobj;
}
EXPORT_SYMBOL(mlx5_fpga_kobj);

void mlx5_fpga_device_query(struct mlx5_fpga_device *fdev,
			    struct mlx5_fpga_query *query)
{
	query->status = fdev->state;
	query->admin_image = fdev->last_admin_image;
	query->oper_image = fdev->last_oper_image;
}
EXPORT_SYMBOL(mlx5_fpga_device_query);

int mlx5_fpga_device_reload(struct mlx5_fpga_device *fdev,
			    enum mlx5_fpga_image image)
{
	int err;

	mutex_lock(&fdev->mutex);
	switch (fdev->state) {
	case MLX5_FPGA_STATUS_NONE:
		err = -ENODEV;
		goto unlock;
	case MLX5_FPGA_STATUS_IN_PROGRESS:
		err = -EBUSY;
		goto unlock;
	case MLX5_FPGA_STATUS_SUCCESS:
		mlx5_disable_device(fdev->mdev);
		break;
	case MLX5_FPGA_STATUS_FAILURE:
		break;
	}
	if (image <= MLX5_FPGA_IMAGE_MAX) {
		err = mlx5_fpga_load(fdev->mdev, image);
		if (err)
			mlx5_fpga_err(fdev, "Failed to request load: %d\n",
				      err);
	} else {
		err = mlx5_fpga_ctrl_op(fdev->mdev, MLX5_FPGA_CTRL_OP_RESET);
		if (err)
			mlx5_fpga_err(fdev, "Failed to request reset: %d\n",
				      err);
	}
	fdev->state = MLX5_FPGA_STATUS_IN_PROGRESS;
unlock:
	mutex_unlock(&fdev->mutex);
	return err;
}
EXPORT_SYMBOL(mlx5_fpga_device_reload);

int mlx5_fpga_flash_select(struct mlx5_fpga_device *fdev,
			   enum mlx5_fpga_image image)
{
	int err;

	mutex_lock(&fdev->mutex);
	switch (fdev->state) {
	case MLX5_FPGA_STATUS_NONE:
		err = -ENODEV;
		goto unlock;
	case MLX5_FPGA_STATUS_IN_PROGRESS:
	case MLX5_FPGA_STATUS_SUCCESS:
	case MLX5_FPGA_STATUS_FAILURE:
		break;
	}

	err = mlx5_fpga_image_select(fdev->mdev, image);
	if (err)
		mlx5_fpga_err(fdev, "Failed to select flash image: %d\n", err);
unlock:
	mutex_unlock(&fdev->mutex);
	return err;
}
EXPORT_SYMBOL(mlx5_fpga_flash_select);

int mlx5_fpga_get_sbu_caps(struct mlx5_fpga_device *fdev, int size, void *buf)
{
	return mlx5_fpga_sbu_caps(fdev->mdev, buf, size);
}
EXPORT_SYMBOL(mlx5_fpga_get_sbu_caps);

struct device *mlx5_fpga_dev(struct mlx5_fpga_device *fdev)
{
	return &fdev->mdev->pdev->dev;
}
EXPORT_SYMBOL(mlx5_fpga_dev);
