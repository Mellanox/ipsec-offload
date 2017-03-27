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

#ifndef MLX5_FPGA_SDK_H
#define MLX5_FPGA_SDK_H

#include <rdma/ib_verbs.h>
#include <linux/mlx5/driver.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/dma-direction.h>
#include <linux/kobject.h>

#include "fpga.h"

#define MLX5_FPGA_CLIENT_NAME_MAX 64

struct mlx5_fpga_conn;
struct mlx5_fpga_device;

struct mlx5_fpga_client {
	/* Informs the client that a core device was created.
	 * The device is not yet operational at this stage
	 * This callback is optional
	 */
	void (*create)(struct mlx5_fpga_device *);
	/* Informs the client that a core device is ready and operational.
	 * @param vid SBU Vendor ID
	 * @param pid SBU Product ID
	 * Any SBU-specific initialization should happen at this stage
	 * @return 0 on success, nonzero error value otherwise
	 */
	int  (*add)(struct mlx5_fpga_device *, u16 vid, u16 pid);
	/* Informs the client that a core device is not operational anymore.
	 * SBU-specific cleanup should happen at this stage
	 * This callback is called once for every successful call to add()
	 */
	void (*remove)(struct mlx5_fpga_device *);
	/* Informs the client that a core device is being destroyed.
	 * The device is not operational at this stage
	 */
	void (*destroy)(struct mlx5_fpga_device *);

	char name[MLX5_FPGA_CLIENT_NAME_MAX];

	struct list_head list;
};

struct mlx5_fpga_dma_entry {
	void *data;
	unsigned int size;
	/* Private member */
	dma_addr_t dma_addr;
};

struct mlx5_fpga_dma_buf {
	enum dma_data_direction dma_dir;
	struct mlx5_fpga_dma_entry sg[2];
	void (*complete)(struct mlx5_fpga_device *fdev,
			 struct mlx5_fpga_conn *conn,
			 struct mlx5_fpga_dma_buf *buf, u8 status);
};

struct mlx5_fpga_conn_attr {
	unsigned int tx_size;
	unsigned int rx_size;
	void (*recv_cb)(void *cb_arg, struct mlx5_fpga_dma_buf *buf);
	void *cb_arg;
};

void mlx5_fpga_client_register(struct mlx5_fpga_client *client);
void mlx5_fpga_client_unregister(struct mlx5_fpga_client *client);
int mlx5_fpga_device_reload(struct mlx5_fpga_device *fdev,
			    enum mlx5_fpga_image image);
int mlx5_fpga_flash_select(struct mlx5_fpga_device *fdev,
			   enum mlx5_fpga_image image);

int mlx5_fpga_sbu_conn_init(struct mlx5_fpga_device *fdev,
			    struct mlx5_fpga_conn_attr *attr);
int mlx5_fpga_sbu_conn_deinit(struct mlx5_fpga_device *fdev);
int mlx5_fpga_sbu_conn_sendmsg(struct mlx5_fpga_device *fdev,
			       struct mlx5_fpga_dma_buf *buf);

u64 mlx5_fpga_ddr_size_get(struct mlx5_fpga_device *dev);
u64 mlx5_fpga_ddr_base_get(struct mlx5_fpga_device *dev);
int mlx5_fpga_mem_read(struct mlx5_fpga_device *dev, size_t size, u64 addr,
		       void *buf, enum mlx5_fpga_access_type access_type);
int mlx5_fpga_mem_write(struct mlx5_fpga_device *dev, size_t size, u64 addr,
			void *buf, enum mlx5_fpga_access_type access_type);

void mlx5_fpga_client_data_set(struct mlx5_fpga_device *fdev,
			       struct mlx5_fpga_client *client,
			       void *data);
void *mlx5_fpga_client_data_get(struct mlx5_fpga_device *fdev,
				struct mlx5_fpga_client *client);

void mlx5_fpga_device_query(struct mlx5_fpga_device *fdev,
			    struct mlx5_fpga_query *query);
struct kobject *mlx5_fpga_kobj(struct mlx5_fpga_device *fdev);
int mlx5_fpga_get_sbu_caps(struct mlx5_fpga_device *dev, int size, void *buf);
struct device *mlx5_fpga_dev(struct mlx5_fpga_device *dev);

#endif /* MLX5_FPGA_SDK_H */
