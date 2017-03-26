/*
 * Copyright (c) 2017, Mellanox Technologies. All rights reserved.
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

#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/mlx5/driver.h>

#include "mlx5_core.h"
#include "fpga.h"
#include "core.h"

#define MLX5_FPGA_LOAD_TIMEOUT 20000 /* msec */

static const char *const mlx5_fpga_error_strings[] = {
	"Null Syndrome",
	"Corrupted DDR",
	"Flash Timeout",
	"Internal Link Error",
	"Watchdog HW Failure",
	"I2C Failure",
	"Image Changed",
};

struct mlx5_fpga_error_work {
	struct work_struct work;
	struct mlx5_fpga_device *fdev;
	u8 syndrome;
};

static struct mlx5_fpga_device *mlx5_fpga_device_alloc(void)
{
	struct mlx5_fpga_device *fdev = NULL;

	fdev = kzalloc(sizeof(*fdev), GFP_KERNEL);
	if (!fdev)
		return NULL;

	mutex_init(&fdev->mutex);
	init_completion(&fdev->load_event);
	fdev->state = MLX5_FPGA_STATUS_NONE;
	return fdev;
}

static const char *mlx5_fpga_image_name(enum mlx5_fpga_image image)
{
	switch (image) {
	case MLX5_FPGA_IMAGE_USER:
		return "user";
	case MLX5_FPGA_IMAGE_FACTORY:
		return "factory";
	default:
		return "unknown";
	}
}

static int mlx5_fpga_device_load_wait(struct mlx5_fpga_device *fdev)
{
	struct mlx5_fpga_query query;
	unsigned long timeout;
	int err;

	timeout = jiffies + msecs_to_jiffies(MLX5_FPGA_LOAD_TIMEOUT);

again:
	err = wait_for_completion_timeout(&fdev->load_event, timeout - jiffies);
	if (err == 0) {
		mlx5_fpga_err(fdev, "Timeout waiting for FPGA load\n");
		return -ETIMEDOUT;
	}

	err = mlx5_fpga_query(fdev->mdev, &query);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to query status: %d\n", err);
		return err;
	}

	fdev->last_admin_image = query.admin_image;
	fdev->last_oper_image = query.oper_image;

	mlx5_fpga_dbg(fdev, "Status %u; Admin image %u; Oper image %u\n",
		      query.status, query.admin_image, query.oper_image);

	switch (query.status) {
	case MLX5_FPGA_STATUS_SUCCESS:
		err = mlx5_fpga_caps(fdev->mdev,
				     fdev->mdev->caps.hca_cur[MLX5_CAP_FPGA]);
		if (err)
			return err;

		mlx5_fpga_info(fdev, "device %u; %s image, version %u\n",
			       MLX5_CAP_FPGA(fdev->mdev, fpga_device),
			       mlx5_fpga_image_name(fdev->last_oper_image),
			       MLX5_CAP_FPGA(fdev->mdev, image_version));
		break;

	case MLX5_FPGA_STATUS_IN_PROGRESS:
		mlx5_fpga_dbg(fdev, "Waiting for load, again\n");
		goto again;

	case MLX5_FPGA_STATUS_FAILURE:
		mlx5_fpga_info(fdev, "%s image failed to load\n",
			       mlx5_fpga_image_name(fdev->last_oper_image));
		err = -EIO;
		break;

	default:
		mlx5_fpga_err(fdev, "Unknown status %u of %s image\n",
			      query.status,
			      mlx5_fpga_image_name(fdev->last_oper_image));
		err = -EIO;
		break;
	}
	return err;
}

int mlx5_fpga_device_start(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;
	unsigned int max_num_qps;
	int err;

	if (!fdev)
		return 0;

	fdev->state = MLX5_FPGA_STATUS_IN_PROGRESS;
	err = mlx5_fpga_device_load_wait(fdev);
	if (err) {
		fdev->state = MLX5_FPGA_STATUS_FAILURE;
		return err;
	}

	mutex_lock(&fdev->mutex);
	max_num_qps = MLX5_CAP_FPGA(mdev, shell_caps.max_num_qps);
	mlx5_core_reserve_gids(mdev, max_num_qps);
	fdev->state = MLX5_FPGA_STATUS_SUCCESS;
	mutex_unlock(&fdev->mutex);
	return err;
}

int mlx5_fpga_device_init(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = NULL;
	int err;

	if (!MLX5_CAP_GEN(mdev, fpga)) {
		mlx5_core_dbg(mdev, "FPGA device not present\n");
		return 0;
	}

	mlx5_core_dbg(mdev, "Initializing FPGA\n");

	fdev = mlx5_fpga_device_alloc();
	if (!fdev)
		return -ENOMEM;

	fdev->mdev = mdev;
	mdev->fpga = fdev;

	mutex_lock(&fdev->mutex);
	mutex_unlock(&fdev->mutex);
	return err;
}

void mlx5_fpga_device_stop(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!fdev)
		return;

	mutex_lock(&fdev->mutex);
	if (fdev->state != MLX5_FPGA_STATUS_SUCCESS)
		goto out_unlock;

	mlx5_core_reserve_gids(mdev, 0);
	fdev->state = MLX5_FPGA_STATUS_NONE;

out_unlock:
	mutex_unlock(&fdev->mutex);
}

void mlx5_fpga_device_deinit(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!fdev)
		return;

	mlx5_fpga_device_stop(mdev);

	fdev->mdev = NULL;
	mdev->fpga = NULL;
	kfree(fdev);
}

static const char *mlx5_fpga_syndrome_to_string(u8 syndrome)
{
	if (syndrome < ARRAY_SIZE(mlx5_fpga_error_strings))
		return mlx5_fpga_error_strings[syndrome];
	return "Unknown";
}

static void mlx5_fpga_handle_error(struct work_struct *work)
{
	struct mlx5_fpga_error_work *err_work;
	struct mlx5_fpga_device *fdev;
	bool disable = false;
	u8 syndrome;

	err_work = container_of(work, struct mlx5_fpga_error_work, work);
	fdev = err_work->fdev;
	syndrome = err_work->syndrome;
	kfree(err_work);

	mutex_lock(&fdev->mutex);
	switch (fdev->state) {
	case MLX5_FPGA_STATUS_SUCCESS:
		mlx5_fpga_err(fdev, "Error %u: %s\n",
			      syndrome, mlx5_fpga_syndrome_to_string(syndrome));
		mlx5_fpga_device_stop(fdev->mdev);
		fdev->state = MLX5_FPGA_STATUS_FAILURE;
		disable = true;
		break;
	case MLX5_FPGA_STATUS_IN_PROGRESS:
		complete(&fdev->load_event);
		break;
	default:
		mlx5_fpga_warn(fdev, "Unexpected error %u: %s\n",
			       syndrome,
			       mlx5_fpga_syndrome_to_string(syndrome));
	}
	mutex_unlock(&fdev->mutex);
	if (disable)
		mlx5_disable_device(fdev->mdev);
}

void mlx5_fpga_event(struct mlx5_core_dev *mdev, u8 event, void *data)
{
	struct mlx5_fpga_error_work *work;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return;

	work->fdev = mdev->fpga;

	switch (event) {
	case MLX5_EVENT_TYPE_FPGA_ERROR:
		INIT_WORK(&work->work, mlx5_fpga_handle_error);
		work->syndrome = MLX5_GET(fpga_error_event, data, syndrome);
		break;
		break;
	default:
		mlx5_fpga_warn(mdev->fpga, "Unexpected event %u\n", event);
		kfree(work);
		return;
	}
	schedule_work(&work->work);
}
