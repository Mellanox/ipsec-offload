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

#include "tools.h"
#include <linux/module.h>
#include "tools_char.h"

MODULE_AUTHOR("Ilan Tayari <ilant@mellanox.com>");
MODULE_DESCRIPTION("Mellanox FPGA Accelerator Tools Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");

static int
mlx_accel_tools_add_one(struct mlx_accel_core_device *accel_device);
static void
mlx_accel_tools_remove_one(struct mlx_accel_core_device *accel_device);

static struct mlx_accel_core_client mlx_accel_tools_client = {
	.name   = MLX_ACCEL_TOOLS_DRIVER_NAME,
	.add    = mlx_accel_tools_add_one,
	.remove = mlx_accel_tools_remove_one,
};

static int mlx_accel_tools_add_one(struct mlx_accel_core_device *accel_device)
{
	struct mlx_accel_tools_dev *dev = NULL;
	int ret = 0;

	pr_debug("mlx_accel_tools_add_one called for %s\n", accel_device->name);

	dev = mlx_accel_tools_alloc(accel_device);
	if (!dev) {
		ret = -ENOMEM;
		goto out;
	}

	mlx_accel_core_client_data_set(accel_device,
				       &mlx_accel_tools_client, dev);

out:
	return ret;
}

static void
mlx_accel_tools_remove_one(struct mlx_accel_core_device *accel_device)
{
	struct mlx_accel_tools_dev *dev;

	pr_debug("mlx_accel_tools_remove_one called for %s\n",
		 accel_device->name);

	dev = mlx_accel_core_client_data_get(accel_device,
					     &mlx_accel_tools_client);
	if (dev)
		mlx_accel_tools_free(dev);
}

static int __init mlx_accel_tools_init(void)
{
	int ret = mlx_accel_tools_char_init();

	if (ret)
		return ret;
	mlx_accel_core_client_register(&mlx_accel_tools_client);
	/* TODO: Handle errors */
	return 0;
}

static void __exit mlx_accel_tools_exit(void)
{
	mlx_accel_core_client_unregister(&mlx_accel_tools_client);
	mlx_accel_tools_char_deinit();
}

module_init(mlx_accel_tools_init);
module_exit(mlx_accel_tools_exit);
