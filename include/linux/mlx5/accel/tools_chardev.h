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

#ifndef TOOLS_CHARDEV_H
#define TOOLS_CHARDEV_H

#include <linux/ioctl.h>
#include "accel_sdk.h"

#define MLX_ACCEL_TOOLS_NAME_SUFFIX "_accel_tools"

struct mlx_accel_fpga_query {
	enum mlx_accel_fpga_image  admin_image;
	enum mlx_accel_fpga_image  oper_image;
	enum mlx_accel_fpga_status status;
};

/* Set the memory access type */
#define IOCTL_ACCESS_TYPE    _IOW('m', 0x80, enum mlx_accel_access_type)
/* Load FPGA image from flash */
#define IOCTL_FPGA_LOAD      _IOW('m', 0x81, enum mlx_accel_fpga_image)
/* Reset FPGA hardware logic */
#define IOCTL_FPGA_RESET      _IO('m', 0x82)
/* Select image for next reset or power-on */
#define IOCTL_FPGA_IMAGE_SEL _IOW('m', 0x83, enum mlx_accel_fpga_image)
/* Query selected and running images */
#define IOCTL_FPGA_QUERY     _IOR('m', 0x84, struct mlx_accel_fpga_query *)

#endif /* TOOLS_CHARDEV_H */
