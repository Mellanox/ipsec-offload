/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
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

#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>

#include "sysfs.h"
#include "sdk.h"
#include "core.h"
#include "qp.h"

struct fpga_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_fpga_device *, char *);
	ssize_t (*store)(struct mlx5_fpga_device *, const char *, size_t);
};

#define FPGA_ATTR_RW(_name) \
static struct fpga_attribute fpga_attr_##_name = __ATTR_RW(_name)

#define FPGA_ATTR_RO(_name) \
static struct fpga_attribute fpga_attr_##_name = __ATTR_RO(_name)

#define FPGA_ATTR_WO(_name) \
static struct fpga_attribute fpga_attr_##_name = __ATTR_WO(_name)

static ssize_t fpga_caps_show(struct mlx5_fpga_device *fdev, char *buf)
{
	struct mlx5_core_dev *mdev = fdev->mdev;

	return scnprintf(buf, PAGE_SIZE,
			 "FPGA ID: 0x%02x\n"
			 "FPGA Device: 0x%06x\n"
			 "Register File Version: 0x%08x\n"
			 "FPGA Ctrl Modify: %u\n"
			 "Access Reg Query: %u\n"
			 "Access Reg Modify: %u\n"
			 "Image Version: 0x%08x\n"
			 "Image Date: 0x%08x\n"
			 "Image Time: 0x%08x\n"
			 "Shell Version: 0x%08x\n"
			 "IEEE Vendor ID: 0x%06x\n"
			 "SBU Product Version: 0x%04x\n"
			 "SBU Product ID: 0x%04x\n"
			 "SBU Basic Caps: 0x%08x\n"
			 "SBU Extended Caps Len: 0x%04x\n"
			 "SBU Extended Caps Address: 0x%llx\n"
			 "FPGA DDR Start Address: 0x%llx\n"
			 "FPGA CrSpace Start Address: 0x%llx\n"
			 "FPGA DDR Size: 0x%llx\n"
			 "FPGA CrSpace Size: 0x%llx\n",
			 MLX5_CAP_FPGA(mdev, fpga_id),
			 MLX5_CAP_FPGA(mdev, fpga_device),
			 MLX5_CAP_FPGA(mdev, register_file_ver),
			 MLX5_CAP_FPGA(mdev, fpga_ctrl_modify),
			 MLX5_CAP_FPGA(mdev, access_reg_query_mode),
			 MLX5_CAP_FPGA(mdev, access_reg_modify_mode),
			 MLX5_CAP_FPGA(mdev, image_version),
			 MLX5_CAP_FPGA(mdev, image_date),
			 MLX5_CAP_FPGA(mdev, image_time),
			 MLX5_CAP_FPGA(mdev, shell_version),
			 MLX5_CAP_FPGA(mdev, ieee_vendor_id),
			 MLX5_CAP_FPGA(mdev, sandbox_product_version),
			 MLX5_CAP_FPGA(mdev, sandbox_product_id),
			 MLX5_CAP_FPGA(mdev, sandbox_basic_caps),
			 MLX5_CAP_FPGA(mdev, sandbox_extended_caps_len),
			 MLX5_CAP64_FPGA(mdev, sandbox_extended_caps_addr),
			 MLX5_CAP64_FPGA(mdev, fpga_ddr_start_addr),
			 MLX5_CAP64_FPGA(mdev, fpga_cr_space_start_addr),
			 1024ULL * MLX5_CAP_FPGA(mdev, fpga_ddr_size),
			 1024ULL * MLX5_CAP_FPGA(mdev, fpga_cr_space_size));
}

static ssize_t shell_caps_show(struct mlx5_fpga_device *fdev, char *buf)
{
	struct mlx5_core_dev *mdev = fdev->mdev;

	return scnprintf(buf, PAGE_SIZE,
			 "Maximum Number of QPs: %u\n"
			 "Total Receive Credits: %u\n"
			 "QP Type: %u\n"
			 "RAE: %u\n"
			 "RWE: %u\n"
			 "RRE: %u\n"
			 "DC: %u\n"
			 "UD: %u\n"
			 "UC: %u\n"
			 "RC: %u\n"
			 "DDR Size: %u GB\n"
			 "QP Message Size: 0x%08x\n",
			 MLX5_CAP_FPGA(mdev, shell_caps.max_num_qps),
			 MLX5_CAP_FPGA(mdev, shell_caps.total_rcv_credits),
			 MLX5_CAP_FPGA(mdev, shell_caps.qp_type),
			 MLX5_CAP_FPGA(mdev, shell_caps.rae),
			 MLX5_CAP_FPGA(mdev, shell_caps.rwe),
			 MLX5_CAP_FPGA(mdev, shell_caps.rre),
			 MLX5_CAP_FPGA(mdev, shell_caps.dc),
			 MLX5_CAP_FPGA(mdev, shell_caps.ud),
			 MLX5_CAP_FPGA(mdev, shell_caps.uc),
			 MLX5_CAP_FPGA(mdev, shell_caps.rc),
			 1 << MLX5_CAP_FPGA(mdev, shell_caps.log_ddr_size),
			 MLX5_CAP_FPGA(mdev,
				       shell_caps.max_fpga_qp_msg_size));
}

static ssize_t shell_counters_show(struct mlx5_fpga_device *fdev, char *buf)
{
	struct mlx5_fpga_shell_counters data;
	int ret = mlx5_fpga_shell_counters(fdev->mdev, false, &data);

	if (ret)
		return -EIO;
	return scnprintf(buf, PAGE_SIZE,
			 "DDR Read Requests: %llu\n"
			 "DDR Write Requests: %llu\n"
			 "DDR Read Bytes: %llu\n"
			 "DDR Write Bytes: %llu\n",
			 data.ddr_read_requests,
			 data.ddr_write_requests,
			 data.ddr_read_bytes,
			 data.ddr_write_bytes);
}

static ssize_t shell_counters_store(struct mlx5_fpga_device *fdev,
				    const char *buf, size_t size)
{
	int ret = mlx5_fpga_shell_counters(fdev->mdev, true, NULL);

	if (ret)
		return -EIO;
	return size;
}

ssize_t mlx5_fpga_counters_sysfs_show(struct mlx5_fpga_conn *conn, char *buf)
{
	struct mlx5_fpga_qp_counters data;
	int ret = mlx5_fpga_query_qp_counters(conn->fdev->mdev, conn->fpga_qpn,
					      false, &data);

	if (ret)
		return -EIO;
	return scnprintf(buf, PAGE_SIZE,
			 "RX Ack Packets: %llu\n"
			 "RX Send Packets: %llu\n"
			 "TX Ack Packets: %llu\n"
			 "TX Send Packets: %llu\n"
			 "RX Total Drop: %llu\n",
			 data.rx_ack_packets,
			 data.rx_send_packets,
			 data.tx_ack_packets,
			 data.tx_send_packets,
			 data.rx_total_drop);
}

ssize_t mlx5_fpga_counters_sysfs_store(struct mlx5_fpga_conn *conn,
				       const char *buf, size_t size)
{
	int ret = mlx5_fpga_query_qp_counters(conn->fdev->mdev, conn->fpga_qpn,
					      true, NULL);

	if (ret)
		return -EIO;
	return size;
}

static ssize_t shell_conn_counters_show(struct mlx5_fpga_device *fdev,
					char *buf)
{
	return mlx5_fpga_counters_sysfs_show(fdev->shell_conn, buf);
}

static ssize_t shell_conn_counters_store(struct mlx5_fpga_device *fdev,
					 const char *buf,
					 size_t size)
{
	return mlx5_fpga_counters_sysfs_store(fdev->shell_conn, buf, size);
}

static ssize_t sbu_conn_counters_show(struct mlx5_fpga_device *fdev,
				      char *buf)
{
	if (fdev->sbu_conn)
		return mlx5_fpga_counters_sysfs_show(fdev->sbu_conn, buf);
	return 0;
}

static ssize_t sbu_conn_counters_store(struct mlx5_fpga_device *fdev,
				       const char *buf,
				       size_t size)
{
	if (fdev->sbu_conn)
		return mlx5_fpga_counters_sysfs_store(fdev->sbu_conn, buf,
						      size);
	return 0;
}

static ssize_t fpga_attr_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct fpga_attribute *fpga_attr;
	struct mlx5_fpga_device *fdev;

	fpga_attr = container_of(attr, struct fpga_attribute, attr);
	fdev = container_of(kobj, struct mlx5_fpga_device, core_kobj);

	if (!fpga_attr->show)
		return -EIO;

	return fpga_attr->show(fdev, buf);
}

static ssize_t fpga_attr_store(struct kobject *kobj, struct attribute *attr,
			       const char *buf, size_t size)
{
	struct fpga_attribute *fpga_attr;
	struct mlx5_fpga_device *fdev;

	fpga_attr = container_of(attr, struct fpga_attribute, attr);
	fdev = container_of(kobj, struct mlx5_fpga_device, core_kobj);

	if (!fpga_attr->store)
		return -EIO;

	return fpga_attr->store(fdev, buf, size);
}

static const struct sysfs_ops fpga_sysfs_ops = {
	.show = fpga_attr_show,
	.store = fpga_attr_store,
};

static void fpga_release(struct kobject *kobj)
{
}

FPGA_ATTR_RO(fpga_caps);
FPGA_ATTR_RO(shell_caps);
FPGA_ATTR_RW(shell_counters);
FPGA_ATTR_RW(shell_conn_counters);
FPGA_ATTR_RW(sbu_conn_counters);

static struct attribute *fpga_default_attrs[] = {
	&fpga_attr_fpga_caps.attr,
	&fpga_attr_shell_caps.attr,
	&fpga_attr_shell_counters.attr,
	&fpga_attr_shell_conn_counters.attr,
	&fpga_attr_sbu_conn_counters.attr,
	NULL
};

static struct kobj_type fpga_type = {
	.release       = fpga_release,
	.sysfs_ops     = &fpga_sysfs_ops,
	.default_attrs = fpga_default_attrs
};

int mlx5_fpga_device_register_sysfs(struct mlx5_fpga_device *fdev)
{
	int ret;
	struct kobject *kobj;

	kobj = kobject_create_and_add("mlx5_fpga",
				      &fdev->mdev->pdev->dev.kobj);
	if (!kobj) {
		ret = -ENOMEM;
		goto out;
	}

	fdev->class_kobj = kobj;
	ret = kobject_init_and_add(&fdev->core_kobj, &fpga_type,
				   fdev->class_kobj, "core");
	if (ret)
		goto err_class_kobj;

	goto out;

err_class_kobj:
	kobject_put(fdev->class_kobj);
	fdev->class_kobj = NULL;
out:
	return ret;
}

void mlx5_fpga_device_unregister_sysfs(struct mlx5_fpga_device *fdev)
{
	kobject_put(&fdev->core_kobj);
	kobject_put(fdev->class_kobj);
}
