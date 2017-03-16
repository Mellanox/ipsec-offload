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

#include "en.h"
#include "fpga/sdk.h"
#include "en_ipsec/ipsec.h"

struct mlx_ipsec_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_ipsec_dev *dev, char *buf);
	ssize_t (*store)(struct mlx5_ipsec_dev *dev, const char *buf,
			 size_t count);
};

#define MLX_IPSEC_ATTR_RW(_name) \
struct mlx_ipsec_attribute mlx_ipsec_attr_##_name = __ATTR_RW(_name)

#define MLX_IPSEC_ATTR_RO(_name) \
struct mlx_ipsec_attribute mlx_ipsec_attr_##_name = __ATTR_RO(_name)

#define MLX_IPSEC_ATTR_WO(_name) \
struct mlx_ipsec_attribute mlx_ipsec_attr_##_name = __ATTR_WO(_name)

static ssize_t mlx_ipsec_attr_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	struct mlx5_ipsec_dev *dev;
	struct mlx_ipsec_attribute *mlx_ipsec_attr;
	ssize_t ret = -EIO;

	dev = container_of(kobj, struct mlx5_ipsec_dev, kobj);
	mlx_ipsec_attr = container_of(attr, struct mlx_ipsec_attribute, attr);
	if (mlx_ipsec_attr->show)
		ret = mlx_ipsec_attr->show(dev, buf);

	return ret;
}

static ssize_t mlx_ipsec_attr_store(struct kobject *kobj,
				    struct attribute *attr, const char *buf,
				    size_t count)
{
	struct mlx5_ipsec_dev *dev;
	struct mlx_ipsec_attribute *mlx_ipsec_attr;
	ssize_t ret = -EIO;

	dev = container_of(kobj, struct mlx5_ipsec_dev, kobj);
	mlx_ipsec_attr = container_of(attr, struct mlx_ipsec_attribute, attr);
	if (mlx_ipsec_attr->store)
		ret = mlx_ipsec_attr->store(dev, buf, count);

	return ret;
}

#define MLX5_IPSEC_CAP(caps, cap) MLX5_GET(ipsec_extended_cap, caps, cap)
#define MLX5_IPSEC_CAP64(c, cap) ((u64)MLX5_IPSEC_CAP(c, cap ## _low) + \
				  ((u64)MLX5_IPSEC_CAP(c, cap ## _high) << 32))

static ssize_t caps_show(struct mlx5_ipsec_dev *dev, char *buf)
{
	u32 *caps = dev->ipsec_caps;

	return scnprintf(buf, PAGE_SIZE,
			"UDP Encapsulations: %08x\n"
			"IPv4 Fragment: %u\n"
			"IPv6: %u\n"
			"Extended Sequence Numbers: %u\n"
			"Large Segment Offload: %u\n"
			"Combined Transport+Tunnel Mode: %u\n"
			"Tunnel Mode: %u\n"
			"Transport Mode: %u\n"
			"Combined AH+ESP: %u\n"
			"ESP: %u\n"
			"AH: %u\n"
			"IPv4 Options: %u\n"
			"Authentication algorithm AES_GCM_128: %u\n"
			"Authentication algorithm AES_GCM_256: %u\n"
			"Encryption algorithm AES_GCM_128: %u\n"
			"Encryption algorithm AES_GCM_256: %u\n"
			"Maximum SAs: %u\n"
			"IPSec Counters: %u\n"
			"IPSec Counters Start Address: 0x%llx\n",
			MLX5_IPSEC_CAP(caps, encapsulation),
			MLX5_IPSEC_CAP(caps, ipv4_fragment),
			MLX5_IPSEC_CAP(caps, ipv6),
			MLX5_IPSEC_CAP(caps, esn),
			MLX5_IPSEC_CAP(caps, lso),
			MLX5_IPSEC_CAP(caps, transport_and_tunnel_mode),
			MLX5_IPSEC_CAP(caps, tunnel_mode),
			MLX5_IPSEC_CAP(caps, transport_mode),
			MLX5_IPSEC_CAP(caps, ah_esp),
			MLX5_IPSEC_CAP(caps, esp),
			MLX5_IPSEC_CAP(caps, ah),
			MLX5_IPSEC_CAP(caps, ipv4_options),
			!!(MLX5_IPSEC_CAP(caps, auth_alg) & BIT(0)),
			!!(MLX5_IPSEC_CAP(caps, auth_alg) & BIT(1)),
			!!(MLX5_IPSEC_CAP(caps, enc_alg) & BIT(0)),
			!!(MLX5_IPSEC_CAP(caps, enc_alg) & BIT(1)),
			MLX5_IPSEC_CAP(caps, sa_cap),
			MLX5_IPSEC_CAP(caps, number_of_ipsec_counters),
			MLX5_IPSEC_CAP64(caps, ipsec_counters_addr));
}

static MLX_IPSEC_ATTR_RO(caps);

static struct attribute *mlx_ipsec_def_attrs[] = {
	&mlx_ipsec_attr_caps.attr,
	NULL,
};

static const struct sysfs_ops mlx5_ipsec_dev_sysfs_ops = {
	.show  = mlx_ipsec_attr_show,
	.store = mlx_ipsec_attr_store,
};

static struct kobj_type mlx5_ipsec_dev_type = {
	.release        = mlx5_ipsec_dev_release,
	.sysfs_ops      = &mlx5_ipsec_dev_sysfs_ops,
	.default_attrs  = mlx_ipsec_def_attrs,
};

int mlx5_ipsec_sysfs_add(struct kobject *kobj, struct kobject *parent)
{
	return kobject_init_and_add(kobj, &mlx5_ipsec_dev_type, parent,
				    "ipsec");
}

