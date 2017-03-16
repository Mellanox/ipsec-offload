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

#ifndef __MLX5_EN_IPSEC_CMDS_H__
#define __MLX5_EN_IPSEC_CMDS_H__

enum {
	MLX5_IPSEC_RX_SYNDROME_DECRYPTED = 0x11,
	MLX5_IPSEC_RX_SYNDROME_AUTH_FAILED = 0x12,
};

struct mlx5_ipsec_rx_metadata {
	unsigned char   reserved;
	__be32		sa_handle;
} __packed;

enum {
	MLX5_IPSEC_TX_SYNDROME_OFFLOAD = 0x8,
	MLX5_IPSEC_TX_SYNDROME_OFFLOAD_WITH_LSO_TCP = 0x9,
};

struct mlx5_ipsec_tx_metadata {
	__be16 mss_inv;		/* 1/MSS in 16bit fixed point, only for LSO */
	__be16 seq;		/* LSBs of the first TCP seq, only for LSO */
	u8     esp_next_proto;  /* Next protocol of ESP */
} __packed;

struct mlx5_ipsec_metadata {
	unsigned char syndrome;
	union {
		unsigned char raw[5];
		/* from FPGA to host, on successful decrypt */
		struct mlx5_ipsec_rx_metadata rx;
		/* from host to FPGA */
		struct mlx5_ipsec_tx_metadata tx;
	} __packed content;
	/* packet type ID field	*/
	__be16 ethertype;
} __packed;

enum mlx5_ipsec_enc_mode {
	SADB_MODE_NONE			= 0,
	SADB_MODE_AES_GCM_128_AUTH_128	= 1,
	SADB_MODE_AES_GCM_256_AUTH_128	= 3,
};

#define MLX5_IPSEC_SADB_IP_AH       BIT(7)
#define MLX5_IPSEC_SADB_IP_ESP      BIT(6)
#define MLX5_IPSEC_SADB_SA_VALID    BIT(5)
#define MLX5_IPSEC_SADB_SPI_EN      BIT(4)
#define MLX5_IPSEC_SADB_DIR_SX      BIT(3)
#define MLX5_IPSEC_SADB_IPV6        BIT(2)

struct mlx5_ipsec_sadb_cmd {
	__be32 cmd;
	u8 key_enc[32];
	u8 key_auth[32];
	__be32 sip[4];
	__be32 dip[4];
	union {
		struct {
			__be32 reserved;
			u8 salt_iv[8];
			__be32 salt;
		} gcm;
		struct {
			u8 salt[16];
		} cbc;
	};
	__be32 spi;
	__be32 sw_sa_handle;
	__be16 tfclen;
	u8 enc_mode;
	u8 sip_masklen;
	u8 dip_masklen;
	u8 flags;
	u8 reserved[2];
} __packed;

enum mlx5_ipsec_response_syndrome {
	MLX5_IPSEC_RESPONSE_SUCCESS = 0,
	MLX5_IPSEC_RESPONSE_ILLEGAL_REQUEST = 1,
	MLX5_IPSEC_RESPONSE_SADB_ISSUE = 2,
	MLX5_IPSEC_RESPONSE_WRITE_RESPONSE_ISSUE = 3,
	MLX5_IPSEC_SA_SEND_FAIL = 0xfe,
	MLX5_IPSEC_SA_PENDING = 0xff,
};

enum {
	MLX5_IPSEC_CMD_ADD_SA = 0,
	MLX5_IPSEC_CMD_DEL_SA = 1,
};

struct mlx5_ipsec_sadb_resp {
	__be32 syndrome;
	__be32 sw_sa_handle;
	u8 reserved[24];
};

#endif /* __MLX5_EN_IPSEC_CMDS_H__ */
