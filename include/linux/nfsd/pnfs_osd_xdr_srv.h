/*
 * pnfs-objects Server XDR definitions and API
 *
 * Copyright (C) from 2011 Panasas Inc.  All rights reserved.
 *
 * Authors:
 *   Boaz Harrosh <bharrosh@panasas.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 *
 */
#ifndef __PNFS_OSD_XDR_SRV_H__
#define __PNFS_OSD_XDR_SRV_H__

#include <linux/pnfs_osd_xdr.h>
#include <linux/exp_xdr.h>

/* Layout encoding */
enum nfsstat4 pnfs_osd_xdr_encode_layout_hdr(
	struct exp_xdr_stream *xdr,
	struct pnfs_osd_layout *layout);

enum nfsstat4 pnfs_osd_xdr_encode_layout_cred(
	struct exp_xdr_stream *xdr,
	struct pnfs_osd_object_cred *cred);

/* deviceaddr encoding */
enum nfsstat4 pnfs_osd_xdr_encode_deviceaddr(
	struct exp_xdr_stream *xdr, struct pnfs_osd_deviceaddr *devaddr);

/* layout_commit decoding */
__be32 *pnfs_osd_xdr_decode_layoutupdate(
	struct pnfs_osd_layoutupdate *lou, __be32 *p);

/* layout_return decoding */
bool pnfs_osd_xdr_decode_ioerr(
	struct pnfs_osd_ioerr *ioerr, struct exp_xdr_stream *xdr);

#endif /* __PNFS_OSD_XDR_SRV_H__ */
