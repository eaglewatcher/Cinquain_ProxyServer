/*
 *  Object-Based pNFS Layout XDR layer for the Server side
 *
 *  Copyright (C) 2007 and on Panasas Inc.
 *  All rights reserved.
 *
 *  Benny Halevy <bhalevy@panasas.com>
 *  Boaz Harrosh <bharrosh@panasas.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  See the file COPYING included with this distribution for more details.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the Panasas company nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/nfsd/nfsd4_pnfs.h>

#include "linux/nfsd/pnfs_osd_xdr_srv.h"

/*
 * struct pnfs_osd_data_map {
 *	u32	odm_num_comps;
 *	u64	odm_stripe_unit;
 *	u32	odm_group_width;
 *	u32	odm_group_depth;
 *	u32	odm_mirror_cnt;
 *	u32	odm_raid_algorithm;
 * };
 */
static enum nfsstat4 pnfs_osd_xdr_encode_data_map(
	struct exp_xdr_stream *xdr,
	struct pnfs_osd_data_map *data_map)
{
	__be32 *p = exp_xdr_reserve_qwords(xdr, 1+2+1+1+1+1);

	if (!p)
		return NFS4ERR_TOOSMALL;

	p = exp_xdr_encode_u32(p, data_map->odm_num_comps);
	p = exp_xdr_encode_u64(p, data_map->odm_stripe_unit);
	p = exp_xdr_encode_u32(p, data_map->odm_group_width);
	p = exp_xdr_encode_u32(p, data_map->odm_group_depth);
	p = exp_xdr_encode_u32(p, data_map->odm_mirror_cnt);
	p = exp_xdr_encode_u32(p, data_map->odm_raid_algorithm);

	return 0;
}

/*
 * struct pnfs_osd_objid {
 *	struct nfs4_deviceid	oid_device_id;
 *	u64			oid_partition_id;
 *	u64			oid_object_id;
 * };
 */
static inline enum nfsstat4 pnfs_osd_xdr_encode_objid(
	struct exp_xdr_stream *xdr,
	struct pnfs_osd_objid *object_id)
{
	__be32 *p = exp_xdr_reserve_qwords(xdr, 2+2+2+2);
	struct nfsd4_pnfs_deviceid *dev_id =
		(struct nfsd4_pnfs_deviceid *)&object_id->oid_device_id;

	if (!p)
		return NFS4ERR_TOOSMALL;

	p = exp_xdr_encode_u64(p, dev_id->sbid);
	p = exp_xdr_encode_u64(p, dev_id->devid);
	p = exp_xdr_encode_u64(p, object_id->oid_partition_id);
	p = exp_xdr_encode_u64(p, object_id->oid_object_id);

	return 0;
}

/*
 * enum pnfs_osd_cap_key_sec4 {
 *	PNFS_OSD_CAP_KEY_SEC_NONE = 0,
 *	PNFS_OSD_CAP_KEY_SEC_SSV  = 1
 * };
 *
 * struct pnfs_osd_object_cred {
 *	struct pnfs_osd_objid		oc_object_id;
 *	u32				oc_osd_version;
 *	u32				oc_cap_key_sec;
 *	struct pnfs_osd_opaque_cred	oc_cap_key
 *	struct pnfs_osd_opaque_cred	oc_cap;
 * };
 */
enum nfsstat4 pnfs_osd_xdr_encode_layout_cred(
	struct exp_xdr_stream *xdr,
	struct pnfs_osd_object_cred *olo_comp)
{
	__be32 *p;
	enum nfsstat4 err;

	err = pnfs_osd_xdr_encode_objid(xdr, &olo_comp->oc_object_id);
	if (err)
		return err;

	p = exp_xdr_reserve_space(xdr, 3*4 + 4+olo_comp->oc_cap.cred_len);
	if (!p)
		return NFS4ERR_TOOSMALL;

	p = exp_xdr_encode_u32(p, olo_comp->oc_osd_version);

	/* No sec for now */
	p = exp_xdr_encode_u32(p, PNFS_OSD_CAP_KEY_SEC_NONE);
	p = exp_xdr_encode_u32(p, 0); /* opaque oc_capability_key<> */

	exp_xdr_encode_opaque(p, olo_comp->oc_cap.cred,
			      olo_comp->oc_cap.cred_len);

	return 0;
}
EXPORT_SYMBOL(pnfs_osd_xdr_encode_layout_cred);

/*
 * struct pnfs_osd_layout {
 *	struct pnfs_osd_data_map	olo_map;
 *	u32				olo_comps_index;
 *	u32				olo_num_comps;
 *	struct pnfs_osd_object_cred	*olo_comps;
 * };
 */
enum nfsstat4 pnfs_osd_xdr_encode_layout_hdr(
	struct exp_xdr_stream *xdr,
	struct pnfs_osd_layout *pol)
{
	__be32 *p;
	enum nfsstat4 err;

	err = pnfs_osd_xdr_encode_data_map(xdr, &pol->olo_map);
	if (err)
		return err;

	p = exp_xdr_reserve_qwords(xdr, 2);
	if (!p)
		return NFS4ERR_TOOSMALL;

	p = exp_xdr_encode_u32(p, pol->olo_comps_index);
	p = exp_xdr_encode_u32(p, pol->olo_num_comps);

	return 0;
}
EXPORT_SYMBOL(pnfs_osd_xdr_encode_layout_hdr);

static enum nfsstat4 _encode_string(struct exp_xdr_stream *xdr,
			  const struct nfs4_string *str)
{
	__be32 *p = exp_xdr_reserve_space(xdr, 4 + str->len);

	if (!p)
		return NFS4ERR_TOOSMALL;
	exp_xdr_encode_opaque(p, str->data, str->len);
	return 0;
}

/* struct pnfs_osd_deviceaddr {
 *	struct pnfs_osd_targetid	oda_targetid;
 *	struct pnfs_osd_targetaddr	oda_targetaddr;
 *	u8				oda_lun[8];
 *	struct nfs4_string		oda_systemid;
 *	struct pnfs_osd_object_cred	oda_root_obj_cred;
 *	struct nfs4_string		oda_osdname;
 * };
 */
enum nfsstat4 pnfs_osd_xdr_encode_deviceaddr(
	struct exp_xdr_stream *xdr, struct pnfs_osd_deviceaddr *devaddr)
{
	__be32 *p;
	enum nfsstat4 err;

	p = exp_xdr_reserve_space(xdr, 4 + 4 + sizeof(devaddr->oda_lun));
	if (!p)
		return NFS4ERR_TOOSMALL;

	/* Empty oda_targetid */
	p = exp_xdr_encode_u32(p, OBJ_TARGET_ANON);

	/* Empty oda_targetaddr for now */
	p = exp_xdr_encode_u32(p, 0);

	/* oda_lun */
	exp_xdr_encode_bytes(p, devaddr->oda_lun, sizeof(devaddr->oda_lun));

	err = _encode_string(xdr, &devaddr->oda_systemid);
	if (err)
		return err;

	err = pnfs_osd_xdr_encode_layout_cred(xdr,
					      &devaddr->oda_root_obj_cred);
	if (err)
		return err;

	err = _encode_string(xdr, &devaddr->oda_osdname);
	if (err)
		return err;

	return 0;
}
EXPORT_SYMBOL(pnfs_osd_xdr_encode_deviceaddr);

/*
 * struct pnfs_osd_layoutupdate {
 *	u32	dsu_valid;
 *	s64	dsu_delta;
 *	u32	olu_ioerr_flag;
 * };
 */
__be32 *
pnfs_osd_xdr_decode_layoutupdate(struct pnfs_osd_layoutupdate *lou, __be32 *p)
{
	lou->dsu_valid = be32_to_cpu(*p++);
	if (lou->dsu_valid)
		p = xdr_decode_hyper(p, &lou->dsu_delta);
	lou->olu_ioerr_flag = be32_to_cpu(*p++);
	return p;
}
EXPORT_SYMBOL(pnfs_osd_xdr_decode_layoutupdate);

/*
 * struct pnfs_osd_objid {
 *	struct nfs4_deviceid	oid_device_id;
 *	u64			oid_partition_id;
 *	u64			oid_object_id;
 * }; xdr size 32
 */
static inline __be32 *
pnfs_osd_xdr_decode_objid(__be32 *p, struct pnfs_osd_objid *objid)
{
	/* FIXME: p = xdr_decode_fixed(...) */
	memcpy(objid->oid_device_id.data, p, sizeof(objid->oid_device_id.data));
	p += XDR_QUADLEN(sizeof(objid->oid_device_id.data));

	p = xdr_decode_hyper(p, &objid->oid_partition_id);
	p = xdr_decode_hyper(p, &objid->oid_object_id);
	return p;
}

/*
 * struct pnfs_osd_ioerr {
 *	struct pnfs_osd_objid	oer_component;
 *	u64			oer_comp_offset;
 *	u64			oer_comp_length;
 *	u32			oer_iswrite;
 *	u32			oer_errno;
 * }; xdr size 32 + 24
 */
bool pnfs_osd_xdr_decode_ioerr(struct pnfs_osd_ioerr *ioerr,
			       struct exp_xdr_stream *xdr)
{
	__be32 *p = exp_xdr_reserve_space(xdr, 32 + 24);
	if (!p)
		return false;

	p = pnfs_osd_xdr_decode_objid(p, &ioerr->oer_component);
	p = xdr_decode_hyper(p, &ioerr->oer_comp_offset);
	p = xdr_decode_hyper(p, &ioerr->oer_comp_length);
	ioerr->oer_iswrite = be32_to_cpu(*p++);
	ioerr->oer_errno = be32_to_cpu(*p);
	return true;
}
EXPORT_SYMBOL(pnfs_osd_xdr_decode_ioerr);
