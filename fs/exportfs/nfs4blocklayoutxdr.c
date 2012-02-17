/*
 *  linux/fs/nfsd/nfs4blocklayoutxdr.c
 *
 *
 *  Created by Rick McNeal on 3/31/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */
#include <linux/module.h>
#include <linux/sunrpc/svc.h>
#include <linux/nfs4.h>
#include <linux/nfsd/nfs4layoutxdr.h>

static int
bl_encode_simple(struct exp_xdr_stream *xdr, pnfs_blocklayout_devinfo_t *bld)
{
	__be32 *p = exp_xdr_reserve_space(xdr,
					  12 + 4 + bld->u.simple.bld_sig_len);

	if (!p)
		return -ETOOSMALL;

	p = exp_xdr_encode_u32(p, 1);
	p = exp_xdr_encode_u64(p, bld->u.simple.bld_offset);
	exp_xdr_encode_opaque(p, bld->u.simple.bld_sig,
			      bld->u.simple.bld_sig_len);

	return 0;
}

static int
bl_encode_slice(struct exp_xdr_stream *xdr, pnfs_blocklayout_devinfo_t *bld)
{
	__be32 *p = exp_xdr_reserve_qwords(xdr, 2 + 2 + 1);

	if (!p)
		return -ETOOSMALL;

	p = exp_xdr_encode_u64(p, bld->u.slice.bld_start);
	p = exp_xdr_encode_u64(p, bld->u.slice.bld_len);
	exp_xdr_encode_u32(p, bld->u.slice.bld_index);

	return 0;
}

static int
bl_encode_concat(struct exp_xdr_stream *xdr, pnfs_blocklayout_devinfo_t *bld)
{
	return -ENOTSUPP;
}

static int
bl_encode_stripe(struct exp_xdr_stream *xdr, pnfs_blocklayout_devinfo_t *bld)
{
	int i;
	__be32 *p = exp_xdr_reserve_space(xdr,
					  2 + 1 + bld->u.stripe.bld_stripes);

	p = exp_xdr_encode_u64(p, bld->u.stripe.bld_chunk_size);
	p = exp_xdr_encode_u32(p, bld->u.stripe.bld_stripes);
	for (i = 0; i < bld->u.stripe.bld_stripes; i++)
		p = exp_xdr_encode_u32(p, bld->u.stripe.bld_stripe_indexs[i]);

	return 0;
}

int
blocklayout_encode_devinfo(struct exp_xdr_stream *xdr,
			   const struct list_head *volumes)
{
	u32				num_vols	= 0,
					*layoutlen_p	= xdr->p;
	pnfs_blocklayout_devinfo_t	*bld;
	int				status		= 0;
	__be32 *p;

	p = exp_xdr_reserve_qwords(xdr, 2);
	if (!p)
		return -ETOOSMALL;
	p += 2;

	/*
	 * All simple volumes with their signature are required to be listed
	 * first.
	 */
	list_for_each_entry(bld, volumes, bld_list) {
		num_vols++;
		p = exp_xdr_reserve_qwords(xdr, 1);
		if (!p)
			return -ETOOSMALL;
		p = exp_xdr_encode_u32(p, bld->bld_type);
		switch (bld->bld_type) {
			case PNFS_BLOCK_VOLUME_SIMPLE:
				status = bl_encode_simple(xdr, bld);
				break;
			case PNFS_BLOCK_VOLUME_SLICE:
				status = bl_encode_slice(xdr, bld);
				break;
			case PNFS_BLOCK_VOLUME_CONCAT:
				status = bl_encode_concat(xdr, bld);
				break;
			case PNFS_BLOCK_VOLUME_STRIPE:
				status = bl_encode_stripe(xdr, bld);
				break;
			default:
				BUG();
		}
		if (status)
			goto error;
	}

	/* ---- Fill in the overall length and number of volumes ---- */
	p = exp_xdr_encode_u32(layoutlen_p, (xdr->p - layoutlen_p - 1) * 4);
	exp_xdr_encode_u32(p, num_vols);

error:
	return status;
}
EXPORT_SYMBOL_GPL(blocklayout_encode_devinfo);

enum nfsstat4
blocklayout_encode_layout(struct exp_xdr_stream *xdr,
			  const struct list_head *bl_head)
{
	struct pnfs_blocklayout_layout	*b;
	u32				*layoutlen_p	= xdr->p,
					extents		= 0;
	__be32 *p;

	/*
	 * Save spot for opaque block layout length and number of extents,
	 * fill-in later.
	 */
	p = exp_xdr_reserve_qwords(xdr, 2);
	if (!p)
		return NFS4ERR_TOOSMALL;
	p += 2;

	list_for_each_entry(b, bl_head, bll_list) {
		extents++;
		p = exp_xdr_reserve_qwords(xdr, 5 * 2 + 1);
		if (!p)
			return NFS4ERR_TOOSMALL;
		p = exp_xdr_encode_u64(p, b->bll_vol_id.sbid);
		p = exp_xdr_encode_u64(p, b->bll_vol_id.devid);
		p = exp_xdr_encode_u64(p, b->bll_foff);
		p = exp_xdr_encode_u64(p, b->bll_len);
		p = exp_xdr_encode_u64(p, b->bll_soff);
		p = exp_xdr_encode_u32(p, b->bll_es);
	}

	/* ---- Fill in the overall length and number of extents ---- */
	p = exp_xdr_encode_u32(layoutlen_p, (p - layoutlen_p - 1) * 4);
	exp_xdr_encode_u32(p, extents);

	return NFS4_OK;
}
EXPORT_SYMBOL_GPL(blocklayout_encode_layout);
