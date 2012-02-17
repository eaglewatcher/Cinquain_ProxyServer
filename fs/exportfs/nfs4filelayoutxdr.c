/*
 *  Copyright (c) 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson <andros@umich.edu>
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
 *  3. Neither the name of the University nor the names of its
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
#include <linux/exp_xdr.h>
#include <linux/module.h>
#include <linux/nfs4.h>
#include <linux/nfsd/nfsfh.h>
#include <linux/nfsd/nfs4layoutxdr.h>

/* We do our-own dprintk so filesystems are not dependent on sunrpc */
#ifdef dprintk
#undef dprintk
#endif
#define dprintk(fmt, args, ...)	do { } while (0)

/* Calculate the XDR length of the GETDEVICEINFO4resok structure
 * excluding the gdir_notification and the gdir_device_addr da_layout_type.
 */
static int fl_devinfo_xdr_words(const struct pnfs_filelayout_device *fdev)
{
	struct pnfs_filelayout_devaddr *fl_addr;
	struct pnfs_filelayout_multipath *mp;
	int i, j, nwords;

	/* da_addr_body length, indice length, indices,
	 * multipath_list4 length */
	nwords = 1 + 1 + fdev->fl_stripeindices_length + 1;
	for (i = 0; i < fdev->fl_device_length; i++) {
		mp = &fdev->fl_device_list[i];
		nwords++; /* multipath list length */
		for (j = 0; j < mp->fl_multipath_length; j++) {
			fl_addr = mp->fl_multipath_list;
			nwords += 1 + exp_xdr_qwords(fl_addr->r_netid.len);
			nwords += 1 + exp_xdr_qwords(fl_addr->r_addr.len);
		}
	}
	dprintk("<-- %s nwords %d\n", __func__, nwords);
	return nwords;
}

/* Encodes the nfsv4_1_file_layout_ds_addr4 structure from draft 13
 * on the response stream.
 * Use linux error codes (not nfs) since these values are being
 * returned to the file system.
 */
int
filelayout_encode_devinfo(struct exp_xdr_stream *xdr,
			  const struct pnfs_filelayout_device *fdev)
{
	unsigned int i, j, len = 0, opaque_words;
	u32 *p_in;
	u32 index_count = fdev->fl_stripeindices_length;
	u32 dev_count = fdev->fl_device_length;
	int error = 0;
	__be32 *p;

	opaque_words = fl_devinfo_xdr_words(fdev);
	dprintk("%s: Begin indx_cnt: %u dev_cnt: %u total size %u\n",
		__func__,
		index_count,
		dev_count,
		opaque_words*4);

	/* check space for opaque length */
	p = p_in = exp_xdr_reserve_qwords(xdr, opaque_words);
	if (!p) {
		error =  -ETOOSMALL;
		goto out;
	}

	/* Fill in length later */
	p++;

	/* encode device list indices */
	p = exp_xdr_encode_u32(p, index_count);
	for (i = 0; i < index_count; i++)
		p = exp_xdr_encode_u32(p, fdev->fl_stripeindices_list[i]);

	/* encode device list */
	p = exp_xdr_encode_u32(p, dev_count);
	for (i = 0; i < dev_count; i++) {
		struct pnfs_filelayout_multipath *mp = &fdev->fl_device_list[i];

		p = exp_xdr_encode_u32(p, mp->fl_multipath_length);
		for (j = 0; j < mp->fl_multipath_length; j++) {
			struct pnfs_filelayout_devaddr *da =
						&mp->fl_multipath_list[j];

			/* Encode device info */
			p = exp_xdr_encode_opaque(p, da->r_netid.data,
						     da->r_netid.len);
			p = exp_xdr_encode_opaque(p, da->r_addr.data,
						     da->r_addr.len);
		}
	}

	/* backfill in length. Subtract 4 for da_addr_body size */
	len = (char *)p - (char *)p_in;
	exp_xdr_encode_u32(p_in, len - 4);

	error = 0;
out:
	dprintk("%s: End err %d xdrlen %d\n",
		__func__, error, len);
	return error;
}
EXPORT_SYMBOL(filelayout_encode_devinfo);

/* Encodes the loc_body structure from draft 13
 * on the response stream.
 * Use linux error codes (not nfs) since these values are being
 * returned to the file system.
 */
enum nfsstat4
filelayout_encode_layout(struct exp_xdr_stream *xdr,
			 const struct pnfs_filelayout_layout *flp)
{
	u32 len = 0, nfl_util, fhlen, i;
	u32 *layoutlen_p;
	enum nfsstat4 nfserr;
	__be32 *p;

	dprintk("%s: device_id %llx:%llx fsi %u, numfh %u\n",
		__func__,
		flp->device_id.pnfs_fsid,
		flp->device_id.pnfs_devid,
		flp->lg_first_stripe_index,
		flp->lg_fh_length);

	/* Ensure file system added at least one file handle */
	if (flp->lg_fh_length <= 0) {
		dprintk("%s: File Layout has no file handles!!\n", __func__);
		nfserr = NFS4ERR_LAYOUTUNAVAILABLE;
		goto out;
	}

	/* Ensure room for len, devid, util, first_stripe_index,
	 * pattern_offset, number of filehandles */
	p = layoutlen_p = exp_xdr_reserve_qwords(xdr, 1+2+2+1+1+2+1);
	if (!p) {
		nfserr = NFS4ERR_TOOSMALL;
		goto out;
	}

	/* save spot for opaque file layout length, fill-in later*/
	p++;

	/* encode device id */
	p = exp_xdr_encode_u64(p, flp->device_id.sbid);
	p = exp_xdr_encode_u64(p, flp->device_id.devid);

	/* set and encode flags */
	nfl_util = flp->lg_stripe_unit;
	if (flp->lg_commit_through_mds)
		nfl_util |= NFL4_UFLG_COMMIT_THRU_MDS;
	if (flp->lg_stripe_type == STRIPE_DENSE)
		nfl_util |= NFL4_UFLG_DENSE;
	p = exp_xdr_encode_u32(p, nfl_util);

	/* encode first stripe index */
	p = exp_xdr_encode_u32(p, flp->lg_first_stripe_index);

	/* encode striping pattern start */
	p = exp_xdr_encode_u64(p, flp->lg_pattern_offset);

	/* encode number of file handles */
	p = exp_xdr_encode_u32(p, flp->lg_fh_length);

	/* encode file handles */
	for (i = 0; i < flp->lg_fh_length; i++) {
		fhlen = flp->lg_fh_list[i].fh_size;
		p = exp_xdr_reserve_space(xdr, 4 + fhlen);
		if (!p) {
			nfserr = NFS4ERR_TOOSMALL;
			goto out;
		}
		p = exp_xdr_encode_opaque(p, &flp->lg_fh_list[i].fh_base, fhlen);
	}

	/* Set number of bytes encoded =  total_bytes_encoded - length var */
	len = (char *)p - (char *)layoutlen_p;
	exp_xdr_encode_u32(layoutlen_p, len - 4);

	nfserr = NFS4_OK;
out:
	dprintk("%s: End err %u xdrlen %d\n",
		__func__, nfserr, len);
	return nfserr;
}
EXPORT_SYMBOL(filelayout_encode_layout);
