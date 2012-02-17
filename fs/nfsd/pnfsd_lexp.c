/*
 * linux/fs/nfsd/pnfs_lexp.c
 *
 * pNFS export of local filesystems.
 *
 * Export local file systems over the files layout type.
 * The MDS (metadata server) functions also as a single DS (data server).
 * This is mostly useful for development and debugging purposes.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Copyright (C) 2008 Benny Halevy, <bhalevy@panasas.com>
 *
 * Initial implementation was based on the pnfs-gfs2 patches done
 * by David M. Richter <richterd@citi.umich.edu>
 */

#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/sunrpc/svc_xprt.h>
#include <linux/nfsd/nfs4layoutxdr.h>

#include "pnfsd.h"

#define NFSDDBG_FACILITY NFSDDBG_PNFS

struct sockaddr_storage pnfsd_lexp_addr;
size_t pnfs_lexp_addr_len;

static wait_queue_head_t lo_recall_wq;

static int
pnfsd_lexp_layout_type(struct super_block *sb)
{
	int ret = LAYOUT_NFSV4_1_FILES;
	dprintk("<-- %s: return %d\n", __func__, ret);
	return ret;
}

static int
pnfsd_lexp_get_device_iter(struct super_block *sb,
			   u32 layout_type,
			   struct nfsd4_pnfs_dev_iter_res *res)
{
	dprintk("--> %s: sb=%p\n", __func__, sb);

	BUG_ON(layout_type != LAYOUT_NFSV4_1_FILES);

	res->gd_eof = 1;
	if (res->gd_cookie)
		return -ENOENT;
	res->gd_cookie = 1;
	res->gd_verf = 1;
	res->gd_devid = 1;

	dprintk("<-- %s: return 0\n", __func__);
	return 0;
}

static int
pnfsd_lexp_get_device_info(struct super_block *sb,
			   struct exp_xdr_stream *xdr,
			   u32 layout_type,
			   const struct nfsd4_pnfs_deviceid *devid)
{
	int err;
	struct pnfs_filelayout_device fdev;
	struct pnfs_filelayout_multipath fl_devices[1];
	u32 fl_stripe_indices[1] = { 0 };
	struct pnfs_filelayout_devaddr daddr;
	/* %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x.%03u.%03u */
	char daddr_buf[8*4 + 2*3 + 10];

	dprintk("--> %s: sb=%p\n", __func__, sb);

	BUG_ON(layout_type != LAYOUT_NFSV4_1_FILES);

	memset(&fdev, '\0', sizeof(fdev));

	if (devid->devid != 1) {
		printk(KERN_ERR "%s: WARNING: didn't receive a deviceid of 1 "
			"(got: 0x%llx)\n", __func__, devid->devid);
		err = -EINVAL;
		goto out;
	}

	/* format local address */
	fdev.fl_device_length = 1;
	fdev.fl_device_list = fl_devices;

	fdev.fl_stripeindices_length = fdev.fl_device_length;
	fdev.fl_stripeindices_list = fl_stripe_indices;

	daddr.r_addr.data = daddr_buf;
	daddr.r_addr.len = sizeof(daddr_buf);
	err = __svc_print_netaddr(&pnfsd_lexp_addr, &daddr.r_addr);
	if (err < 0)
		goto out;
	daddr.r_addr.len = err;
	switch (pnfsd_lexp_addr.ss_family) {
	case AF_INET:
		daddr.r_netid.data = "tcp";
		daddr.r_netid.len = 3;
		break;
	case AF_INET6:
		daddr.r_netid.data = "tcp6";
		daddr.r_netid.len = 4;
		break;
	default:
		BUG();
	}
	fdev.fl_device_list[0].fl_multipath_length = 1;
	fdev.fl_device_list[0].fl_multipath_list = &daddr;

	/* have nfsd encode the device info */
	err = filelayout_encode_devinfo(xdr, &fdev);
out:
	dprintk("<-- %s: return %d\n", __func__, err);
	return err;
}

static int get_stripe_unit(int blocksize)
{
	if (blocksize < NFSSVC_MAXBLKSIZE)
		blocksize = NFSSVC_MAXBLKSIZE - (NFSSVC_MAXBLKSIZE % blocksize);
	dprintk("%s: return %d\n", __func__, blocksize);
	return blocksize;
}

static enum nfsstat4
pnfsd_lexp_layout_get(struct inode *inode,
		      struct exp_xdr_stream *xdr,
		      const struct nfsd4_pnfs_layoutget_arg *arg,
		      struct nfsd4_pnfs_layoutget_res *res)
{
	enum nfsstat4 rc = NFS4_OK;
	struct pnfs_filelayout_layout *layout = NULL;
	struct knfsd_fh *fhp = NULL;

	dprintk("--> %s: inode=%p\n", __func__, inode);

	res->lg_seg.layout_type = LAYOUT_NFSV4_1_FILES;
#ifdef     CONFIG_PNFSD_LEXP_LAYOUT_SEGMENTS
#if CONFIG_PNFSD_LEXP_LAYOUT_SEGMENT_SIZE <= 0
#error CONFIG_PNFSD_LEXP_LAYOUT_SEGMENT_SIZE must be greater than zero
#endif
	res->lg_seg.offset -= res->lg_seg.offset % CONFIG_PNFSD_LEXP_LAYOUT_SEGMENT_SIZE;
	res->lg_seg.length = CONFIG_PNFSD_LEXP_LAYOUT_SEGMENT_SIZE;
#else   /* CONFIG_PNFSD_LEXP_LAYOUT_SEGMENTS */
	res->lg_seg.offset = 0;
	res->lg_seg.length = NFS4_MAX_UINT64;
#endif  /* CONFIG_PNFSD_LEXP_LAYOUT_SEGMENTS */

	layout = kzalloc(sizeof(*layout), GFP_KERNEL);
	if (layout == NULL) {
		rc = NFS4ERR_DELAY;
		goto error;
	}

	/* Set file layout response args */
	layout->lg_layout_type = LAYOUT_NFSV4_1_FILES;
	layout->lg_stripe_type = STRIPE_SPARSE;
	layout->lg_commit_through_mds = true;
	layout->lg_stripe_unit = get_stripe_unit(inode->i_sb->s_blocksize);
	layout->lg_fh_length = 1;
	layout->device_id.sbid = arg->lg_sbid;
	layout->device_id.devid = 1;				/*FSFTEMP*/
	layout->lg_first_stripe_index = 0;			/*FSFTEMP*/
	layout->lg_pattern_offset = 0;

	fhp = kmalloc(sizeof(*fhp), GFP_KERNEL);
	if (fhp == NULL) {
		rc = NFS4ERR_DELAY;
		goto error;
	}

	memcpy(fhp, arg->lg_fh, sizeof(*fhp));
	pnfs_fh_mark_ds(fhp);
	layout->lg_fh_list = fhp;

	/* Call nfsd to encode layout */
	rc = filelayout_encode_layout(xdr, layout);
exit:
	kfree(layout);
	kfree(fhp);
	dprintk("<-- %s: return %d offset=%llu length=%llu\n", __func__, rc,
		(unsigned long long)res->lg_seg.offset,
		(unsigned long long)res->lg_seg.length);
	return rc;

error:
	res->lg_seg.length = 0;
	goto exit;
}

static int
pnfsd_lexp_layout_commit(struct inode *inode,
			 const struct nfsd4_pnfs_layoutcommit_arg *args,
			 struct nfsd4_pnfs_layoutcommit_res *res)
{
	dprintk("%s: (unimplemented)\n", __func__);

	return 0;
}

static int
pnfsd_lexp_layout_return(struct inode *inode,
			 const struct nfsd4_pnfs_layoutreturn_arg *args)
{
	wake_up_all(&lo_recall_wq);
	return 0;
}

static int pnfsd_lexp_get_state(struct inode *inode, struct knfsd_fh *fh,
				struct pnfs_get_state *p)
{
	return 0;	/* just use the current stateid */
}

static struct pnfs_export_operations pnfsd_lexp_ops = {
	.layout_type = pnfsd_lexp_layout_type,
	.get_device_info = pnfsd_lexp_get_device_info,
	.get_device_iter = pnfsd_lexp_get_device_iter,
	.layout_get = pnfsd_lexp_layout_get,
	.layout_commit = pnfsd_lexp_layout_commit,
	.layout_return = pnfsd_lexp_layout_return,
	.get_state = pnfsd_lexp_get_state,
};

void
pnfsd_lexp_init(struct inode *inode)
{
	static bool init_once;

	dprintk("%s: &pnfsd_lexp_ops=%p\n", __func__, &pnfsd_lexp_ops);
	inode->i_sb->s_pnfs_op = &pnfsd_lexp_ops;

	if (!init_once++)
		init_waitqueue_head(&lo_recall_wq);
}

bool
is_inode_pnfsd_lexp(struct inode *inode)
{
	return inode->i_sb->s_pnfs_op == &pnfsd_lexp_ops;
}

static bool
has_layout(struct nfs4_file *fp)
{
	return !list_empty(&fp->fi_layouts);
}

/*
 * recalls the layout if needed and waits synchronously for its return
 */
int
pnfsd_lexp_recall_layout(struct inode *inode, bool with_nfs4_state_lock)
{
	struct nfs4_file *fp;
	struct nfsd4_pnfs_cb_layout cbl;
	int status = 0;

	dprintk("%s: begin\n", __func__);
	fp = find_file(inode);
	if (!fp)
		goto out_nofp;

	if (!has_layout(fp))
		goto out;

	memset(&cbl, 0, sizeof(cbl));
	cbl.cbl_recall_type = RETURN_FILE;
	cbl.cbl_seg.layout_type = LAYOUT_NFSV4_1_FILES;
	/* for now, always recall the whole layout */
	cbl.cbl_seg.iomode = IOMODE_ANY;
	cbl.cbl_seg.offset = 0;
	cbl.cbl_seg.length = NFS4_MAX_UINT64;

	while (has_layout(fp)) {
		dprintk("%s: recalling layout\n", __func__);
		status = _nfsd_layout_recall_cb(inode->i_sb, inode, &cbl, with_nfs4_state_lock);

		switch (status) {
		case 0:
		case -EAGAIN:
			break;
		case -ENOENT:	/* no matching layout */
			status = 0;
			goto out;
		default:
			goto out;
		}

		if (with_nfs4_state_lock)
			nfs4_unlock_state();
		status = wait_event_interruptible(lo_recall_wq, !has_layout(fp));
		if (with_nfs4_state_lock)
			nfs4_lock_state();
		dprintk("%s: waiting status=%d\n", __func__, status);
		if (status)
			break;
	}
out:
	put_nfs4_file(fp);
out_nofp:
	dprintk("%s: status=%d\n", __func__, status);
	return status;
}
