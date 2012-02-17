/*
 *  bl_ops.c
 *  spNFS
 *
 *  Created by Rick McNeal on 4/1/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

/*
 * Block layout operations.
 *
 * These functions, with the exception of pnfs_block_enabled, are assigned to
 * the super block s_export_op structure.
 */

#include <linux/module.h>
#include <linux/genhd.h>
#include <linux/fs.h>
#include <linux/exportfs.h>
#include <linux/nfsd/nfs4layoutxdr.h>
#include <linux/nfsd/export.h>
#include <linux/nfsd/nfsd4_pnfs.h>
#include <linux/nfsd/debug.h>
#include <linux/spinlock_types.h>
#include <linux/dm-ioctl.h>
#include <asm/uaccess.h>
#include <linux/falloc.h>

#include "pnfsd.h"
#include "nfsd4_block.h"

#define NFSDDBG_FACILITY	NFSDDBG_PNFS

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define BL_LAYOUT_HASH_BITS	4
#define BL_LAYOUT_HASH_SIZE	(1 << BL_LAYOUT_HASH_BITS)
#define BL_LAYOUT_HASH_MASK	(BL_LAYOUT_HASH_SIZE - 1)
#define BL_LIST_REQ	(sizeof (struct dm_ioctl) + 256)

#define bl_layout_hashval(id) \
	((id) & BL_LAYOUT_HASH_MASK)

#define BL_SECT_SHIFT		9
#define BL_SECT_SIZE		(1 << BL_SECT_SHIFT)
#define BL_SECT_MASK		(~(BL_SECT_SIZE - 1))
#define BL_SECT_ALIGN(x)	ALIGN((x), BL_SECT_SIZE)

#define BLL_F_END(p) ((p)->bll_foff + (p)->bll_len)
#define BLL_S_END(p) ((p)->bll_soff + (p)->bll_len)
#define _2SECTS(v) ((v) >> BL_SECT_SHIFT)
#define _2BYTES(v) ((unsigned long long)(v) << BL_SECT_SHIFT)

#ifndef READ32
#define READ32(x)	(x) = ntohl(*p++)
#define READ64(x)	do {			\
(x) = (u64)ntohl(*p++) << 32;	\
(x) |= ntohl(*p++);		\
} while (0)
#endif


typedef enum {False = 0, True = !False} boolean_t;
/* ---- block layoutget and commit structure ---- */
typedef struct bl_layout_rec {
	struct list_head	blr_hash,
				blr_layouts;
	dev_t			blr_rdev;
	struct inode		*blr_inode;
	int			blr_recalled;	// debug
	u64			blr_orig_size,
				blr_commit_size,
				blr_ext_size;
	struct mutex		blr_lock;	// Protects blr_layouts
} bl_layout_rec_t;

static struct list_head layout_hash;
static struct list_head layout_hashtbl[BL_LAYOUT_HASH_SIZE];
static spinlock_t layout_hashtbl_lock;

/* ---- prototypes ---- */
static boolean_t device_slice(dev_t devid);
static boolean_t device_dm(dev_t devid);
static boolean_t layout_inode_add(struct inode *i, bl_layout_rec_t **);
static bl_layout_rec_t *layout_inode_find(struct inode *i);
static void layout_inode_del(struct inode *i);
static char *map_state2name(enum pnfs_block_extent_state4 s);
static pnfs_blocklayout_devinfo_t *bld_alloc(struct list_head *volume, int type);
static void bld_free(pnfs_blocklayout_devinfo_t *bld);
static pnfs_blocklayout_devinfo_t *bld_simple(struct list_head *volumes,
    dev_t devid, int local_index);
static pnfs_blocklayout_devinfo_t *bld_slice(struct list_head *volumes,
    dev_t devid, int my_loc, int idx);
static int layout_cache_fill_from(bl_layout_rec_t *r, struct list_head *h,
    struct nfsd4_layout_seg *seg);
struct list_head *layout_cache_iter(struct super_block *, bl_layout_rec_t *r,
    struct list_head *bl_possible, struct nfsd4_layout_seg *seg);
static void layout_cache_merge(bl_layout_rec_t *r, struct list_head *h);
static int layout_cache_update(bl_layout_rec_t *r, struct list_head *h);
static void layout_cache_del(bl_layout_rec_t *r, const struct nfsd4_layout_seg *seg);
static void print_bll(pnfs_blocklayout_layout_t *b, char *);
static inline boolean_t layout_cache_fill_from_list(bl_layout_rec_t *r,
    struct list_head *h, struct nfsd4_layout_seg *seg);
static inline void bll_collapse(bl_layout_rec_t *r,
    pnfs_blocklayout_layout_t *c);
static pnfs_blocklayout_layout_t *bll_alloc(u64 offset, u64 len,
    enum bl_cache_state state, struct list_head *h);
static pnfs_blocklayout_layout_t *bll_alloc_dup(pnfs_blocklayout_layout_t *b,
    enum bl_cache_state c, struct list_head *h);
static inline boolean_t layout_conflict(pnfs_blocklayout_layout_t *b, u32 iomode,
    enum pnfs_block_extent_state4 *s);
static void extents_setup(struct fiemap_extent_info *fei);
static void extents_count(struct fiemap_extent_info *fei, struct inode *i,
    u64 foff, u64 len);
static boolean_t extents_get(struct fiemap_extent_info *fei, struct inode *i,
    u64 foff, u64 len);
static boolean_t extents_process(struct fiemap_extent_info *fei,
    struct list_head *bl_candidates, struct nfsd4_layout_seg *,
    u64 sbid, dev_t dev, pnfs_blocklayout_layout_t *b);
static void extents_cleanup(struct fiemap_extent_info *fei);

void
nfsd_bl_init(void)
{
	int	i;
	dprintk("%s loaded\n", __func__);

	spin_lock_init(&layout_hashtbl_lock);
	INIT_LIST_HEAD(&layout_hash);
	for (i = 0; i < BL_LAYOUT_HASH_SIZE; i++)
		INIT_LIST_HEAD(&layout_hashtbl[i]);
	bl_init_proc();
}

/*
 * pnfs_block_enabled -- check to see if this file system should be export as
 * block pnfs
 */
bool
pnfs_block_enabled(struct inode *inode, int ex_flags)
{
	bl_comm_msg_t	msg;
	bl_comm_res_t	*res	= NULL;
	static int bl_comm_once	= 0;
	
	dprintk("--> %s\n", __func__);
	/*
	 * FIXME: Figure out method to determine if this file system should
	 * be exported. The following areas need to be checked.
	 * (1) Validate that this file system was exported as a pNFS
	 *     block-layout
	 * (2) Has there been successful communication with the
	 *     volume daemon?
	 */
	/* Check #1 */
#ifdef notyet
	if (!(ex_flags & NFSEXP_PNFS_BLOCK)) {
		dprintk("%s: pnfs_block not set in export\n", __func__);
		return false;
	}
#endif
	
	/* Check #1 */
	if (!bl_comm_once) {
		msg.msg_type = PNFS_UPCALL_MSG_VERS;
		msg.u.msg_vers = PNFS_UPCALL_VERS;
		if (bl_upcall(bl_comm_global, &msg, &res)) {
			dprintk("%s: Failed to contact pNFS block daemon\n",
				__func__);
			return false;
		}
		if (msg.u.msg_vers != res->u.vers) {
			dprintk("%s: vers mismatch, kernel != daemon\n",
				__func__);
			kfree(res);
			return false;
		}
	}
	bl_comm_once = 1;

	kfree(res);
	
	dprintk("<-- %s okay\n", __func__);
	return true;
}

int
bl_layout_type(struct super_block *sb)
{
	dprintk("%s --> %d\n", __func__, LAYOUT_BLOCK_VOLUME);
	return LAYOUT_BLOCK_VOLUME;
}

int
bl_getdeviceiter(struct super_block *sb,
		 u32 layout_type,
		 struct nfsd4_pnfs_dev_iter_res *res)
{
	res->gd_eof = 1;	
	if (res->gd_cookie)
		return -ENOENT;
	res->gd_devid	= sb->s_dev;
	res->gd_verf	= 1;
	res->gd_cookie	= 1;
	return 0;
}

static int
bl_getdeviceinfo_slice(struct super_block *sb, struct exp_xdr_stream *xdr,
		       const struct nfsd4_pnfs_deviceid *devid)
{
	pnfs_blocklayout_devinfo_t	*bld_slice_p,
					*bld_simple_p,
					*bld;
	int				status		= -EIO,
					location	= 0;
	struct list_head		volumes;
	
	dprintk("--> %s\n", __func__);
	INIT_LIST_HEAD(&volumes);

	bld_simple_p = bld_simple(&volumes, devid->devid,
				  location++);
	if (!bld_simple_p)
		goto out;
	bld_slice_p = bld_slice(&volumes, devid->devid, location++,
	    bld_simple_p->bld_index_loc);

	if (!bld_slice_p)
		goto out;
	
	status = blocklayout_encode_devinfo(xdr, &volumes);

out:
	while (!list_empty(&volumes)) {
		bld = list_entry(volumes.next, pnfs_blocklayout_devinfo_t,
		    bld_list);
		if (bld->bld_type == PNFS_BLOCK_VOLUME_SIMPLE)
			kfree(bld->u.simple.bld_sig);
		bld_free(bld);
	}
	
	dprintk("<-- %s (rval %d)\n", __func__, status);
	return status;
}

static int
bl_getdeviceinfo_dm(struct super_block *sb, struct exp_xdr_stream *xdr,
		    const struct nfsd4_pnfs_deviceid *devid)
{
	pnfs_blocklayout_devinfo_t	*bld		= NULL;
	int				status		= -EIO,	// default to error
					i,
					location	= 0;
	struct list_head		volumes;
	bl_comm_msg_t			msg;
	bl_comm_res_t			*res;
	
	dprintk("--> %s\n", __func__);
	INIT_LIST_HEAD(&volumes);
	
	msg.msg_type = PNFS_UPCALL_MSG_DMGET;
	msg.u.msg_dev = devid->devid;
	if (bl_upcall(bl_comm_global, &msg, &res)) {
		dprintk("%s: upcall for DMGET failed\n", __func__);
		goto out;
	}
		
	/*
	 * Don't use bld_alloc() here. If used this will be the first volume
	 * type added to the list whereas the protocol requires it to be the
	 * last.
	 */
	bld = kmalloc(sizeof (*bld), GFP_KERNEL);
	if (!bld)
		goto out;
	memset(bld, 0, sizeof (*bld));
	bld->bld_type			= PNFS_BLOCK_VOLUME_STRIPE;
	bld->u.stripe.bld_stripes	= res->u.stripe.num_stripes;
	bld->u.stripe.bld_chunk_size	= _2BYTES(res->u.stripe.stripe_size);
	dprintk("%s: stripes %d, chunk_size %Lu\n", __func__,
	    bld->u.stripe.bld_stripes, _2SECTS(bld->u.stripe.bld_chunk_size));
	
	bld->u.stripe.bld_stripe_indexs = kmalloc(bld->u.stripe.bld_stripes *
						  sizeof (int), GFP_KERNEL);
	if (!bld->u.stripe.bld_stripe_indexs)
		goto out;

	for (i = 0; i < bld->u.stripe.bld_stripes; i++) {
		dev_t			dev;
		pnfs_blocklayout_devinfo_t	*bldp;
		
		dev = MKDEV(res->u.stripe.devs[i].major,
			    res->u.stripe.devs[i].minor);
		if (dev == 0)
			goto out;
		
		bldp = bld_simple(&volumes, dev, location++);
		if (!bldp) {
			dprintk("%s: bld_simple failed\n", __func__);
			goto out;
		}
		bldp = bld_slice(&volumes, dev, location++, bldp->bld_index_loc);

		if (!bldp) {
			dprintk("%s: bld_slice failed\n", __func__);
			goto out;
		}
		bld->u.stripe.bld_stripe_indexs[i] = bldp->bld_index_loc;

	}
	list_add_tail(&bld->bld_list, &volumes);
	status = blocklayout_encode_devinfo(xdr, &volumes);
	
out:
	while (!list_empty(&volumes)) {
		bld = list_entry(volumes.next, pnfs_blocklayout_devinfo_t,
		    bld_list);
		switch (bld->bld_type) {
			case PNFS_BLOCK_VOLUME_SLICE:
			case PNFS_BLOCK_VOLUME_CONCAT:
				// No memory to release for these
				break;
			case PNFS_BLOCK_VOLUME_SIMPLE:
				kfree(bld->u.simple.bld_sig);
				break;
			case PNFS_BLOCK_VOLUME_STRIPE:
				kfree(bld->u.stripe.bld_stripe_indexs);
				break;
		}
		bld_free(bld);
	}
	kfree(res);
	dprintk("<-- %s (rval %d)\n", __func__, status);
	return status;
}

/*
 * bl_getdeviceinfo -- determine device tree for requested devid
 */
int
bl_getdeviceinfo(struct super_block *sb, struct exp_xdr_stream *xdr,
		 u32 layout_type,
		 const struct nfsd4_pnfs_deviceid *devid)
{
	if (device_slice(devid->devid) == True)
		return bl_getdeviceinfo_slice(sb, xdr, devid);
	else if (device_dm(devid->devid) == True)
		return bl_getdeviceinfo_dm(sb, xdr, devid);
	return -EINVAL;
}

enum nfsstat4
bl_layoutget(struct inode *i, struct exp_xdr_stream *xdr,
	     const struct nfsd4_pnfs_layoutget_arg *arg,
	     struct nfsd4_pnfs_layoutget_res *res)
{
	pnfs_blocklayout_layout_t	*b;
	bl_layout_rec_t			*r;
	struct list_head		bl_possible,
					*bl_candidates	= NULL;
	boolean_t			del_on_error	= False;
	int				adj;
	enum nfsstat4			nfserr		= NFS4_OK;
	
	dprintk("--> %s (inode=[0x%x:%lu], offset=%Lu, len=%Lu, iomode=%d)\n",
	    __func__, i->i_sb->s_dev, i->i_ino, _2SECTS(res->lg_seg.offset),
	    _2SECTS(res->lg_seg.length), res->lg_seg.iomode);

	if (res->lg_seg.length == 0) {
		printk("%s: request length of 0, error condition\n", __func__);
		return NFS4ERR_BADLAYOUT;
	}
	
	/*
	 * Adjust the length as required per spec.
	 * - First case is were the length is set to (u64)-1. Cheap means to
	 *   define the end of the file.
	 * - Second case is were the I/O mode is read-only, but the request is
	 *   past the end of the file so the request needs to be trimed.
	 */
	if ((res->lg_seg.length == NFS4_MAX_UINT64) ||
	    (((res->lg_seg.offset + res->lg_seg.length) > i->i_size) &&
	     (res->lg_seg.iomode == IOMODE_READ)))
		res->lg_seg.length = i->i_size - res->lg_seg.offset;
	
	adj = res->lg_seg.offset & ~BL_SECT_MASK;
	res->lg_seg.offset -= adj;
	res->lg_seg.length = BL_SECT_ALIGN(res->lg_seg.length + adj);

	if (res->lg_seg.iomode != IOMODE_READ)
		if (i->i_op->fallocate(i, FALLOC_FL_KEEP_SIZE,
				       res->lg_seg.offset, res->lg_seg.length))
			return NFS4ERR_IO;
		
	INIT_LIST_HEAD(&bl_possible);
	
	if ((r = layout_inode_find(i)) == NULL) {
		if (layout_inode_add(i, &r) == False) {
			printk("%s: layout_inode_add failed\n", __func__);
			return NFS4ERR_IO;
		}
		del_on_error = True;
	}
	BUG_ON(!r);
	
	mutex_lock(&r->blr_lock);
	
	if (layout_cache_fill_from(r, &bl_possible, &res->lg_seg)) {
		/*
		 * This will send LAYOUTTRYAGAIN error to the client.
		 */
		dprintk("%s: layout_cache_fill_from() failed\n", __func__);
		nfserr = NFS4ERR_LAYOUTTRYLATER;
		goto layoutget_cleanup;
	}
	
	res->lg_return_on_close	= 1;
	res->lg_seg.length	= 0;
	
	bl_candidates = layout_cache_iter(i->i_sb, r, &bl_possible, &res->lg_seg);
	if (!bl_candidates) {
		nfserr = NFS4ERR_LAYOUTTRYLATER;
		goto layoutget_cleanup;
	}
	
	layout_cache_merge(r, bl_candidates);
	if (layout_cache_update(r, bl_candidates)) {
		/* ---- Failed to allocate memory. ---- */
		dprintk("%s: layout_cache_update() failed\n", __func__);
		nfserr = NFS4ERR_LAYOUTTRYLATER;
		goto layoutget_cleanup;
	}
	
	nfserr = blocklayout_encode_layout(xdr, bl_candidates);
	if (nfserr)
		dprintk("%s: layoutget xdr routine failed\n", __func__);
	
layoutget_cleanup:
	if (bl_candidates) {
		while (!list_empty(bl_candidates)) {
			b = list_entry(bl_candidates->next,
			    struct pnfs_blocklayout_layout, bll_list);
			list_del(&b->bll_list);
			kfree(b);
		}
	}

	mutex_unlock(&r->blr_lock);
	if (unlikely(nfserr)) {
		if (del_on_error == True)
			layout_inode_del(i);
		res->lg_seg.length = 0;
		res->lg_seg.offset = 0;
	}
	
	dprintk("<-- %s (rval %u)\n", __func__, nfserr);
	return nfserr;
}

/*
 * bl_layoutcommit -- commit changes, especially size, to file systemj
 *
 * Currently this routine isn't called and everything is handled within
 * nfsd4_layoutcommit(). By not calling this routine the server doesn't
 * handle a partial return, a set of extents, of the layout. The extents
 * are decoded here, but nothing is done with them. If this routine is
 * be called the interface must change to pass the 'dentry' pointer such
 * that notify_change() can be called.
 */
int
bl_layoutcommit(struct inode *i,
		const struct nfsd4_pnfs_layoutcommit_arg *args,
		struct nfsd4_pnfs_layoutcommit_res *res)
{
	bl_layout_rec_t			*r;
	int				status	= 0;
	u64				lw_plus;
	
	dprintk("--> %s (ino [0x%x:%lu])\n", __func__, i->i_sb->s_dev, i->i_ino);
	r = layout_inode_find(i);
	if (r) {
		lw_plus = args->lc_last_wr + 1;
		if (args->lc_newoffset) {
			dprintk("  lc_last_wr %Lu\n", lw_plus);
			if (r->blr_orig_size < lw_plus) {
				r->blr_orig_size	= lw_plus;
				res->lc_size_chg	= 1;
				res->lc_newsize		= lw_plus;
			}
		}

		if (args->lc_up_len) {
			int	extents,
				i;
			struct pnfs_blocklayout_layout *b;
			__be32 *p = args->lc_up_layout;
			
			/*
			 * Client is returning a set of extents which
			 * should/could be used to update the file system.
			 * See section 2.3.2 in draft-ietf-nfsv4-pnfs-block-08
			 */
			READ32(extents);
			dprintk("  Client returning %d extents: data size %d\n",
			    extents, args->lc_up_len);
			b = kmalloc(sizeof (struct pnfs_blocklayout_layout) *
				    extents, GFP_KERNEL);
			if (b) {
				for (i = 0; i < extents; i++) {
					READ64(b[i].bll_vol_id.sbid);
					READ64(b[i].bll_vol_id.devid);
					READ64(b[i].bll_foff);
					READ64(b[i].bll_len);
					READ64(b[i].bll_soff);
					READ32(b[i].bll_es);
					dprintk("  %d: foff %Lu, len %Lu, soff %Lu "
					    "state %s\n",
					    i, _2SECTS(b[i].bll_foff),
					    _2SECTS(b[i].bll_len),
					    _2SECTS(b[i].bll_soff),
					    map_state2name(b[i].bll_es));
				}
				kfree(b);
			} else {
				status = -ENOMEM;
			}
		}
	} else
		dprintk("%s: Unexpected commit to inode %p\n", __func__, i);
	
	dprintk("<-- %s (rval %d)\n", __func__, status);
	return status;
}

int
bl_layoutreturn(struct inode *i,
		const struct nfsd4_pnfs_layoutreturn_arg *args)
{
	int				status	= 0;
	bl_layout_rec_t			*r;

	dprintk("--> %s (ino [0x%x:%lu])\n", __func__, i->i_sb->s_dev, i->i_ino);
	
	r = layout_inode_find(i);
	if (r) {
		mutex_lock(&r->blr_lock);
		layout_cache_del(r, &args->lr_seg);
		mutex_unlock(&r->blr_lock);
		dprintk("    ext_size %Lu, i_size %Lu, orig_size %Lu\n",
		    r->blr_ext_size, i->i_size, r->blr_orig_size);
	}

	layout_inode_del(i);
	dprintk("<-- %s (rval %d)\n", __func__, status);
	return status;
}

int
bl_layoutrecall(struct inode *inode, int type, u64 offset, u64 len, bool with_nfs4_state_lock)
{
	struct super_block		*sb;
	struct nfsd4_pnfs_cb_layout	lr;
	bl_layout_rec_t			*r;
	pnfs_blocklayout_layout_t	*b;
	u64				adj;
	
	dprintk("--> %s\n", __func__);
	BUG_ON(!len);
	switch (type) {
		case RETURN_FILE:
			sb = inode->i_sb;
			dprintk("  recalling layout [0x%x:%lu], %Lu:%Lu\n",
			    inode->i_sb->s_dev, inode->i_ino,
				_2SECTS(offset), _2SECTS(len));
			break;
		case RETURN_FSID:
			sb = inode->i_sb;
			dprintk("%s: recalling layout for fsid x (unimplemented)\n",
				__func__);
			return 0;
		case RETURN_ALL:
			/*
			 * XXX figure out how to get a sb since there's no
			 * inode ptr
			 */
			dprintk("%s: recalling all layouts (unimplemented)\n",
				__func__);
			return 0;
		default:
			return -EINVAL;
	}
	
restart:
	r = layout_inode_find(inode);
	if (r && len && !r->blr_recalled) {
		mutex_lock(&r->blr_lock);
		list_for_each_entry(b, &r->blr_layouts, bll_list) {
			if (!r->blr_recalled && !b->bll_recalled &&
			    (offset >= b->bll_foff) && (offset < BLL_F_END(b))) {
				b->bll_recalled		= 1;
				lr.cbl_recall_type	= type;
				lr.cbl_seg.layout_type	= LAYOUT_BLOCK_VOLUME;
				lr.cbl_seg.clientid	= 0;
				lr.cbl_seg.offset	= 0;
				lr.cbl_seg.length	= NFS4_MAX_UINT64;
				r->blr_recalled		= 1;
				dprintk("  FULL LAYOUTRECALL\n");
				lr.cbl_seg.iomode = IOMODE_ANY;

				/*
				 * Currently there are only two cases where the
				 * layout is being returned.
				 *    (1) Someone is issuing a NFS_WRITE operation
				 *        to this layout.
				 *    (2) The file has been truncated which means
				 *        the layout is immediately made invalid.
				 * In both cases the client must write any
				 * uncommitted modifications to the server via
				 * NFS_WRITE.
				 */
				lr.cbl_layoutchanged = 1;

				/*
				 * Need to drop the lock because we'll get a
				 * layoutreturn which will block waiting for
				 * the lock. The request will come in on the
				 * same thread which will cause a deadlock.
				 */
				mutex_unlock(&r->blr_lock);
				_nfsd_layout_recall_cb(sb, inode, &lr, with_nfs4_state_lock);
				adj = MIN(b->bll_len - (offset - b->bll_foff),
				    len);
				offset += adj;
				len -= adj;
				if (!len) {
					mutex_lock(&r->blr_lock);
					break;
				}
				/*
				 * Since layoutreturn will have been called we
				 * can't assume blr_layouts is still valid,
				 * so restart.
				 */
				goto restart;
			}
		}
		mutex_unlock(&r->blr_lock);
	}
	
	dprintk("<-- %s\n", __func__);
	return 0;
}

/*
 * []------------------------------------------------------------------[]
 * | Support functions from here on down.				|
 * []------------------------------------------------------------------[]
 */

/*
 * bld_simple -- given a dev_t build a simple volume structure
 *
 * Simple volume contains the device signature and offset to that data in
 * the storage volume.
 */
static pnfs_blocklayout_devinfo_t *
bld_simple(struct list_head *volumes, dev_t devid, int local_index)
{
	pnfs_blocklayout_devinfo_t	*bld	= NULL;
	bl_comm_msg_t			msg;
	bl_comm_res_t			*res	= NULL;
	
	msg.msg_type = PNFS_UPCALL_MSG_GETSIG;
	msg.u.msg_dev = devid;
	if (bl_upcall(bl_comm_global, &msg, &res)) {
		dprintk("%s: Failed to get signature information\n", __func__);
		goto error;
	}
	
	bld = bld_alloc(volumes, PNFS_BLOCK_VOLUME_SIMPLE);
	if (!bld)
		return NULL;
	
	bld->u.simple.bld_offset = _2BYTES(res->u.sig.sector) + res->u.sig.offset;
	bld->u.simple.bld_sig_len = res->u.sig.len;
	bld->u.simple.bld_sig = kmalloc(res->u.sig.len, GFP_KERNEL);
	if (!bld->u.simple.bld_sig)
		goto error;
	
	memcpy(bld->u.simple.bld_sig, res->u.sig.sig, res->u.sig.len);
	kfree(res);
	return bld;
	
error:
	if (bld)
		bld_free(bld);
	if (res)
		kfree(res);
	dprintk("%s: error in bld_simple\n", __func__);
	return NULL;
}

/*
 * bld_slice -- given a dev_t build a slice volume structure
 *
 * A slice volume contains the length of the slice/partition and its offset
 * from the beginning of the storage volume. There's also a reference to
 * the "simple" volume which contains this slice.
 */
static pnfs_blocklayout_devinfo_t *
bld_slice(struct list_head *volumes, dev_t devid, int my_loc, int simple_loc)
{
	pnfs_blocklayout_devinfo_t	*bld;
	bl_comm_msg_t			msg;
	bl_comm_res_t			*res;
	
	dprintk("--> %s\n", __func__);
	bld = bld_alloc(volumes, PNFS_BLOCK_VOLUME_SLICE);
	if (!bld)
		return NULL;
	
	msg.msg_type	= PNFS_UPCALL_MSG_GETSLICE;
	msg.u.msg_dev	= devid;
	if (bl_upcall(bl_comm_global, &msg, &res)) {
		dprintk("Upcall to get slice info failed\n");
		bld_free(bld);
		return NULL;
	}
	
	bld->bld_devid.devid = devid;
	bld->bld_index_loc	= my_loc;
	bld->u.slice.bld_start	= _2BYTES(res->u.slice.start);
	bld->u.slice.bld_len	= _2BYTES(res->u.slice.length);
	bld->u.slice.bld_index	= simple_loc;

	dprintk("%s: start %Lu, len %Lu\n", __func__,
		_2SECTS(bld->u.slice.bld_start), _2SECTS(bld->u.slice.bld_len));

	kfree(res);
	dprintk("<-- %s (rval %p)\n", __func__, bld);
	return bld;
}

static int
layout_cache_fill_from(bl_layout_rec_t *r, struct list_head *h,
    struct nfsd4_layout_seg *seg)
{
	pnfs_blocklayout_layout_t	*n;
	
	dprintk("--> %s\n", __func__);
	
	if (!list_empty(&r->blr_layouts))
		if (layout_cache_fill_from_list(r, h, seg) == False)
			return -EIO;
	
	/*
	 * This deals with two conditions.
	 *    (1) When blr_layouts is empty we need to create the first entry
	 *    (2) When the range requested falls past the end of any current
	 *        layout the residual must be taken care of.
	 */	
	if (seg->length) {
		n = bll_alloc(seg->offset, seg->length, BLOCK_LAYOUT_NEW, h);
		if (!n)
			return -ENOMEM;
		dprintk("  remaining at %Lu, len %Lu\n", _2SECTS(n->bll_foff),
			_2SECTS(n->bll_len));
	}
	
	dprintk("<-- %s\n", __func__);
	return 0;
}

struct list_head *
layout_cache_iter(struct super_block *sb, bl_layout_rec_t *r,
		  struct list_head *bl_possible, struct nfsd4_layout_seg *seg)
{
	pnfs_blocklayout_layout_t	*b,
					*n		= NULL;
	struct list_head		*bl_candidates	= NULL;
	struct fiemap_extent_info	fei;
	struct inode			*i;
	dev_t				dev;
	u64				sbid = find_sbid(sb);
	
	dev	= r->blr_rdev;
	i	= r->blr_inode;
	
	dprintk("--> %s\n", __func__);
	bl_candidates = kmalloc(sizeof (*bl_candidates), GFP_KERNEL);
	if (!bl_candidates)
		return NULL;
	INIT_LIST_HEAD(bl_candidates);
	extents_setup(&fei);
	
	list_for_each_entry(b, bl_possible, bll_list) {
		if (b->bll_cache_state == BLOCK_LAYOUT_NEW) {
			
			extents_count(&fei, i, b->bll_foff, b->bll_len);
			if (fei.fi_extents_mapped) {
				
				/*
				 * Common case here. Got a range which has
				 * extents. Now get those extents and process
				 * them into pNFS extents.
				 */
				if (extents_get(&fei, i, b->bll_foff,
				    b->bll_len) == False)
					goto cleanup;
				if (extents_process(&fei, bl_candidates,
						    seg, sbid, dev, b) == False)
					goto cleanup;
				extents_cleanup(&fei);
				
			} else if (seg->iomode == IOMODE_READ) {
				
				/*
				 * Found a hole in a file while reading. No 
				 * problem, just create a pNFS extent for the
				 * range and let the client know there's no
				 * backing store.
				 */
				n = bll_alloc(b->bll_foff, b->bll_len,
				    BLOCK_LAYOUT_NEW, bl_candidates);
				n->bll_es = PNFS_BLOCK_NONE_DATA;
				n->bll_vol_id.sbid = sbid;
				n->bll_vol_id.devid = dev;
				seg->length += b->bll_len;
			} else {
				
				/*
				 * There's a problem here. Since the iomode
				 * is read/write fallocate should have allocated
				 * any necessary storage for the given range.
				 */
				dprintk("    Extent count for RW is 0\n");
				goto cleanup;
			}
			
		} else {
			n = bll_alloc_dup(b, b->bll_cache_state, bl_candidates);
			seg->length += n->bll_len;
		}

		if (r->blr_ext_size < (b->bll_foff + b->bll_len))
			r->blr_ext_size = b->bll_foff + b->bll_len;
	}
	
	while (!list_empty(bl_possible)) {
		b = list_entry(bl_possible->next,
		    struct pnfs_blocklayout_layout, bll_list);
		list_del(&b->bll_list);
		kfree(b);
	}
		
	b = list_first_entry(bl_candidates, struct pnfs_blocklayout_layout,
	    bll_list);
	seg->offset = b->bll_foff;
	dprintk("<-- %s okay\n", __func__);
	return bl_candidates;
	
cleanup:
	extents_cleanup(&fei);
	if (bl_candidates)
		kfree(bl_candidates);
	dprintk("<-- %s, error occurred\n", __func__);
	return NULL;
}

/*
 * layout_cache_merge -- collapse layouts which make up a contiguous range.
 */
static void
layout_cache_merge(bl_layout_rec_t *r, struct list_head *h)
{
	pnfs_blocklayout_layout_t	*b,
					*p;
	
	dprintk("--> %s\n", __func__);
restart:
	p = NULL;
	list_for_each_entry(b, h, bll_list) {
		if (p && (BLL_S_END(p) == b->bll_soff) &&
		    (p->bll_es == b->bll_es) &&
		    (b->bll_es != PNFS_BLOCK_NONE_DATA)) {
			/*
			 * We've got a condidate.
			 */
#ifdef too_verbose
			dprintk("  merge %Lu(f):%Lu(l):%Lu(s) into %Lu(f):%Lu(l):%Lu(s)\n",
				_2SECTS(b->bll_foff), _2SECTS(b->bll_len),
				_2SECTS(b->bll_soff),
				_2SECTS(p->bll_foff), _2SECTS(p->bll_len),
				_2SECTS(b->bll_soff));
#endif
			
			if (p->bll_cache_state == BLOCK_LAYOUT_CACHE)
				p->bll_cache_state = BLOCK_LAYOUT_UPDATE;
			p->bll_len += b->bll_len;
			list_del(&b->bll_list);
			kfree(b);
			goto restart;
		} else if (p && (BLL_F_END(p) == b->bll_foff) &&
			   (p->bll_es == b->bll_es) &&
			   (b->bll_es == PNFS_BLOCK_NONE_DATA)) {
			p->bll_len += b->bll_len;
			list_del(&b->bll_list);
			kfree(b);
			goto restart;
		} else
			p = b;
	}
	dprintk("<-- %s\n", __func__);
}

static int
layout_cache_update(bl_layout_rec_t *r, struct list_head *h)
{
	pnfs_blocklayout_layout_t	*b,
					*c,
					*n;
	boolean_t			status = 0;
	
	dprintk("--> %s\n", __func__);
	if (list_empty(&r->blr_layouts)) {
		/* ---- Just add entries and return ---- */
		dprintk("  cache empty for inode 0x%x:%ld\n", r->blr_rdev,
			r->blr_inode->i_ino);
		list_for_each_entry(b, h, bll_list) {
			c = bll_alloc_dup(b, BLOCK_LAYOUT_CACHE,
					  &r->blr_layouts);
			if (!c) {
				status = -ENOMEM;
				break;
			}
			dprintk("    adding %Lu(f):%Lu(l):%Lu(s):%d\n",
				_2SECTS(c->bll_foff), _2SECTS(c->bll_len),
				_2SECTS(c->bll_soff), c->bll_es);
		}
		return status;
	}
	
	list_for_each_entry(b, h, bll_list) {
		BUG_ON(!b->bll_vol_id.devid);
		if (b->bll_cache_state == BLOCK_LAYOUT_UPDATE) {
			boolean_t found = False;
			list_for_each_entry(c, &r->blr_layouts, bll_list) {
				if ((b->bll_soff >= c->bll_soff) &&
				    (b->bll_soff < BLL_S_END(c)) &&
				    (b->bll_es != PNFS_BLOCK_NONE_DATA)) {
					u64	u;
					
					if ((b->bll_foff < c->bll_foff) ||
					    (b->bll_foff > BLL_F_END(c)))
						BUG();
					
					u = BLL_S_END(b) - BLL_S_END(c);
					/*
					 * The updated cache entry has to be
					 * different than the current.
					 * Otherwise the cache state for 'b'
					 * should be BLOCK_LAYOUT_CACHE.
					 */
					BUG_ON(BLL_S_END(b) < BLL_S_END(c));
					
					dprintk("  "
						"updating %Lu(f):%Lu(l):%Lu(s) to len %Lu\n",
						_2SECTS(c->bll_foff),
						_2SECTS(c->bll_len),
						_2SECTS(c->bll_soff),
						_2SECTS(c->bll_len + u));
					c->bll_len += u;
					bll_collapse(r, c);
					found = True;
					break;
				}
			}

			if (found == False) {
				dprintk("  ERROR Expected to find"
				    " %Lu(f):%Lu(l):%Lu(s), but didn't\n",
				    _2SECTS(b->bll_foff), _2SECTS(b->bll_len),
				    _2SECTS(b->bll_soff));
				list_for_each_entry(c, &r->blr_layouts, bll_list)
					print_bll(c, "Cached");
				BUG();
			}
		} else if (b->bll_cache_state == BLOCK_LAYOUT_NEW) {
			
			c = list_first_entry(&r->blr_layouts,
			    struct pnfs_blocklayout_layout, bll_list);
			if (b->bll_foff < c->bll_foff) {
				/*
				 * Special case where new entry is before
				 * first cached entry.
				 */
				c = bll_alloc_dup(b, BLOCK_LAYOUT_CACHE, NULL);
				list_add(&c->bll_list, &r->blr_layouts);
				dprintk("  new entry at head of list at %Lu, "
					"len %Lu\n",
					_2SECTS(c->bll_foff), _2SECTS(c->bll_len));
			} else {
				list_for_each_entry(c, &r->blr_layouts,
				    bll_list) {
					n = list_entry(c->bll_list.next,
					    struct pnfs_blocklayout_layout,
					    bll_list);
					/*
					 * This is ugly, but can't think of
					 * another way to examine this case.
					 * Consider the following. Need to
					 * add an entry which starts at 40
					 * and the cache has the following
					 * entries:
					 * Start    Length
					 * 10       5
					 * 30       5
					 * 50       5
					 * So, need to look and see if the new
					 * entry starts after the current
					 * cache, but before the next one.
					 * There's a catch in that the next
					 * entry might not be valid as it's
					 * really just a pointer to the list
					 * head.
					 */
					if (((b->bll_foff >=
					      BLL_F_END(c)) &&
					     (c->bll_list.next == &r->blr_layouts)) ||
					    ((b->bll_foff >=
					      BLL_F_END(c)) &&
					     (b->bll_foff < n->bll_foff))) {
						
						n = bll_alloc_dup(b,
								  BLOCK_LAYOUT_CACHE, NULL);
						dprintk("  adding new %Lu:%Lu"
							" after %Lu:%Lu\n",
							_2SECTS(n->bll_foff),
							_2SECTS(n->bll_len),
							_2SECTS(c->bll_foff),
							_2SECTS(c->bll_len));
						list_add(&n->bll_list,
							 &c->bll_list);
						break;
					}
				}
			}
		}
	}
	dprintk("<-- %s\n", __func__);
	return status;
}

static void
layout_cache_del(bl_layout_rec_t *r, const struct nfsd4_layout_seg *seg_in)
{
	struct pnfs_blocklayout_layout	*b,
					*n;
	u64				len;
	struct nfsd4_layout_seg		seg = *seg_in;
	
	dprintk("--> %s\n", __func__);
	if (seg.length == NFS4_MAX_UINT64) {
		r->blr_recalled = 0;
		dprintk("  Fast return of all layouts\n");
		while (!list_empty(&r->blr_layouts)) {
			b = list_entry(r->blr_layouts.next,
				       struct pnfs_blocklayout_layout, bll_list);
			dprintk("    foff %Lu, len %Lu, soff %Lu\n",
				_2SECTS(b->bll_foff), _2SECTS(b->bll_len),
				_2SECTS(b->bll_soff));
			list_del(&b->bll_list);
			kfree(b);
		}
		dprintk("<-- %s\n", __func__);
		return;
	}

restart:
	list_for_each_entry(b, &r->blr_layouts, bll_list) {
		if (seg.offset == b->bll_foff) {
			/*
			 * This handle the following three cases:
			 * (1) return layout matches entire cache layout
			 * (2) return layout matches beginning portion of cache
			 * (3) return layout matches entire cache layout and
			 *     into next entry. Varies from #1 in end case.
			 */
			dprintk("  match on offsets, %Lu:%Lu\n",
				_2SECTS(seg.offset), _2SECTS(seg.length));
			len = MIN(seg.length, b->bll_len);
			b->bll_foff	+= len;
			b->bll_soff	+= len;
			b->bll_len	-= len;
			seg.length	-= len;
			seg.offset	+= len;
			if (!b->bll_len) {
				list_del(&b->bll_list);
				kfree(b);
				dprintk("    removing cache line\n");
				if (!seg.length) {
					dprintk("    also finished\n");
					goto complete;
				}
				/*
				 * Since 'b' was freed we can't continue at the
				 * next entry which is referenced as
				 * b->bll_list.next by the list_for_each_entry
				 * macro. Need to restart the loop.
				 * TODO: Think about creating a dummy 'b' which
				 *       would keep list_for_each_entry() happy.
				 */
				goto restart;
			}
			if (!seg.length) {
				dprintk("    finished, but cache line not"
					"empty\n");
				goto complete;
			}
		} else if ((seg.offset >= b->bll_foff) &&
		    (seg.offset < BLL_F_END(b))) {
			/*
			 * layout being returned is within this cache line.
			 */
			dprintk("  layout %Lu:%Lu within cache line %Lu:%Lu\n",
				_2SECTS(seg.offset), _2SECTS(seg.length),
				_2SECTS(b->bll_foff), _2SECTS(b->bll_len));
			BUG_ON(!seg.length);
			if ((seg.offset + seg.length) >= BLL_F_END(b)) {
				/*
				 * Layout returned starts in the middle of
				 * cache entry and just need to trim back
				 * cache to shorter length.
				 */
				dprintk("    trim back cache line\n");
				len = seg.offset - b->bll_foff;
				seg.offset += b->bll_len - len;
				seg.length -= b->bll_len - len;
				b->bll_len = len;
				if (!seg.length)
					return;
			} else {
				/*
				 * Need to split current cache layout because
				 * chunk is being removed from the middle.
				 */
				dprintk("    split cache line\n");
				len = seg.offset + seg.length;
				n = bll_alloc(len,
					      (b->bll_foff + b->bll_len) - len,
					      BLOCK_LAYOUT_CACHE, NULL);
				n->bll_soff = b->bll_soff + len;
				list_add(&n->bll_list, &b->bll_list);
				b->bll_len = seg.offset - b->bll_foff;
				return;
			}
		}
	}
complete:
	if (list_empty(&r->blr_layouts))
		r->blr_recalled = 0;
	dprintk("<-- %s\n", __func__);
}

/*
 * layout_cache_fill_from_list -- fills from cache list
 *
 * NOTE: This routine was only seperated out from layout_cache_file_from()
 * to reduce the indentation level which makes the code easier to read.
 */
static inline boolean_t
layout_cache_fill_from_list(bl_layout_rec_t *r, struct list_head *h,
    struct nfsd4_layout_seg *seg)
{
	pnfs_blocklayout_layout_t	*b,
					*n;
	enum pnfs_block_extent_state4	s;
	u64				sbid = find_sbid(r->blr_inode->i_sb);

	list_for_each_entry(b, &r->blr_layouts, bll_list) {
		if (seg->offset < b->bll_foff) {
			n = bll_alloc(seg->offset,
			    MIN(seg->length, b->bll_foff - seg->offset),
			    BLOCK_LAYOUT_NEW, NULL);
			if (!n)
				return False;
			
			list_add(&n->bll_list, h->prev);
			dprintk("  new: %Lu:%Lu, added before %Lu:%Lu\n",
			    _2SECTS(n->bll_foff), _2SECTS(n->bll_len),
			    _2SECTS(b->bll_foff), _2SECTS(b->bll_len));
			seg->offset += n->bll_len;
			seg->length -= n->bll_len;
			if (!seg->length)
				break;
		}
		
		if ((seg->offset >= b->bll_foff) &&
		    (seg->offset < BLL_F_END(b))) {
			if (layout_conflict(b, seg->iomode, &s) == False) {
				dprintk("  CONFLICT FOUND: "
				    "%Lu(f):%Lu(l):%Lu(s) state %d, iomode %d\n",
				    _2SECTS(b->bll_foff), _2SECTS(b->bll_len),
				    _2SECTS(b->bll_soff), b->bll_es,
				    seg->iomode);
				return False;
			}
			n = bll_alloc(seg->offset,
			    MIN(seg->length, BLL_F_END(b) - seg->offset),
			    BLOCK_LAYOUT_CACHE, h);
			dprintk("  CACHE hit: Found %Lu(f):%Lu(l): "
			    "in %Lu(f):%Lu(l):%Lu(s):%d\n",
			    _2SECTS(n->bll_foff), _2SECTS(n->bll_len),
			    _2SECTS(b->bll_foff), _2SECTS(b->bll_len),
			    _2SECTS(b->bll_soff), b->bll_es);
			if (!n)
				return False;
			
			n->bll_soff = b->bll_soff + seg->offset - b->bll_foff;
			n->bll_vol_id.sbid = sbid;
			n->bll_vol_id.devid = b->bll_vol_id.devid;
			n->bll_es = s;
			seg->offset += n->bll_len;
			seg->length -= n->bll_len;
			if (!seg->length)
				break;
		}
	}
	return True;
}

static u64
bll_alloc_holey(struct list_head *bl_candidates, u64 offset, u64 length,
		u64 sbid, dev_t dev)
{
	pnfs_blocklayout_layout_t	*n;
	
	n = bll_alloc(offset, length, BLOCK_LAYOUT_NEW, bl_candidates);
	if (!n)
		return 0;
	n->bll_es = PNFS_BLOCK_NONE_DATA;
	n->bll_vol_id.sbid = sbid;
	n->bll_vol_id.devid = dev;
	
	return n->bll_len;
}

static void
extents_setup(struct fiemap_extent_info *fei)
{
	fei->fi_extents_start	= NULL;
}

/*
 * extents_count -- Determine the number of extents for a given range.
 *
 * No need to call set_fs() here because the function
 * doesn't use copy_to_user() if it's only counting
 * the number of extents needed.
 */
static void
extents_count(struct fiemap_extent_info *fei, struct inode *i, u64 foff, u64 len)
{
	dprintk("    Need fiemap of %Ld:%Ld\n", _2SECTS(foff), _2SECTS(len));
	fei->fi_flags		= FIEMAP_FLAG_SYNC;
	fei->fi_extents_max	= 0;
	fei->fi_extents_start	= NULL;
	fei->fi_extents_mapped	= 0;
	i->i_op->fiemap(i, fei, foff, len + (1 << i->i_sb->s_blocksize_bits) - 1);
}

/*
 * extents_get -- Get list of extents for range
 *
 * extents_count() must have been called before this routine such that
 * fi_extents_mapped is known.
 */
static boolean_t
extents_get(struct fiemap_extent_info *fei, struct inode *i, u64 foff, u64 len)
{
	int			m_space,
				rval;
	struct fiemap_extent	*fe;
	mm_segment_t		old_fs = get_fs();
	
	/*
	 * Now malloc the correct amount of space
	 * needed. It's possible for the file to have changed
	 * between calls which would require more space for
	 * the extents. If that occurs the last extent will
	 * not have FIEMAP_EXTENT_LAST set and the error will
	 * be caught in extents_process().
	 */
	m_space = fei->fi_extents_mapped * sizeof (struct fiemap_extent);
	fe = kmalloc(m_space, GFP_KERNEL);
	if (!fe)
		return False;
	memset(fe, 0, m_space);
	
	fei->fi_extents_max	= fei->fi_extents_mapped;
	fei->fi_extents_mapped	= 0;
	fei->fi_extents_start	= fe;
	
	set_fs(KERNEL_DS);
	rval = i->i_op->fiemap(i, fei, foff, len +
	    (1 << i->i_sb->s_blocksize_bits) - 1);
	set_fs(old_fs);
	
	if (rval < 0 || !fei->fi_extents_mapped) {
		dprintk("    No extents. Wanted %d, got %d: rval=%d\n",
			fei->fi_extents_max, fei->fi_extents_mapped, rval);
		kfree(fe);
		fei->fi_extents_start = NULL;
		return False;
	} else
		return True;
}

/*
 * extents_process -- runs through the extent returned from the file system and
 *	 creates block layout entries.
 */
static boolean_t
extents_process(struct fiemap_extent_info *fei, struct list_head *bl_candidates,
    struct nfsd4_layout_seg *seg, u64 sbid, dev_t dev, pnfs_blocklayout_layout_t *b)
{
	struct fiemap_extent		*fep,
					*fep_last	= NULL;
	int				i;
	pnfs_blocklayout_layout_t	*n;
	u64				last_end,
					rval;
	
	dprintk("--> %s\n", __func__);
	for (fep = fei->fi_extents_start, i = 0; i < fei->fi_extents_mapped;
	    i++, fep++) {
		
		BUG_ON(!fep->fe_physical);
		/*
		 * Deal with corner cases of hoel-y files.
		 */
		if (fep_last && ((fep_last->fe_logical + fep_last->fe_length) !=
				 fep->fe_logical)) {
			
			/*
			 * If the last extent doesn't end logically
			 * at the beginning of the current we've got
			 * hole and need to create a pNFS extent.
			 */
			dprintk("    Got a hole at %Ld:%Ld \n", 
			    _2SECTS(fep_last->fe_logical),
			    _2SECTS(fep_last->fe_length));
			last_end = fep_last->fe_logical + fep_last->fe_length;
			rval = bll_alloc_holey(bl_candidates, last_end,
			    fep->fe_logical - last_end, sbid, dev);
			if (!rval)
				return False;
			seg->length += rval;
		}
		
		n = bll_alloc(fep->fe_logical, fep->fe_length,
		    BLOCK_LAYOUT_NEW, bl_candidates);
		if (unlikely(n == NULL)) {
			dprintk("%s: bll_alloc failed\n", __func__);
			return False;
		}
		
		n->bll_soff = fep->fe_physical;
		n->bll_es = seg->iomode == IOMODE_READ ?
		    PNFS_BLOCK_READ_DATA : PNFS_BLOCK_READWRITE_DATA;
		n->bll_vol_id.sbid = sbid;
		n->bll_vol_id.devid = dev;
		seg->length += fep->fe_length;
		print_bll(n, "New extent");
		fep_last = fep;
	}
	dprintk("<-- %s (i=%d)\n", __func__, i);
	
	return True;
}

static void
extents_cleanup(struct fiemap_extent_info *fei)
{
	if (fei->fi_extents_start) {
		kfree(fei->fi_extents_start);
		fei->fi_extents_start = NULL;
	}
}

/*
 * device_slice -- check to see if device is a slice or DM
 */
static boolean_t
device_slice(dev_t devid)
{
	struct block_device	*bd	= blkdev_get_by_dev(devid, FMODE_READ, NULL);
	boolean_t		rval	= False;
	
	dprintk("%s: dev_id=%u:%u\n", __func__, MAJOR(devid), MINOR(devid));
	if (!IS_ERR(bd)) {
		dprintk("%s: minors=%d\n", __func__, bd->bd_disk->minors);
		if (bd->bd_disk->minors > 1)
			rval = True;
		blkdev_put(bd, FMODE_READ);
	}
	dprintk("%s: ret=%d\n", __func__, rval);
	return rval;
}

/*
 * device_dm -- check to see if device is a Device Mapper volume.
 *
 * Returns 1 for DM or 0 if not
 */
static boolean_t
device_dm(dev_t devid)
{
	boolean_t		rval = False;
	bl_comm_msg_t		msg;
	bl_comm_res_t		*res;
	
	msg.msg_type	= PNFS_UPCALL_MSG_DMCHK;
	msg.u.msg_dev	= devid;
	if (bl_upcall(bl_comm_global, &msg, &res)) {
		dprintk("Failed upcall to check on DM status\n");
	} else if (res->u.dm_vol) {
		rval = True;
		dprintk("Device is DM volume\n");
	} else
		dprintk("Device is not DM volume\n");
	kfree(res);
	
	return rval;
}

static boolean_t
layout_inode_add(struct inode *i, bl_layout_rec_t **p)
{
	bl_layout_rec_t		*r	= NULL;

	if (!i->i_op->fiemap || !i->i_op->fallocate) {
		printk("pNFS: file system doesn't support required fiemap or"
		    "fallocate methods\n");
		return False;
	}
	
	r = kmalloc(sizeof (*r), GFP_KERNEL);
	if (!r)
		goto error;

	r->blr_rdev	= i->i_sb->s_dev;
	r->blr_inode	= i;
	r->blr_orig_size = i->i_size;
	r->blr_ext_size	= 0;
	r->blr_recalled	= 0;
	INIT_LIST_HEAD(&r->blr_layouts);
	mutex_init(&r->blr_lock);
	spin_lock(&layout_hashtbl_lock);
	list_add_tail(&r->blr_hash, &layout_hash);
	spin_unlock(&layout_hashtbl_lock);
	*p = r;
	return True;
	
error:
	if (r)
		kfree(r);
	return False;
}

static bl_layout_rec_t *
__layout_inode_find(struct inode *i)
{
	bl_layout_rec_t	*r;
	
	if (!list_empty(&layout_hash)) {
		list_for_each_entry(r, &layout_hash, blr_hash) {
			if ((r->blr_inode->i_ino == i->i_ino) &&
			    (r->blr_rdev == i->i_sb->s_dev)) {
				return r;
			}
		}
	}
	return NULL;
}

static bl_layout_rec_t *
layout_inode_find(struct inode *i)
{
	bl_layout_rec_t	*r;

	spin_lock(&layout_hashtbl_lock);
	r = __layout_inode_find(i);
	spin_unlock(&layout_hashtbl_lock);
	
	return r;
}

static void
layout_inode_del(struct inode *i)
{
	bl_layout_rec_t	*r;
	
	spin_lock(&layout_hashtbl_lock);
	r = __layout_inode_find(i);
	if (r) {
		/* FIXME: cannot acquire mutex while holding a spin lock
		 * need kref?
		 */
		if (list_empty(&r->blr_layouts)) {
			list_del(&r->blr_hash);
			kfree(r);
		}
	} else {
		dprintk("%s: failed to find inode [0x%x:%lu] in table for delete\n",
			__func__, i->i_sb->s_dev, i->i_ino);
	}
	spin_unlock(&layout_hashtbl_lock);
}

/*
 * map_state2name -- converts state in ascii string.
 *
 * Used for debug messages only.
 */
static char *
map_state2name(enum pnfs_block_extent_state4 s)
{
	switch (s) {
	case PNFS_BLOCK_READWRITE_DATA:	return "     RW";
	case PNFS_BLOCK_READ_DATA:	return "     RO";
	case PNFS_BLOCK_INVALID_DATA:	return "INVALID";
	case PNFS_BLOCK_NONE_DATA:	return "   NONE";
	default:
		BUG();
	}
}

static pnfs_blocklayout_devinfo_t *
bld_alloc(struct list_head *volumes, int type)
{
	pnfs_blocklayout_devinfo_t *bld;
	
	bld = kmalloc(sizeof (*bld), GFP_KERNEL);
	if (!bld)
		return NULL;

	memset(bld, 0, sizeof (*bld));
	bld->bld_type = type;
	list_add_tail(&bld->bld_list, volumes);

	return bld;
}

static void
bld_free(pnfs_blocklayout_devinfo_t *bld)
{
	list_del(&bld->bld_list);
	kfree(bld);
}

static void
print_bll(pnfs_blocklayout_layout_t *b, char *text)
{
	dprintk("    BLL: %s\n", text);
	dprintk("    foff %Lu, soff %Lu, len %Lu, state %s\n",
	    _2SECTS(b->bll_foff), _2SECTS(b->bll_soff), _2SECTS(b->bll_len),
	    map_state2name(b->bll_es));
}

static inline void
bll_collapse(bl_layout_rec_t *r, pnfs_blocklayout_layout_t *c)
{
	pnfs_blocklayout_layout_t	*n;
	int				dbg_count	= 0;
	u64				endpoint;
	
	BUG_ON(c->bll_es == PNFS_BLOCK_NONE_DATA);
	while (c->bll_list.next != &r->blr_layouts) {
		n = list_entry(c->bll_list.next,
			       struct pnfs_blocklayout_layout, bll_list);
		endpoint = BLL_S_END(c);
		if ((n->bll_soff >= c->bll_soff) &&
		    (n->bll_soff < endpoint)) {
			if (endpoint < BLL_S_END(n)) {
				/*
				 * The following is possible.
				 *
				 * 
				 * Existing: +---+                 +---+
				 *      New: +-----------------------+
				 * The client request merge entries together
				 * but didn't require picking up all of the
				 * last entry. So, we still need to delete
				 * the last entry and add the remaining space
				 * to the new entry.
				 */
				c->bll_len += BLL_S_END(n) - endpoint;
			}
			dbg_count++;
			list_del(&n->bll_list);
			kfree(n);
		} else {
			break;
		}
	}
	/* ---- Debug only, remove before integration ---- */
	if (dbg_count)
		dprintk("  Collapsed %d cache entries between %Lu(s) and %Lu(s)\n",
			dbg_count, _2SECTS(c->bll_soff), _2SECTS(BLL_S_END(c)));
}

static pnfs_blocklayout_layout_t *
bll_alloc(u64 offset, u64 len, enum bl_cache_state state, struct list_head *h)
{
	pnfs_blocklayout_layout_t	*n	= NULL;
	
	n = kmalloc(sizeof (*n), GFP_KERNEL);
	if (n) {
		memset(n, 0, sizeof (*n));
		n->bll_foff		= offset;
		n->bll_len		= len;
		n->bll_cache_state	= state;
		if (h)
			list_add_tail(&n->bll_list, h);
	}
	return n;
}

static pnfs_blocklayout_layout_t *
bll_alloc_dup(pnfs_blocklayout_layout_t *b, enum bl_cache_state c,
	      struct list_head *h)
{
	pnfs_blocklayout_layout_t	*n	= NULL;
	
	n = bll_alloc(b->bll_foff, b->bll_len, c, h);
	if (n) {
		n->bll_es			= b->bll_es;
		n->bll_soff			= b->bll_soff;
		n->bll_vol_id			= b->bll_vol_id;
	}
	return n;
}

static inline boolean_t
layout_conflict(pnfs_blocklayout_layout_t *b, u32 iomode,
		enum pnfs_block_extent_state4 *s)
{
	/* ---- Normal case ---- */
	*s = b->bll_es;
	
	switch (b->bll_es) {
	case PNFS_BLOCK_READWRITE_DATA:
		if (iomode == IOMODE_READ)
			*s = PNFS_BLOCK_READ_DATA;
		/* ---- Any use is permitted. ---- */
		break;
	case PNFS_BLOCK_READ_DATA:
		/* ---- Committed as read only data. ---- */
		if (iomode == IOMODE_RW)
			return False;
		break;
	case PNFS_BLOCK_INVALID_DATA:
		/* ---- Blocks have been allocated, but not initialized ---- */
		if (iomode == IOMODE_READ)
			*s = PNFS_BLOCK_NONE_DATA;
		break;
	case PNFS_BLOCK_NONE_DATA:
		/* ---- Hole-y file. No backing store avail. ---- */
		if (iomode != IOMODE_READ)
			return False;
		break;
	default:
		BUG();
	}
	return True;
}
