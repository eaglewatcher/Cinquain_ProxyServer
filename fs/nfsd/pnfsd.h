/*
 *  Copyright (c) 2005 The Regents of the University of Michigan.
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
 *
 */

#ifndef LINUX_NFSD_PNFSD_H
#define LINUX_NFSD_PNFSD_H

#include <linux/list.h>
#include <linux/nfsd/nfsd4_pnfs.h>

#include "state.h"
#include "xdr4.h"

/* outstanding layout stateid */
struct nfs4_layout_state {
	struct kref		ls_ref;
	struct nfs4_stid	ls_stid;
	struct list_head	ls_perfile;
};

/* outstanding layout */
struct nfs4_layout {
	struct list_head		lo_perfile;	/* hash by f_id */
	struct list_head		lo_perclnt;	/* hash by clientid */
	struct nfs4_file		*lo_file;	/* backpointer */
	struct nfs4_client		*lo_client;
	struct nfs4_layout_state	*lo_state;
	struct nfsd4_layout_seg		lo_seg;
	bool				lo_roc;
};

struct pnfs_inval_state {
	struct knfsd_fh		mdsfh; /* needed only by invalidate all */
	stateid_t		stid;
	clientid_t		clid;
	u32			status;
};

/* pNFS Data Server state */
#define DS_STATEID_VALID   0
#define DS_STATEID_ERROR   1
#define DS_STATEID_NEW     2

struct pnfs_ds_stateid {
	struct list_head	ds_hash;        /* ds_stateid hash entry */
	struct list_head	ds_perclid;     /* per client hash entry */
	stateid_t		ds_stid;
	struct knfsd_fh		ds_fh;
	unsigned long		ds_access;
	u32			ds_status;      /* from MDS */
	u32			ds_verifier[2]; /* from MDS */
	wait_queue_head_t	ds_waitq;
	unsigned long		ds_flags;
	struct kref		ds_ref;
	clientid_t		ds_mdsclid;
};

struct pnfs_ds_clientid {
	struct list_head	dc_hash;        /* mds_clid_hashtbl entry */
	struct list_head	dc_stateid;     /* ds_stateid head */
	struct list_head	dc_permdsid;    /* per mdsid hash entry */
	clientid_t		dc_mdsclid;
	struct kref		dc_ref;
	uint32_t		dc_mdsid;
};

struct pnfs_mds_id {
	struct list_head	di_hash;        /* mds_nodeid list entry */
	struct list_head	di_mdsclid;     /* mds_clientid head */
	uint32_t		di_mdsid;
	time_t			di_mdsboot;	/* mds boot time */
	struct kref		di_ref;
};

/* notify device request (from exported filesystem) */
struct nfs4_notify_device {
	struct nfsd4_pnfs_cb_dev_list  *nd_list;
	struct nfs4_client	       *nd_client;
	struct list_head	        nd_perclnt;

	/* nfsd internal */
	struct nfsd4_callback		nd_recall;
};

u64 find_sbid(struct super_block *);
u64 find_create_sbid(struct super_block *);
struct super_block *find_sbid_id(u64);
__be32 nfs4_pnfs_get_layout(struct nfsd4_pnfs_layoutget *, struct exp_xdr_stream *);
int nfs4_pnfs_return_layout(struct super_block *, struct svc_fh *,
					struct nfsd4_pnfs_layoutreturn *);
int nfs4_pnfs_cb_get_state(struct super_block *, struct pnfs_get_state *);
int nfs4_pnfs_cb_change_state(struct pnfs_get_state *);
void nfs4_ds_get_verifier(stateid_t *, struct super_block *, u32 *);
int put_layoutrecall(struct nfs4_layoutrecall *);
void nomatching_layout(struct nfs4_layoutrecall *);
void *layoutrecall_done(struct nfs4_layoutrecall *);
void nfsd4_cb_layout(struct nfs4_layoutrecall *);
int _nfsd_layout_recall_cb(struct super_block *, struct inode *,
			  struct nfsd4_pnfs_cb_layout *,
			  bool with_nfs4_state_lock);
int nfsd_layout_recall_cb(struct super_block *, struct inode *,
			  struct nfsd4_pnfs_cb_layout *);
int nfsd_device_notify_cb(struct super_block *,
			  struct nfsd4_pnfs_cb_dev_list *);
void nfsd4_cb_notify_device(struct nfs4_notify_device *);
void pnfs_set_device_notify(clientid_t *, unsigned int types);
void pnfs_clear_device_notify(struct nfs4_client *);

#if defined(CONFIG_PNFSD_LOCAL_EXPORT)
extern struct sockaddr_storage pnfsd_lexp_addr;
extern size_t pnfs_lexp_addr_len;

extern void pnfsd_lexp_init(struct inode *);
extern bool is_inode_pnfsd_lexp(struct inode *);
extern int pnfsd_lexp_recall_layout(struct inode *, bool with_nfs4_state_lock);
#endif /* CONFIG_PNFSD_LOCAL_EXPORT */

#endif /* LINUX_NFSD_PNFSD_H */
