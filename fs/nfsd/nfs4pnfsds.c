/*
*  linux/fs/nfsd/nfs4pnfsds.c
*
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
#if defined(CONFIG_PNFSD)

#define NFSDDBG_FACILITY NFSDDBG_PNFS

#include <linux/param.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/debug.h>
#include <linux/nfs4.h>
#include <linux/exportfs.h>
#include <linux/sched.h>

#include "nfsd.h"
#include "pnfsd.h"
#include "state.h"

/*
 * Hash tables for pNFS Data Server state
 *
 * mds_nodeid:	list of struct pnfs_mds_id one per Metadata server (MDS) using
 *		this data server (DS).
 *
 * mds_clid_hashtbl[]: uses clientid_hashval(), hash of all clientids obtained
 *			from any MDS.
 *
 * ds_stid_hashtbl[]: uses stateid_hashval(), hash of all stateids obtained
 *			from any MDS.
 *
 */
/* Hash tables for clientid state */
#define CLIENT_HASH_BITS                 4
#define CLIENT_HASH_SIZE                (1 << CLIENT_HASH_BITS)
#define CLIENT_HASH_MASK                (CLIENT_HASH_SIZE - 1)

#define clientid_hashval(id) \
	((id) & CLIENT_HASH_MASK)

/* hash table for pnfs_ds_stateid */
#define STATEID_HASH_BITS	10
#define STATEID_HASH_SIZE	(1 << STATEID_HASH_BITS)
#define STATEID_HASH_MASK	(STATEID_HASH_SIZE - 1)

static int stateid_hashval(stateid_t *stidp)
{
	unsigned v = stidp->si_opaque.so_clid.cl_boot ^
		     stidp->si_opaque.so_clid.cl_id ^
		     stidp->si_opaque.so_id;
	return v & STATEID_HASH_MASK;
}

static struct list_head mds_id_tbl;
static struct list_head mds_clid_hashtbl[CLIENT_HASH_SIZE];
static struct list_head ds_stid_hashtbl[STATEID_HASH_SIZE];

static void put_ds_clientid(struct pnfs_ds_clientid *dcp);
static void put_ds_mdsid(struct pnfs_mds_id *mdp);

/* Mutex for data server state.  Needs to be separate from
 * mds state mutex since a node can be both mds and ds */
static DEFINE_MUTEX(ds_mutex);
static struct thread_info *ds_mutex_owner;

static void
ds_lock_state(void)
{
	mutex_lock(&ds_mutex);
	ds_mutex_owner = current_thread_info();
}

static void
ds_unlock_state(void)
{
	BUG_ON(ds_mutex_owner != current_thread_info());
	ds_mutex_owner = NULL;
	mutex_unlock(&ds_mutex);
}

static int
cmp_clid(const clientid_t *cl1, const clientid_t *cl2)
{
	return (cl1->cl_boot == cl2->cl_boot) &&
	       (cl1->cl_id == cl2->cl_id);
}

void
nfs4_pnfs_state_init(void)
{
	int i;

	for (i = 0; i < CLIENT_HASH_SIZE; i++)
		INIT_LIST_HEAD(&mds_clid_hashtbl[i]);

	for (i = 0; i < STATEID_HASH_SIZE; i++)
		INIT_LIST_HEAD(&ds_stid_hashtbl[i]);

	INIT_LIST_HEAD(&mds_id_tbl);
}

static struct pnfs_mds_id *
find_pnfs_mds_id(u32 mdsid)
{
	struct pnfs_mds_id *local = NULL;

	dprintk("pNFSD: %s\n", __func__);
	list_for_each_entry(local, &mds_id_tbl, di_hash) {
		if (local->di_mdsid == mdsid)
			return local;
	}
	return NULL;
}

static struct pnfs_ds_clientid *
find_pnfs_ds_clientid(const clientid_t *clid)
{
	struct pnfs_ds_clientid *local = NULL;
	unsigned int hashval;

	dprintk("pNFSD: %s\n", __func__);

	hashval = clientid_hashval(clid->cl_id);
	list_for_each_entry(local, &mds_clid_hashtbl[hashval], dc_hash) {
		if (cmp_clid(&local->dc_mdsclid, clid))
			return local;
	}
	return NULL;
}

/* FIXME: Can we use the server generic idr based stateid bookeeping introduced in 3.2? */
static struct pnfs_ds_stateid *
find_pnfs_ds_stateid(stateid_t *stidp)
{
	struct pnfs_ds_stateid *local = NULL;
	unsigned int hashval;

	dprintk("pNFSD: %s\n", __func__);

	hashval = stateid_hashval(stidp);
	list_for_each_entry(local, &ds_stid_hashtbl[hashval], ds_hash)
		if (!memcmp(&local->ds_stid.si_opaque, &stidp->si_opaque, sizeof(stidp->si_opaque))) {
			stateid_t *sid = &local->ds_stid;
			dprintk("NFSD: %s <-- %p ds_flags %lx " STATEID_FMT "\n",
				__func__, local, local->ds_flags,
				STATEID_VAL(sid));
			return local;
		}
	return NULL;
}

static void
release_ds_mdsid(struct kref *kref)
{
	struct pnfs_mds_id *mdp =
		container_of(kref, struct pnfs_mds_id, di_ref);
	dprintk("pNFSD: %s\n", __func__);

	list_del(&mdp->di_hash);
	list_del(&mdp->di_mdsclid);
	kfree(mdp);
}

static void
release_ds_clientid(struct kref *kref)
{
	struct pnfs_ds_clientid *dcp =
		container_of(kref, struct pnfs_ds_clientid, dc_ref);
	struct pnfs_mds_id *mdp;
	dprintk("pNFSD: %s\n", __func__);

	mdp = find_pnfs_mds_id(dcp->dc_mdsid);
	if (mdp)
		put_ds_mdsid(mdp);

	list_del(&dcp->dc_hash);
	list_del(&dcp->dc_stateid);
	list_del(&dcp->dc_permdsid);
	kfree(dcp);
}

static void
release_ds_stateid(struct kref *kref)
{
	struct pnfs_ds_stateid *dsp =
		container_of(kref, struct pnfs_ds_stateid, ds_ref);
	struct pnfs_ds_clientid *dcp;
	dprintk("pNFS %s: dsp %p\n", __func__, dsp);

	dcp = find_pnfs_ds_clientid(&dsp->ds_mdsclid);
	if (dcp)
		put_ds_clientid(dcp);

	list_del(&dsp->ds_hash);
	list_del(&dsp->ds_perclid);
	kfree(dsp);
}

static void
put_ds_clientid(struct pnfs_ds_clientid *dcp)
{
	dprintk("pNFS %s: dcp %p ref %d\n", __func__, dcp,
		atomic_read(&dcp->dc_ref.refcount));
	kref_put(&dcp->dc_ref, release_ds_clientid);
}

static void
get_ds_clientid(struct pnfs_ds_clientid *dcp)
{
	dprintk("pNFS %s: dcp %p ref %d\n", __func__, dcp,
		atomic_read(&dcp->dc_ref.refcount));
	kref_get(&dcp->dc_ref);
}

static void
put_ds_mdsid(struct pnfs_mds_id *mdp)
{
	dprintk("pNFS %s: mdp %p ref %d\n", __func__, mdp,
		atomic_read(&mdp->di_ref.refcount));
	kref_put(&mdp->di_ref, release_ds_mdsid);
}

static void
get_ds_mdsid(struct pnfs_mds_id *mdp)
{
	dprintk("pNFS %s: mdp %p ref %d\n", __func__, mdp,
		atomic_read(&mdp->di_ref.refcount));
	kref_get(&mdp->di_ref);
}

static void
put_ds_stateid(struct pnfs_ds_stateid *dsp)
{
	dprintk("pNFS %s: dsp %p ref %d\n", __func__, dsp,
		atomic_read(&dsp->ds_ref.refcount));
	kref_put(&dsp->ds_ref, release_ds_stateid);
}

static void
get_ds_stateid(struct pnfs_ds_stateid *dsp)
{
	dprintk("pNFS %s: dsp %p ref %d\n", __func__, dsp,
		atomic_read(&dsp->ds_ref.refcount));
	kref_get(&dsp->ds_ref);
}

void
nfs4_pnfs_state_shutdown(void)
{
	struct pnfs_ds_stateid *dsp;
	int i;

	dprintk("pNFSD %s: -->\n", __func__);

	ds_lock_state();
	for (i = 0; i < STATEID_HASH_SIZE; i++) {
		while (!list_empty(&ds_stid_hashtbl[i])) {
			dsp = list_entry(ds_stid_hashtbl[i].next,
					 struct pnfs_ds_stateid, ds_hash);
			put_ds_stateid(dsp);
		}
	}
	ds_unlock_state();
}

static struct pnfs_mds_id *
alloc_init_mds_id(struct pnfs_get_state *gsp)
{
	struct pnfs_mds_id *mdp;

	dprintk("pNFSD: %s\n", __func__);

	mdp = kmalloc(sizeof(*mdp), GFP_KERNEL);
	if (!mdp)
		return NULL;
	INIT_LIST_HEAD(&mdp->di_hash);
	INIT_LIST_HEAD(&mdp->di_mdsclid);
	list_add(&mdp->di_hash, &mds_id_tbl);
	mdp->di_mdsid = gsp->dsid;
	mdp->di_mdsboot = 0;
	kref_init(&mdp->di_ref);
	return mdp;
}

static struct pnfs_ds_clientid *
alloc_init_ds_clientid(struct pnfs_get_state *gsp)
{
	struct pnfs_mds_id *mdp;
	struct pnfs_ds_clientid *dcp;
	clientid_t *clid = (clientid_t *)&gsp->clid;
	unsigned int hashval = clientid_hashval(clid->cl_id);

	dprintk("pNFSD: %s\n", __func__);

	mdp = find_pnfs_mds_id(gsp->dsid);
	if (!mdp) {
		mdp = alloc_init_mds_id(gsp);
		if (!mdp)
			return NULL;
	} else {
		get_ds_mdsid(mdp);
	}

	dcp = kmalloc(sizeof(*dcp), GFP_KERNEL);
	if (!dcp)
		return NULL;

	INIT_LIST_HEAD(&dcp->dc_hash);
	INIT_LIST_HEAD(&dcp->dc_stateid);
	INIT_LIST_HEAD(&dcp->dc_permdsid);
	list_add(&dcp->dc_hash, &mds_clid_hashtbl[hashval]);
	list_add(&dcp->dc_permdsid, &mdp->di_mdsclid);
	dcp->dc_mdsclid = *clid;
	kref_init(&dcp->dc_ref);
	dcp->dc_mdsid = gsp->dsid;
	return dcp;
}

static struct pnfs_ds_stateid *
alloc_init_ds_stateid(struct svc_fh *cfh, stateid_t *stidp)
{
	struct pnfs_ds_stateid *dsp;

	dprintk("pNFSD: %s\n", __func__);

	dsp = kmalloc(sizeof(*dsp), GFP_KERNEL);
	if (!dsp)
		return dsp;

	INIT_LIST_HEAD(&dsp->ds_hash);
	INIT_LIST_HEAD(&dsp->ds_perclid);
	memcpy(&dsp->ds_stid, stidp, sizeof(dsp->ds_stid));
	fh_copy_shallow(&dsp->ds_fh, &cfh->fh_handle);
	dsp->ds_access = 0;
	dsp->ds_status = 0;
	dsp->ds_flags = 0L;
	kref_init(&dsp->ds_ref);
	set_bit(DS_STATEID_NEW, &dsp->ds_flags);
	clear_bit(DS_STATEID_VALID, &dsp->ds_flags);
	clear_bit(DS_STATEID_ERROR, &dsp->ds_flags);
	init_waitqueue_head(&dsp->ds_waitq);

	list_add(&dsp->ds_hash, &ds_stid_hashtbl[stateid_hashval(stidp)]);
	dprintk("pNFSD: %s <-- dsp %p\n", __func__, dsp);
	return dsp;
}

static int
update_ds_stateid(struct pnfs_ds_stateid *dsp, struct svc_fh *cfh,
		  struct pnfs_get_state *gsp)
{
	struct pnfs_ds_clientid *dcp;
	int new = 0;

	dprintk("pNFSD: %s dsp %p\n", __func__, dsp);

	dcp = find_pnfs_ds_clientid((clientid_t *)&gsp->clid);
	if (!dcp) {
		dcp = alloc_init_ds_clientid(gsp);
		if (!dcp)
			return 1;
		new = 1;
	}
	if (test_bit(DS_STATEID_NEW, &dsp->ds_flags)) {
		list_add(&dsp->ds_perclid, &dcp->dc_stateid);
		if (!new)
			get_ds_clientid(dcp);
	}

	memcpy(&dsp->ds_stid, &gsp->stid, sizeof(stateid_t));
	dsp->ds_access = gsp->access;
	dsp->ds_status = 0;
	dsp->ds_verifier[0] = gsp->verifier[0];
	dsp->ds_verifier[1] = gsp->verifier[1];
	memcpy(&dsp->ds_mdsclid, &gsp->clid, sizeof(clientid_t));
	set_bit(DS_STATEID_VALID, &dsp->ds_flags);
	clear_bit(DS_STATEID_ERROR, &dsp->ds_flags);
	clear_bit(DS_STATEID_NEW, &dsp->ds_flags);
	return 0;
}

int
nfs4_pnfs_cb_change_state(struct pnfs_get_state *gs)
{
	stateid_t *stid = (stateid_t *)&gs->stid;
	struct pnfs_ds_stateid *dsp;

	dprintk("pNFSD: %s stateid=" STATEID_FMT "\n", __func__,
		STATEID_VAL(stid));

	ds_lock_state();
	dsp = find_pnfs_ds_stateid(stid);
	if (dsp)
		put_ds_stateid(dsp);
	ds_unlock_state();

	dprintk("pNFSD: %s dsp %p\n", __func__, dsp);

	if (dsp)
		return 0;
	return -ENOENT;
}

/* Retrieves and validates stateid.
 * If stateid exists and its fields match, return it.
 * If stateid exists but either the generation or
 * ownerids don't match, check with mds to see if it is valid.
 * If the stateid doesn't exist, the first thread creates a
 * invalid *marker* stateid, then checks to see if the
 * stateid exists on the mds.  If so, it validates the *marker*
 * stateid and updates its fields.  Subsequent threads that
 * find the *marker* stateid wait until it is valid or an error
 * occurs.
 * Called with ds_state_lock.
 */
static struct pnfs_ds_stateid *
nfsv4_ds_get_state(struct svc_fh *cfh, stateid_t *stidp)
{
	struct inode *ino = cfh->fh_dentry->d_inode;
	struct super_block *sb;
	struct pnfs_ds_stateid *dsp = NULL;
	struct pnfs_get_state gs = {
		.access = 0,
	};
	int status = 0, waiter = 0;

	dprintk("pNFSD: %s -->\n", __func__);

	dsp = find_pnfs_ds_stateid(stidp);
	/* Note: we assume same endianess on MDS and DS */
	if (dsp && test_bit(DS_STATEID_VALID, &dsp->ds_flags) &&
	    (stidp->si_generation == dsp->ds_stid.si_generation))
		goto out_noput;

	sb = ino->i_sb;
	if (!sb || !sb->s_pnfs_op->get_state)
		goto out_noput;

	/* Uninitialize current state if it exists yet it doesn't match.
	 * If it is already invalid, another thread is checking state */
	if (dsp) {
		if (!test_and_clear_bit(DS_STATEID_VALID, &dsp->ds_flags))
			waiter = 1;
	} else {
		dsp = alloc_init_ds_stateid(cfh, stidp);
		if (!dsp)
			goto out_noput;
	}

	dprintk("pNFSD: %s Starting loop\n", __func__);
	get_ds_stateid(dsp);
	while (!test_bit(DS_STATEID_VALID, &dsp->ds_flags)) {
		ds_unlock_state();

		/* Another thread is checking the state */
		if (waiter) {
			dprintk("pNFSD: %s waiting\n", __func__);
			wait_event_interruptible_timeout(dsp->ds_waitq,
				(test_bit(DS_STATEID_VALID, &dsp->ds_flags) ||
				 test_bit(DS_STATEID_ERROR, &dsp->ds_flags)),
				 msecs_to_jiffies(1024));
			dprintk("pNFSD: %s awake\n", __func__);
			ds_lock_state();
			if (test_bit(DS_STATEID_ERROR, &dsp->ds_flags))
				goto out;

			continue;
		}

		/* Validate stateid on mds */
		dprintk("pNFSD: %s Checking state on MDS\n", __func__);
		memcpy(&gs.stid, stidp, sizeof(gs.stid));
		status = sb->s_pnfs_op->get_state(ino, &cfh->fh_handle, &gs);
		dprintk("pNFSD: %s from MDS status %d\n", __func__, status);
		ds_lock_state();
		/* if !status and stateid is valid, update id and mark valid */
		if (status || update_ds_stateid(dsp, cfh, &gs)) {
			set_bit(DS_STATEID_ERROR, &dsp->ds_flags);
			/* remove invalid stateid from list */
			put_ds_stateid(dsp);
			wake_up(&dsp->ds_waitq);
			goto out;
		}

		wake_up(&dsp->ds_waitq);
	}
out:
	if (dsp)
		put_ds_stateid(dsp);
out_noput:
	if (dsp)
		dprintk("pNFSD: %s <-- dsp %p ds_flags %lx " STATEID_FMT "\n",
			__func__, dsp, dsp->ds_flags, STATEID_VAL(&dsp->ds_stid));
	/* If error, return null */
	if (dsp && test_bit(DS_STATEID_ERROR, &dsp->ds_flags))
		dsp = NULL;
	dprintk("pNFSD: %s <-- dsp %p\n", __func__, dsp);
	return dsp;
}

int
nfs4_preprocess_pnfs_ds_stateid(struct svc_fh *cfh, stateid_t *stateid)
{
	struct pnfs_ds_stateid *dsp;
	int status = 0;

	dprintk("pNFSD: %s --> " STATEID_FMT "\n", __func__,
		STATEID_VAL(stateid));

	/* Must release state lock while verifying stateid on mds */
	nfs4_unlock_state();
	ds_lock_state();
	dsp = nfsv4_ds_get_state(cfh, stateid);
	if (dsp) {
		get_ds_stateid(dsp);
		dprintk("pNFSD: %s Found " STATEID_FMT "\n", __func__,
			STATEID_VAL(&dsp->ds_stid));

		dprintk("NFSD: %s: dsp %p fh_size %u:%u "
			"fh [%08x:%08x:%08x:%08x]:[%08x:%08x:%08x:%08x] "
			"gen %x:%x\n",
			__func__, dsp,
			cfh->fh_handle.fh_size, dsp->ds_fh.fh_size,
			((unsigned *)&cfh->fh_handle.fh_base)[0],
			((unsigned *)&cfh->fh_handle.fh_base)[1],
			((unsigned *)&cfh->fh_handle.fh_base)[2],
			((unsigned *)&cfh->fh_handle.fh_base)[3],
			((unsigned *)&dsp->ds_fh.fh_base)[0],
			((unsigned *)&dsp->ds_fh.fh_base)[1],
			((unsigned *)&dsp->ds_fh.fh_base)[2],
			((unsigned *)&dsp->ds_fh.fh_base)[3],
			stateid->si_generation, dsp->ds_stid.si_generation);
	}

	if (!dsp ||
	    (cfh->fh_handle.fh_size != dsp->ds_fh.fh_size) ||
	    (memcmp(&cfh->fh_handle.fh_base, &dsp->ds_fh.fh_base,
		    dsp->ds_fh.fh_size) != 0) ||
	    (stateid->si_generation > dsp->ds_stid.si_generation))
		status = nfserr_bad_stateid;
	else if (stateid->si_generation < dsp->ds_stid.si_generation)
		status = nfserr_old_stateid;

	if (dsp)
		put_ds_stateid(dsp);
	ds_unlock_state();
	nfs4_lock_state();
	dprintk("pNFSD: %s <-- status %d\n", __func__, be32_to_cpu(status));
	return status;
}

void
nfs4_ds_get_verifier(stateid_t *stateid, struct super_block *sb, u32 *p)
{
	struct pnfs_ds_stateid *dsp = NULL;

	dprintk("pNFSD: %s --> stid %p\n", __func__, stateid);

	ds_lock_state();
	if (stateid != NULL) {
		dsp = find_pnfs_ds_stateid(stateid);
		if (dsp)
			get_ds_stateid(dsp);
	}

	/* XXX: Should we fetch the stateid or wait if some other
	 * thread is currently retrieving the stateid ? */
	if (dsp && test_bit(DS_STATEID_VALID, &dsp->ds_flags)) {
		*p++ = dsp->ds_verifier[0];
		*p++ = dsp->ds_verifier[1];
		put_ds_stateid(dsp);
	} else {
		/* must be on MDS */
		ds_unlock_state();
		sb->s_pnfs_op->get_verifier(sb, p);
		ds_lock_state();
		p += 2;
	}
	ds_unlock_state();
	dprintk("pNFSD: %s <-- dsp %p\n", __func__, dsp);
	return;
}

#endif /* CONFIG_PNFSD */
