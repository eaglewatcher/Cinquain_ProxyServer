/*
 *  Copyright (c) 2001 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Kendrick Smith <kmsmith@umich.edu>
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

#ifndef _NFSD4_STATE_H
#define _NFSD4_STATE_H

#include <linux/idr.h>
#include <linux/sunrpc/svc_xprt.h>
#include <linux/nfsd/nfsfh.h>
#include <linux/nfsd/export.h>
#include "nfsfh.h"

typedef struct {
	u32             cl_boot;
	u32             cl_id;
} clientid_t;

static inline int
same_clid(clientid_t *cl1, clientid_t *cl2)
{
	return (cl1->cl_boot == cl2->cl_boot) && (cl1->cl_id == cl2->cl_id);
}

typedef struct {
	clientid_t	so_clid;
	u32		so_id;
} stateid_opaque_t;

typedef struct {
	u32                     si_generation;
	stateid_opaque_t        si_opaque;
} stateid_t;

#define STATEID_FMT	"(%08x/%08x/%08x/%08x)"
#define STATEID_VAL(s) \
	(s)->si_opaque.so_clid.cl_boot, \
	(s)->si_opaque.so_clid.cl_id, \
	(s)->si_opaque.so_id, \
	(s)->si_generation

struct nfs4_stid {
#define NFS4_OPEN_STID 1
#define NFS4_LOCK_STID 2
#define NFS4_DELEG_STID 4
/* For an open stateid kept around *only* to process close replays: */
#define NFS4_CLOSED_STID 8
#define NFS4_LAYOUT_STID 16
	unsigned char sc_type;
	stateid_t sc_stateid;
	struct nfs4_client *sc_client;
};

struct nfs4_delegation {
	struct nfs4_stid	dl_stid; /* must be first field */
	struct list_head	dl_perfile;
	struct list_head	dl_perclnt;
	struct list_head	dl_recall_lru;  /* delegation recalled */
	atomic_t		dl_count;       /* ref count */
	struct nfs4_file	*dl_file;
	u32			dl_type;
	time_t			dl_time;
/* For recall: */
	struct knfsd_fh		dl_fh;
	int			dl_retries;
	struct nfsd4_callback	dl_recall;
};

/* client delegation callback info */
struct nfs4_cb_conn {
	/* SETCLIENTID info */
	struct sockaddr_storage	cb_addr;
	struct sockaddr_storage	cb_saddr;
	size_t			cb_addrlen;
	u32                     cb_prog; /* used only in 4.0 case;
					    per-session otherwise */
	u32                     cb_ident;	/* minorversion 0 only */
	struct svc_xprt		*cb_xprt;	/* minorversion 1 only */
};

static inline struct nfs4_delegation *delegstateid(struct nfs4_stid *s)
{
	return container_of(s, struct nfs4_delegation, dl_stid);
}

/* Maximum number of slots per session. 160 is useful for long haul TCP */
#define NFSD_MAX_SLOTS_PER_SESSION     160
/* Maximum number of operations per session compound */
#define NFSD_MAX_OPS_PER_COMPOUND	16
/* Maximum  session per slot cache size */
#define NFSD_SLOT_CACHE_SIZE		1024
/* Maximum number of NFSD_SLOT_CACHE_SIZE slots per session */
#define NFSD_CACHE_SIZE_SLOTS_PER_SESSION	32
#define NFSD_MAX_MEM_PER_SESSION  \
		(NFSD_CACHE_SIZE_SLOTS_PER_SESSION * NFSD_SLOT_CACHE_SIZE)

struct nfsd4_slot {
	bool	sl_inuse;
	bool	sl_cachethis;
	u16	sl_opcnt;
	u32	sl_seqid;
	__be32	sl_status;
	u32	sl_datalen;
	char	sl_data[];
};

struct nfsd4_channel_attrs {
	u32		headerpadsz;
	u32		maxreq_sz;
	u32		maxresp_sz;
	u32		maxresp_cached;
	u32		maxops;
	u32		maxreqs;
	u32		nr_rdma_attrs;
	u32		rdma_attrs;
};

struct nfsd4_create_session {
	clientid_t			clientid;
	struct nfs4_sessionid		sessionid;
	u32				seqid;
	u32				flags;
	struct nfsd4_channel_attrs	fore_channel;
	struct nfsd4_channel_attrs	back_channel;
	u32				callback_prog;
	u32				uid;
	u32				gid;
};

struct nfsd4_bind_conn_to_session {
	struct nfs4_sessionid		sessionid;
	u32				dir;
};

/* The single slot clientid cache structure */
struct nfsd4_clid_slot {
	u32				sl_seqid;
	__be32				sl_status;
	struct nfsd4_create_session	sl_cr_ses;
};

struct nfsd4_conn {
	struct list_head cn_persession;
	struct svc_xprt *cn_xprt;
	struct svc_xpt_user cn_xpt_user;
	struct nfsd4_session *cn_session;
/* CDFC4_FORE, CDFC4_BACK: */
	unsigned char cn_flags;
};

struct nfsd4_session {
	struct kref		se_ref;
	struct list_head	se_hash;	/* hash by sessionid */
	struct list_head	se_perclnt;
	u32			se_flags;
	struct nfs4_client	*se_client;
	struct nfs4_sessionid	se_sessionid;
	struct nfsd4_channel_attrs se_fchannel;
	struct nfsd4_channel_attrs se_bchannel;
	struct list_head	se_conns;
	u32			se_cb_prog;
	u32			se_cb_seq_nr;
	struct nfsd4_slot	*se_slots[];	/* forward channel slots */
};

static inline void
nfsd4_put_session(struct nfsd4_session *ses)
{
	extern void free_session(struct kref *kref);
	kref_put(&ses->se_ref, free_session);
}

static inline void
nfsd4_get_session(struct nfsd4_session *ses)
{
	kref_get(&ses->se_ref);
}

/* formatted contents of nfs4_sessionid */
struct nfsd4_sessionid {
	clientid_t	clientid;
	u32		sequence;
	u32		reserved;
};

#define HEXDIR_LEN     33 /* hex version of 16 byte md5 of cl_name plus '\0' */

/*
 * struct nfs4_client - one per client.  Clientids live here.
 * 	o Each nfs4_client is hashed by clientid.
 *
 * 	o Each nfs4_clients is also hashed by name 
 * 	  (the opaque quantity initially sent by the client to identify itself).
 * 	  
 *	o cl_perclient list is used to ensure no dangling stateowner references
 *	  when we expire the nfs4_client
 */
struct nfs4_client {
	struct list_head	cl_idhash; 	/* hash by cl_clientid.id */
	struct list_head	cl_strhash; 	/* hash by cl_name */
	struct list_head	cl_openowners;
	struct idr		cl_stateids;	/* stateid lookup */
	struct list_head	cl_delegations;
	struct list_head        cl_lru;         /* tail queue */
	struct xdr_netobj	cl_name; 	/* id generated by client */
	char                    cl_recdir[HEXDIR_LEN]; /* recovery dir */
	nfs4_verifier		cl_verifier; 	/* generated by client */
	time_t                  cl_time;        /* time of last lease renewal */
	struct sockaddr_storage	cl_addr; 	/* client ipaddress */
	u32			cl_flavor;	/* setclientid pseudoflavor */
	char			*cl_principal;	/* setclientid principal name */
	struct svc_cred		cl_cred; 	/* setclientid principal */
	clientid_t		cl_clientid;	/* generated by server */
	nfs4_verifier		cl_confirm;	/* generated by server */
	u32			cl_firststate;	/* recovery dir creation */
	u32			cl_minorversion;

	/* for v4.0 and v4.1 callbacks: */
	struct nfs4_cb_conn	cl_cb_conn;
#define NFSD4_CLIENT_CB_UPDATE	1
#define NFSD4_CLIENT_KILL	2
	unsigned long		cl_cb_flags;
	struct rpc_clnt		*cl_cb_client;
	u32			cl_cb_ident;
#define NFSD4_CB_UP		0
#define NFSD4_CB_UNKNOWN	1
#define NFSD4_CB_DOWN		2
#define NFSD4_CB_FAULT		3
	int			cl_cb_state;
	struct nfsd4_callback	cl_cb_null;
	struct nfsd4_session	*cl_cb_session;
	struct list_head	cl_callbacks; /* list of in-progress callbacks */

	/* for all client information that callback code might need: */
	spinlock_t		cl_lock;

	/* for nfs41 */
	struct list_head	cl_sessions;
	struct nfsd4_clid_slot	cl_cs_slot;	/* create_session slot */
	u32			cl_exchange_flags;
	/* number of rpc's in progress over an associated session: */
	atomic_t		cl_refcount;

	/* for nfs41 callbacks */
	/* We currently support a single back channel with a single slot */
	unsigned long		cl_cb_slot_busy;
	struct rpc_wait_queue	cl_cb_waitq;	/* backchannel callers may */
						/* wait here for slots */
#if defined(CONFIG_PNFSD)
	struct list_head	cl_layouts;	/* outstanding layouts */
	struct list_head	cl_layoutrecalls; /* outstanding layoutrecall
						     callbacks */
	atomic_t		cl_deviceref;	/* Num outstanding devs */
#endif /* CONFIG_PNFSD */
};

static inline void
mark_client_expired(struct nfs4_client *clp)
{
	clp->cl_time = 0;
}

static inline bool
is_client_expired(struct nfs4_client *clp)
{
	return clp->cl_time == 0;
}

/* struct nfs4_client_reset
 * one per old client. Populates reset_str_hashtbl. Filled from conf_id_hashtbl
 * upon lease reset, or from upcall to state_daemon (to read in state
 * from non-volitile storage) upon reboot.
 */
struct nfs4_client_reclaim {
	struct list_head	cr_strhash;	/* hash by cr_name */
	char			cr_recdir[HEXDIR_LEN]; /* recover dir */
};

static inline void
update_stateid(stateid_t *stateid)
{
	stateid->si_generation++;
	/* Wraparound recommendation from 3530bis-13 9.1.3.2: */
	if (stateid->si_generation == 0)
		stateid->si_generation = 1;
}

/* A reasonable value for REPLAY_ISIZE was estimated as follows:  
 * The OPEN response, typically the largest, requires 
 *   4(status) + 8(stateid) + 20(changeinfo) + 4(rflags) +  8(verifier) + 
 *   4(deleg. type) + 8(deleg. stateid) + 4(deleg. recall flag) + 
 *   20(deleg. space limit) + ~32(deleg. ace) = 112 bytes 
 */

#define NFSD4_REPLAY_ISIZE       112 

/*
 * Replay buffer, where the result of the last seqid-mutating operation 
 * is cached. 
 */
struct nfs4_replay {
	__be32			rp_status;
	unsigned int		rp_buflen;
	char			*rp_buf;
	struct knfsd_fh		rp_openfh;
	char			rp_ibuf[NFSD4_REPLAY_ISIZE];
};

struct nfs4_stateowner {
	struct list_head        so_strhash;   /* hash by op_name */
	struct list_head        so_stateids;
	struct nfs4_client *    so_client;
	/* after increment in ENCODE_SEQID_OP_TAIL, represents the next
	 * sequence id expected from the client: */
	u32                     so_seqid;
	struct xdr_netobj       so_owner;     /* open owner name */
	struct nfs4_replay	so_replay;
	bool			so_is_open_owner;
};

struct nfs4_openowner {
	struct nfs4_stateowner	oo_owner; /* must be first field */
	struct list_head        oo_perclient;
	/*
	 * We keep around openowners a little while after last close,
	 * which saves clients from having to confirm, and allows us to
	 * handle close replays if they come soon enough.  The close_lru
	 * is a list of such openowners, to be reaped by the laundromat
	 * thread eventually if they remain unused:
	 */
	struct list_head	oo_close_lru;
	struct nfs4_ol_stateid *oo_last_closed_stid;
	time_t			oo_time; /* time of placement on so_close_lru */
#define NFS4_OO_CONFIRMED   1
#define NFS4_OO_PURGE_CLOSE 2
#define NFS4_OO_NEW         4
	unsigned char		oo_flags;
};

struct nfs4_lockowner {
	struct nfs4_stateowner	lo_owner; /* must be first element */
	struct list_head	lo_owner_ino_hash; /* hash by owner,file */
	struct list_head        lo_perstateid; /* for lockowners only */
	struct list_head	lo_list; /* for temporary uses */
};

static inline struct nfs4_openowner * openowner(struct nfs4_stateowner *so)
{
	return container_of(so, struct nfs4_openowner, oo_owner);
}

static inline struct nfs4_lockowner * lockowner(struct nfs4_stateowner *so)
{
	return container_of(so, struct nfs4_lockowner, lo_owner);
}

/*
*  nfs4_file: a file opened by some number of (open) nfs4_stateowners.
*    o fi_perfile list is used to search for conflicting 
*      share_acces, share_deny on the file.
*/
struct nfs4_file {
	atomic_t		fi_ref;
	struct list_head        fi_hash;    /* hash by "struct inode *" */
	struct list_head        fi_stateids;
	struct list_head	fi_delegations;
	/* One each for O_RDONLY, O_WRONLY, O_RDWR: */
	struct file *		fi_fds[3];
	/*
	 * Each open or lock stateid contributes 0-4 to the counts
	 * below depending on which bits are set in st_access_bitmap:
	 *     1 to fi_access[O_RDONLY] if NFS4_SHARE_ACCES_READ is set
	 *   + 1 to fi_access[O_WRONLY] if NFS4_SHARE_ACCESS_WRITE is set
	 *   + 1 to both of the above if NFS4_SHARE_ACCESS_BOTH is set.
	 */
	atomic_t		fi_access[2];
	struct file		*fi_deleg_file;
	struct file_lock	*fi_lease;
	atomic_t		fi_delegees;
	struct inode		*fi_inode;
	bool			fi_had_conflict;
#if defined(CONFIG_PNFSD)
	struct list_head	fi_layouts;
	struct list_head	fi_layout_states;
	/* used by layoutget / layoutrecall */
	struct nfs4_fsid	fi_fsid;
	u32			fi_fhlen;
	u8			fi_fhval[NFS4_FHSIZE];
#endif /* CONFIG_PNFSD */
};

/* XXX: for first cut may fall back on returning file that doesn't work
 * at all? */
static inline struct file *find_writeable_file(struct nfs4_file *f)
{
	if (f->fi_fds[O_WRONLY])
		return f->fi_fds[O_WRONLY];
	return f->fi_fds[O_RDWR];
}

static inline struct file *find_readable_file(struct nfs4_file *f)
{
	if (f->fi_fds[O_RDONLY])
		return f->fi_fds[O_RDONLY];
	return f->fi_fds[O_RDWR];
}

static inline struct file *find_any_file(struct nfs4_file *f)
{
	if (f->fi_fds[O_RDWR])
		return f->fi_fds[O_RDWR];
	else if (f->fi_fds[O_WRONLY])
		return f->fi_fds[O_WRONLY];
	else
		return f->fi_fds[O_RDONLY];
}

#if defined(CONFIG_PNFSD)
/* pNFS Metadata server state */

struct pnfs_ds_dev_entry {
	struct list_head	dd_dev_entry; /* st_pnfs_ds_id entry */
	u32			dd_dsid;
};
#endif /* CONFIG_PNFSD */

/* "ol" stands for "Open or Lock".  Better suggestions welcome. */
struct nfs4_ol_stateid {
	struct nfs4_stid    st_stid; /* must be first field */
	struct list_head              st_perfile;
	struct list_head              st_perstateowner;
	struct list_head              st_lockowners;
#if defined(CONFIG_PNFSD)
	struct list_head              st_pnfs_ds_id;
#endif /* CONFIG_PNFSD */
	struct nfs4_stateowner      * st_stateowner;
	struct nfs4_file            * st_file;
	unsigned long                 st_access_bmap;
	unsigned long                 st_deny_bmap;
	struct nfs4_ol_stateid         * st_openstp;
};

static inline struct nfs4_ol_stateid *openlockstateid(struct nfs4_stid *s)
{
	return container_of(s, struct nfs4_ol_stateid, st_stid);
}

/* flags for preprocess_seqid_op() */
#define RD_STATE	        0x00000010
#define WR_STATE	        0x00000020

struct nfsd4_compound_state;

extern __be32 nfs4_preprocess_stateid_op(struct nfsd4_compound_state *cstate,
		stateid_t *stateid, int flags, struct file **filp);
extern void __nfs4_lock_state(const char *func);
#define nfs4_lock_state() __nfs4_lock_state(__func__)
extern void nfs4_unlock_state(void);
extern int nfs4_in_grace(void);
extern __be32 nfs4_check_open_reclaim(clientid_t *clid);
extern void nfs4_free_openowner(struct nfs4_openowner *);
extern void nfs4_free_lockowner(struct nfs4_lockowner *);
extern int set_callback_cred(void);
extern void nfsd4_probe_callback(struct nfs4_client *clp);
extern void nfsd4_probe_callback_sync(struct nfs4_client *clp);
extern void nfsd4_change_callback(struct nfs4_client *clp, struct nfs4_cb_conn *);
extern void nfsd4_do_callback_rpc(struct work_struct *);
extern void nfsd4_cb_recall(struct nfs4_delegation *dp);
extern int nfsd4_create_callback_queue(void);
extern void nfsd4_destroy_callback_queue(void);
extern void nfsd4_shutdown_callback(struct nfs4_client *);
extern void nfs4_put_delegation(struct nfs4_delegation *dp);
extern __be32 nfs4_make_rec_clidname(char *clidname, struct xdr_netobj *clname);
extern void nfsd4_init_recdir(void);
extern int nfsd4_recdir_load(void);
extern void nfsd4_shutdown_recdir(void);
extern int nfs4_client_to_reclaim(const char *name);
extern int nfs4_has_reclaimed_state(const char *name, bool use_exchange_id);
extern void nfsd4_recdir_purge_old(void);
extern void nfsd4_create_clid_dir(struct nfs4_client *clp);
extern void nfsd4_remove_clid_dir(struct nfs4_client *clp);
extern void release_session_client(struct nfsd4_session *);
extern __be32 nfs4_validate_stateid(struct nfs4_client *, stateid_t *);
extern void nfsd4_purge_closed_stateid(struct nfs4_stateowner *);
extern void nfsd4_free_slab(struct kmem_cache **);
extern struct nfs4_file *find_file(struct inode *);
extern struct nfs4_file *find_alloc_file(struct inode *, struct svc_fh *);
extern void put_nfs4_file(struct nfs4_file *);
extern void get_nfs4_file(struct nfs4_file *);
extern struct nfs4_client *find_confirmed_client(clientid_t *);
extern void nfsd4_init_stid(struct nfs4_stid *, struct nfs4_client *, unsigned char type);
extern void nfsd4_unhash_stid(struct nfs4_stid *);
extern struct nfs4_stid *find_stateid(struct nfs4_client *, stateid_t *);
extern __be32 nfsd4_lookup_stateid(stateid_t *, unsigned char typemask, struct nfs4_stid **);
extern void expire_client_lock(struct nfs4_client *);
extern int filter_confirmed_clients(int (* func)(struct nfs4_client *, void *), void *);

#if defined(CONFIG_PNFSD)
extern int nfsd4_init_pnfs_slabs(void);
extern void nfsd4_free_pnfs_slabs(void);
extern void pnfs_expire_client(struct nfs4_client *);
extern void release_pnfs_ds_dev_list(struct nfs4_ol_stateid *);
extern void nfs4_pnfs_state_init(void);
extern void nfs4_pnfs_state_shutdown(void);
extern void nfs4_ds_get_verifier(stateid_t *, struct super_block *, u32 *);
extern int nfs4_preprocess_pnfs_ds_stateid(struct svc_fh *, stateid_t *);
extern void pnfsd_roc(struct nfs4_client *clp, struct nfs4_file *fp);
#else /* CONFIG_PNFSD */
static inline void nfsd4_free_pnfs_slabs(void) {}
static inline int nfsd4_init_pnfs_slabs(void) { return 0; }
static inline void pnfs_expire_client(struct nfs4_client *clp) {}
static inline void release_pnfs_ds_dev_list(struct nfs4_ol_stateid *stp) {}
static inline void nfs4_pnfs_state_shutdown(void) {}
static inline void pnfsd_roc(struct nfs4_client *clp, struct nfs4_file *fp) {}
#endif /* CONFIG_PNFSD */

static inline u64
end_offset(u64 start, u64 len)
{
	u64 end;

	end = start + len;
	return end >= start ? end : NFS4_MAX_UINT64;
}

/* last octet in a range */
static inline u64
last_byte_offset(u64 start, u64 len)
{
	u64 end;

	BUG_ON(!len);
	end = start + len;
	return end > start ? end - 1 : NFS4_MAX_UINT64;
}

#endif   /* NFSD4_STATE_H */
