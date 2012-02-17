#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/exportfs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/sunrpc/clnt.h>
#include <linux/workqueue.h>
#include <linux/sunrpc/rpc_pipe_fs.h>
#include <linux/proc_fs.h>
#include <linux/nfs_fs.h>
#include <linux/nfsd/debug.h>

#include "nfsd4_block.h"

#define NFSDDBG_FACILITY NFSDDBG_PNFS

static ssize_t bl_pipe_upcall(struct file *, struct rpc_pipe_msg *,
    char __user *, size_t);
static ssize_t bl_pipe_downcall(struct file *, const char __user *, size_t);
static void bl_pipe_destroy_msg(struct rpc_pipe_msg *);

static struct rpc_pipe_ops bl_upcall_ops = {
	.upcall		= bl_pipe_upcall,
	.downcall	= bl_pipe_downcall,
	.destroy_msg	= bl_pipe_destroy_msg,
};

bl_comm_t	*bl_comm_global;

int
nfsd_bl_start(void)
{
	bl_comm_t	*bl_comm = NULL;
	struct vfsmount *mnt;
	struct path path;
	int rc;

	dprintk("%s: starting pipe\n", __func__);
	if (bl_comm_global)
		return -EEXIST;

	mnt = rpc_get_mount();
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	/* FIXME: do not abuse rpc_pipefs/nfs */
	rc = vfs_path_lookup(mnt->mnt_root, mnt, "/nfs", 0, &path);
	if (rc)
		goto err;

	bl_comm = kzalloc(sizeof (*bl_comm), GFP_KERNEL);
	if (!bl_comm) {
		rc = -ENOMEM;
		goto err;
	}

	/* FIXME: rename to "spnfs_block" */
	bl_comm->pipe_dentry = rpc_mkpipe(path.dentry, "pnfs_block", bl_comm,
					 &bl_upcall_ops, 0);
	if (IS_ERR(bl_comm->pipe_dentry)) {
		rc = -EPIPE;
		goto err;
	}
	mutex_init(&bl_comm->lock);
	mutex_init(&bl_comm->pipe_lock);
	init_waitqueue_head(&bl_comm->pipe_wq);

	bl_comm_global = bl_comm;
	return 0;
err:
	rpc_put_mount();
	kfree(bl_comm);
	return rc;
}

void
nfsd_bl_stop(void)
{
	bl_comm_t	*c = bl_comm_global;

	dprintk("%s: stopping pipe\n", __func__);
	if (!c)
		return;
	rpc_unlink(c->pipe_dentry);
	rpc_put_mount();
	bl_comm_global = NULL;
	kfree(c);
}

static ssize_t
bl_pipe_upcall(struct file *file, struct rpc_pipe_msg *msg, char __user *dst,
    size_t buflen)
{
	char	*data	= (char *)msg->data + msg->copied;
	ssize_t	mlen	= msg->len - msg->copied,
		left;

	if (mlen > buflen)
		mlen = buflen;

	left = copy_to_user(dst, data, mlen);
	if (left < 0) {
		msg->errno = left;
		return left;
	}
	mlen		-= left;
	msg->copied	+= mlen;
	msg->errno	= 0;

	return mlen;
}

static ssize_t
bl_pipe_downcall(struct file *filp, const char __user *src, size_t mlen)
{
	struct rpc_inode	*rpci	= RPC_I(filp->f_dentry->d_inode);
	bl_comm_t		*bc	= (bl_comm_t *)rpci->private;
	bl_comm_msg_t		*im	= &bc->msg;
	int			ret;
	bl_comm_res_t		*res;
	

	if (mlen == 0) {
		im->msg_status = PNFS_BLOCK_FAILURE;
		im->msg_res = NULL;
		wake_up(&bc->pipe_wq);
		return -EFAULT;
	}
	
	if ((res = kmalloc(mlen, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	
	if (copy_from_user(res, src, mlen)) {
		kfree(res);
		return -EFAULT;
	}
	
	mutex_lock(&bc->pipe_lock);
	
	ret		= mlen;
	im->msg_status	= res->res_status;
	im->msg_res	= res;
	
	wake_up(&bc->pipe_wq);
	mutex_unlock(&bc->pipe_lock);
	return ret;
}

static void
bl_pipe_destroy_msg(struct rpc_pipe_msg *msg)
{
	bl_comm_msg_t	*im = msg->data;
	bl_comm_t	*bc = container_of(im, struct bl_comm, msg);
	
	if (msg->errno >= 0)
		return;

	mutex_lock(&bc->pipe_lock);
	im->msg_status = PNFS_BLOCK_FAILURE;
	wake_up(&bc->pipe_wq);
	mutex_unlock(&bc->pipe_lock);
}

int
bl_upcall(bl_comm_t *bc, bl_comm_msg_t *upmsg, bl_comm_res_t **res)
{
	struct rpc_pipe_msg	msg;
	DECLARE_WAITQUEUE(wq, current);
	int			rval	= 1;
	bl_comm_msg_t		*m	= &bc->msg;
	
	if (bc == NULL) {
		dprintk("%s: No pNFS block daemon available\n", __func__);
		return 1;
	}
	
	mutex_lock(&bc->lock);
	mutex_lock(&bc->pipe_lock);
	
	memcpy(m, upmsg, sizeof (*m));
	
	memset(&msg, 0, sizeof (msg));
	msg.data = m;
	msg.len = sizeof (*m);
	
	add_wait_queue(&bc->pipe_wq, &wq);
	rval = rpc_queue_upcall(bc->pipe_dentry->d_inode, &msg);
	if (rval < 0) {
		remove_wait_queue(&bc->pipe_wq, &wq);
		goto out;
	}
	
	set_current_state(TASK_UNINTERRUPTIBLE);
	mutex_unlock(&bc->pipe_lock);
	schedule();
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&bc->pipe_wq, &wq);
	mutex_lock(&bc->pipe_lock);
	
	if (m->msg_status == PNFS_BLOCK_SUCCESS) {
		*res = m->msg_res;
		rval = 0;
	} else
		rval = 1;
	
out:
	mutex_unlock(&bc->pipe_lock);
	mutex_unlock(&bc->lock);
	return rval;
}

static ssize_t ctl_write(struct file *file, const char __user *buf, size_t len,
    loff_t *offset)
{
	int		cmd,
			rc;
	bl_comm_t	*bc	= bl_comm_global;
	bl_comm_msg_t	msg;
	bl_comm_res_t	*res;

	if (copy_from_user((int *)&cmd, (int *)buf, sizeof (int)))
		return -EFAULT;
	switch (cmd) {
	case PNFS_BLOCK_CTL_STOP:
		msg.msg_type = PNFS_UPCALL_MSG_STOP;
		(void) bl_upcall(bc, &msg, &res);
		kfree(res);
		nfsd_bl_stop();
		break;
		
	case PNFS_BLOCK_CTL_START:
		rc = nfsd_bl_start();
		if (rc != 0)
			return rc;
		break;
		
	case PNFS_BLOCK_CTL_VERS:
		msg.msg_type = PNFS_UPCALL_MSG_VERS;
		msg.u.msg_vers = PNFS_UPCALL_VERS;
		if (bl_upcall(bc, &msg, &res)) {
			dprintk("%s: Failed to contact pNFS block daemon\n",
			    __func__);
			return 0;
		}
		kfree(res);
		break;
		
	default:
		dprintk("%s: unknown ctl command %d\n", __func__, cmd);
		break;
	}
	return len;
}

static struct file_operations ctl_ops = {
	.write	= ctl_write,
};

/*
 * bl_init_proc -- set up proc interfaces
 *
 * Creating a pnfs_block directory isn't really required at this point
 * since we've only got a single node in that directory. If the need for
 * more nodes doesn't present itself shortly this code should revert
 * to a single top level node. McNeal 11-Aug-2008.
 */
int
bl_init_proc(void)
{
	struct proc_dir_entry *e;

	e = proc_mkdir("fs/pnfs_block", NULL);
	if (!e)
		return -ENOMEM;

	e = create_proc_entry("fs/pnfs_block/ctl", 0, NULL);
	if (!e)
		return -ENOMEM;
	e->proc_fops = &ctl_ops;

	return 0;
}
