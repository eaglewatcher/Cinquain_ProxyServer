/******************************************************************************
 *
 * (c) 2007 Network Appliance, Inc.  All Rights Reserved.
 * (c) 2009 NetApp.  All Rights Reserved.
 *
 * NetApp provides this source code under the GPL v2 License.
 * The GPL v2 license is available at
 * http://opensource.org/licenses/gpl-license.php.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ******************************************************************************/

#include <linux/nfs4.h>
#include <linux/nfsd/debug.h>
#include <linux/nfsd/nfs4pnfsdlm.h>
#include <linux/nfsd/nfs4layoutxdr.h>
#include <linux/sunrpc/clnt.h>

#include "nfsfh.h"
#include "nfsd.h"

#define NFSDDBG_FACILITY                NFSDDBG_FILELAYOUT

/* Just use a linked list. Do not expect more than 32 dlm_device_entries
 * the first implementation will just use one device per cluster file system
 */

static LIST_HEAD(dlm_device_list);
static DEFINE_SPINLOCK(dlm_device_list_lock);

struct dlm_device_entry {
	struct list_head	dlm_dev_list;
	char			disk_name[DISK_NAME_LEN];
	int			num_ds;
	char			ds_list[NFSD_DLM_DS_LIST_MAX];
};

static struct dlm_device_entry *
_nfsd4_find_pnfs_dlm_device(char *disk_name)
{
	struct dlm_device_entry *dlm_pdev;

	dprintk("--> %s  disk name %s\n", __func__, disk_name);
	spin_lock(&dlm_device_list_lock);
	list_for_each_entry(dlm_pdev, &dlm_device_list, dlm_dev_list) {
		dprintk("%s Look for dlm_pdev %s\n", __func__,
			dlm_pdev->disk_name);
		if (!memcmp(dlm_pdev->disk_name, disk_name, strlen(disk_name))) {
			spin_unlock(&dlm_device_list_lock);
			return dlm_pdev;
		}
	}
	spin_unlock(&dlm_device_list_lock);
	return NULL;
}

static struct dlm_device_entry *
nfsd4_find_pnfs_dlm_device(struct super_block *sb) {
	char dname[BDEVNAME_SIZE];

	bdevname(sb->s_bdev, dname);
	return _nfsd4_find_pnfs_dlm_device(dname);
}

ssize_t
nfsd4_get_pnfs_dlm_device_list(char *buf, ssize_t buflen)
{
	char *pos = buf;
	ssize_t size = 0;
	struct dlm_device_entry *dlm_pdev;
	int ret = -EINVAL;

	spin_lock(&dlm_device_list_lock);
	list_for_each_entry(dlm_pdev, &dlm_device_list, dlm_dev_list)
	{
		int advanced;
		advanced = snprintf(pos, buflen - size, "%s:%s\n", dlm_pdev->disk_name, dlm_pdev->ds_list);
		if (advanced >= buflen - size)
			goto out;
		size += advanced;
		pos += advanced;
	}
	ret = size;

out:
	spin_unlock(&dlm_device_list_lock);
	return ret;
}

bool nfsd4_validate_pnfs_dlm_device(char *ds_list, int *num_ds)
{
	char *start = ds_list;

	*num_ds = 0;

	while (*start) {
		struct sockaddr_storage tempAddr;
		int ipLen = strcspn(start, ",");

		if (!rpc_pton(start, ipLen, (struct sockaddr *)&tempAddr, sizeof(tempAddr)))
			return false;
		(*num_ds)++;
		start += ipLen + 1;
	}
	return true;
}

/*
 * pnfs_dlm_device string format:
 *     block-device-path:<ds1 ipv4 address>,<ds2 ipv4 address>
 *
 * Examples
 *     /dev/sda:192.168.1.96,192.168.1.97' creates a data server list with
 *     two data servers for the dlm cluster file system mounted on /dev/sda.
 *
 *     /dev/sda:192.168.1.96,192.168.1.100'
 *     replaces the data server list for /dev/sda
 *
 *     Only the deviceid == 1 is supported. Can add device id to
 *     pnfs_dlm_device string when needed.
 *
 *     Only the round robin each data server once stripe index is supported.
 */
int
nfsd4_set_pnfs_dlm_device(char *pnfs_dlm_device, int len)

{
	struct dlm_device_entry *new, *found;
	char *bufp = pnfs_dlm_device;
	char *endp = bufp + strlen(bufp);
	int err = -ENOMEM;

	dprintk("--> %s len %d\n", __func__, len);

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return err;

	err = -EINVAL;
	/* disk_name */
	/* FIXME: need to check for valid disk_name. search superblocks?
	 * check for slash dev slash ?
	 */
	len = strcspn(bufp, ":");
	if (len > DISK_NAME_LEN)
		goto out_free;
	memcpy(new->disk_name, bufp, len);

	err = -EINVAL;
	bufp += len + 1;
	if (bufp >= endp)
		goto out_free;

	/* data server list */
	/* FIXME: need to check for comma separated valid ip format */
	len = strlen(bufp);
	if (len > NFSD_DLM_DS_LIST_MAX)
		goto out_free;
	memcpy(new->ds_list, bufp, len);


	/*  validate the ips */
	if (!nfsd4_validate_pnfs_dlm_device(new->ds_list, &(new->num_ds)))
		goto out_free;

	dprintk("%s disk_name %s num_ds %d ds_list %s\n", __func__,
		new->disk_name, new->num_ds, new->ds_list);

	found = _nfsd4_find_pnfs_dlm_device(new->disk_name);
	if (found) {
		/* FIXME: should compare found->ds_list with new->ds_list
		 * and if it is different, kick off a CB_NOTIFY change
		 * deviceid.
		 */
		dprintk("%s pnfs_dlm_device %s:%s already in cache "
			" replace ds_list with new ds_list %s\n", __func__,
			found->disk_name, found->ds_list, new->ds_list);
		memset(found->ds_list, 0, DISK_NAME_LEN);
		memcpy(found->ds_list, new->ds_list, strlen(new->ds_list));
		found->num_ds = new->num_ds;
		kfree(new);
	} else {
		dprintk("%s Adding pnfs_dlm_device %s:%s\n", __func__,
				new->disk_name, new->ds_list);
		spin_lock(&dlm_device_list_lock);
		list_add(&new->dlm_dev_list, &dlm_device_list);
		spin_unlock(&dlm_device_list_lock);
	}
	dprintk("<-- %s Success\n", __func__);
	return 0;

out_free:
	kfree(new);
	dprintk("<-- %s returns %d\n", __func__, err);
	return err;
}

void nfsd4_pnfs_dlm_shutdown(void)
{
	struct dlm_device_entry *dlm_pdev, *next;

	dprintk("--> %s\n", __func__);

	spin_lock(&dlm_device_list_lock);
	list_for_each_entry_safe (dlm_pdev, next, &dlm_device_list,
				  dlm_dev_list) {
		list_del(&dlm_pdev->dlm_dev_list);
		kfree(dlm_pdev);
	}
	spin_unlock(&dlm_device_list_lock);
}

static int nfsd4_pnfs_dlm_getdeviter(struct super_block *sb,
				     u32 layout_type,
				     struct nfsd4_pnfs_dev_iter_res *res)
{
	if (layout_type != LAYOUT_NFSV4_1_FILES) {
		printk(KERN_ERR "%s: ERROR: layout type isn't 'file' "
			"(type: %x)\n", __func__, layout_type);
		return -ENOTSUPP;
	}

	res->gd_eof = 1;
	if (res->gd_cookie)
		return -ENOENT;

	res->gd_cookie = 1;
	res->gd_verf = 1;
	res->gd_devid = 1;
	return 0;
}

static int nfsd4_pnfs_dlm_getdevinfo(struct super_block *sb,
				     struct exp_xdr_stream *xdr,
				     u32 layout_type,
				     const struct nfsd4_pnfs_deviceid *devid)
{
	int err, len, i = 0;
	struct pnfs_filelayout_device fdev;
	struct pnfs_filelayout_devaddr *daddr;
	struct dlm_device_entry *dlm_pdev;
	char   *bufp;

	err = -ENOTSUPP;
	if (layout_type != LAYOUT_NFSV4_1_FILES) {
		dprintk("%s: ERROR: layout type isn't 'file' "
			"(type: %x)\n", __func__, layout_type);
		return err;
	}

	/* We only hand out a deviceid of 1 in LAYOUTGET, so a GETDEVICEINFO
	 * with a gdia_device_id != 1 is invalid.
	 */
	err = -EINVAL;
	if (devid->devid != 1) {
		dprintk("%s: WARNING: didn't receive a deviceid of "
			"1 (got: 0x%llx)\n", __func__, devid->devid);
		return err;
	}

	/*
	 * If the DS list has not been established, return -EINVAL
	 */
	dlm_pdev = nfsd4_find_pnfs_dlm_device(sb);
	if (!dlm_pdev) {
		dprintk("%s: DEBUG: disk %s Not Found\n", __func__,
			sb->s_bdev->bd_disk->disk_name);
		return err;
	}

	dprintk("%s: Found disk %s with DS list |%s|\n",
		__func__, dlm_pdev->disk_name, dlm_pdev->ds_list);

	memset(&fdev, '\0', sizeof(fdev));
	fdev.fl_device_length = dlm_pdev->num_ds;

	err = -ENOMEM;
	len = sizeof(*fdev.fl_device_list) * fdev.fl_device_length;
	fdev.fl_device_list = kzalloc(len, GFP_KERNEL);
	if (!fdev.fl_device_list) {
		printk(KERN_ERR "%s: ERROR: unable to kmalloc a device list "
			"buffer for %d DSes.\n", __func__, i);
		fdev.fl_device_length = 0;
		goto out;
	}

	/* Set a simple stripe indicie */
	fdev.fl_stripeindices_length = fdev.fl_device_length;
	fdev.fl_stripeindices_list = kzalloc(sizeof(u32) *
				     fdev.fl_stripeindices_length, GFP_KERNEL);

	if (!fdev.fl_stripeindices_list) {
		printk(KERN_ERR "%s: ERROR: unable to kmalloc a stripeindices "
			"list buffer for %d DSes.\n", __func__, i);
		goto out;
	}
	for (i = 0; i < fdev.fl_stripeindices_length; i++)
		fdev.fl_stripeindices_list[i] = i;

	/* Transfer the data server list with a single multipath entry */
	bufp = dlm_pdev->ds_list;
	for (i = 0; i < fdev.fl_device_length; i++) {
		daddr = kmalloc(sizeof(*daddr), GFP_KERNEL);
		if (!daddr) {
			printk(KERN_ERR "%s: ERROR: unable to kmalloc a device "
				"addr buffer.\n", __func__);
			goto out;
		}

		len = strcspn(bufp, ",");
		daddr->r_addr.data = kmalloc(len + 4, GFP_KERNEL);
		memcpy(daddr->r_addr.data, bufp, len);
		/*
		 * append the port number.  interpreted as two more bytes
		 * beyond the quad: ".8.1" -> 0x08.0x01 -> 0x0801 = port 2049.
		 */
		memcpy(daddr->r_addr.data + len, ".8.1", 4);
		daddr->r_addr.len = len + 4;

		daddr->r_netid.data = "tcp6";
		daddr->r_netid.len = strnchr(daddr->r_addr.data, len, ':') ? 4 : 3;

		fdev.fl_device_list[i].fl_multipath_length = 1;
		fdev.fl_device_list[i].fl_multipath_list = daddr;

		dprintk("%s: encoding DS |%s|\n", __func__, bufp);

		bufp += len + 1;
	}

	/* have nfsd encode the device info */
	err = filelayout_encode_devinfo(xdr, &fdev);
out:
	for (i = 0; i < fdev.fl_device_length; i++)
		kfree(fdev.fl_device_list[i].fl_multipath_list);
	kfree(fdev.fl_device_list);
	kfree(fdev.fl_stripeindices_list);
	dprintk("<-- %s returns %d\n", __func__, err);
	return err;
}

static int get_stripe_unit(int blocksize)
{
	if (blocksize >= NFSSVC_MAXBLKSIZE)
		return blocksize;
	return NFSSVC_MAXBLKSIZE - (NFSSVC_MAXBLKSIZE % blocksize);
}

/*
 * Look up inode block device in pnfs_dlm_device list.
 * Hash on the inode->i_ino and number of data servers.
 */
static int dlm_ino_hash(struct inode *ino)
{
	struct dlm_device_entry *de;
	u32 hash_mask = 0;

	/* If can't find the inode block device in the pnfs_dlm_deivce list
	 * then don't hand out a layout
	 */
	de = nfsd4_find_pnfs_dlm_device(ino->i_sb);
	if (!de)
		return -1;
	hash_mask = de->num_ds - 1;
	return ino->i_ino & hash_mask;
}

static enum nfsstat4 nfsd4_pnfs_dlm_layoutget(struct inode *inode,
			   struct exp_xdr_stream *xdr,
			   const struct nfsd4_pnfs_layoutget_arg *args,
			   struct nfsd4_pnfs_layoutget_res *res)
{
	struct pnfs_filelayout_layout *layout = NULL;
	struct knfsd_fh *fhp = NULL;
	int index;
	enum nfsstat4 rc = NFS4_OK;

	dprintk("%s: LAYOUT_GET\n", __func__);

	/* DLM exported file systems only support layouts for READ */
	if (res->lg_seg.iomode == IOMODE_RW)
		return NFS4ERR_BADIOMODE;

	index = dlm_ino_hash(inode);
	dprintk("%s first stripe index %d i_ino %lu\n", __func__, index,
		inode->i_ino);
	if (index < 0)
		return NFS4ERR_LAYOUTUNAVAILABLE;

	res->lg_seg.layout_type = LAYOUT_NFSV4_1_FILES;
	/* Always give out whole file layouts */
	res->lg_seg.offset = 0;
	res->lg_seg.length = NFS4_MAX_UINT64;
	/* Always give out READ ONLY layouts */
	res->lg_seg.iomode = IOMODE_READ;

	layout = kzalloc(sizeof(*layout), GFP_KERNEL);
	if (layout == NULL) {
		rc = NFS4ERR_LAYOUTTRYLATER;
		goto error;
	}

	/* Set file layout response args */
	layout->lg_layout_type = LAYOUT_NFSV4_1_FILES;
	layout->lg_stripe_type = STRIPE_SPARSE;
	layout->lg_commit_through_mds = false;
	layout->lg_stripe_unit = get_stripe_unit(inode->i_sb->s_blocksize);
	layout->lg_fh_length = 1;
	layout->device_id.sbid = args->lg_sbid;
	layout->device_id.devid = 1;                                /*FSFTEMP*/
	layout->lg_first_stripe_index = index;                      /*FSFTEMP*/
	layout->lg_pattern_offset = 0;

	fhp = kmalloc(sizeof(*fhp), GFP_KERNEL);
	if (fhp == NULL) {
		rc = NFS4ERR_LAYOUTTRYLATER;
		goto error;
	}

	memcpy(fhp, args->lg_fh, sizeof(*fhp));
	pnfs_fh_mark_ds(fhp);
	layout->lg_fh_list = fhp;

	/* Call nfsd to encode layout */
	rc = filelayout_encode_layout(xdr, layout);
exit:
	kfree(layout);
	kfree(fhp);
	return rc;

error:
	res->lg_seg.length = 0;
	goto exit;
}

static int
nfsd4_pnfs_dlm_layouttype(struct super_block *sb)
{
	return LAYOUT_NFSV4_1_FILES;
}

/* For use by DLM cluster file systems exported by pNFSD */
const struct pnfs_export_operations pnfs_dlm_export_ops = {
	.layout_type = nfsd4_pnfs_dlm_layouttype,
	.get_device_info = nfsd4_pnfs_dlm_getdevinfo,
	.get_device_iter = nfsd4_pnfs_dlm_getdeviter,
	.layout_get = nfsd4_pnfs_dlm_layoutget,
};
EXPORT_SYMBOL(pnfs_dlm_export_ops);
