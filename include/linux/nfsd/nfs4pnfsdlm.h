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
#include <linux/genhd.h>

/*
 * Length of comma separated pnfs data server IPv4 addresses. Enough room for
 * 32 addresses.
 */
#define NFSD_DLM_DS_LIST_MAX   512
/*
 * Length of colon separated pnfs dlm device of the form
 * disk_name:comma separated data server IPv4 address
 */
#define NFSD_PNFS_DLM_DEVICE_MAX (NFSD_DLM_DS_LIST_MAX + DISK_NAME_LEN + 1)

#ifdef CONFIG_PNFSD

/* For use by DLM cluster file systems exported by pNFSD */
extern const struct pnfs_export_operations pnfs_dlm_export_ops;

int nfsd4_set_pnfs_dlm_device(char *pnfs_dlm_device, int len);

void nfsd4_pnfs_dlm_shutdown(void);

ssize_t nfsd4_get_pnfs_dlm_device_list(char *buf, ssize_t buflen);

#else /* CONFIG_PNFSD */

static inline void nfsd4_pnfs_dlm_shutdown(void)
{
	return;
}

#endif /* CONFIG_PNFSD */
