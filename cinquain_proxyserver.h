#ifndef _CINQUAIN_PROXYSERVER_H_
#define _CINQUAIN_PROXYSERVER_H_

#include <linux/nfs4.h>

typedef  __kernel_sockaddr_storage  ClientID;

typedef struct cq_filepath {
       u32              lo_len; 
       char *         lo_name; 
} FilePath;

u32              cq_bmval[2];
typedef  cq_bmval  Bitmap;

typedef struct cq_attrib{
       u32       att_len;
       char*   att_buf;
}Attributes;


typedef struct cq_iattr {
       unsigned int     ia_valid;
       umode_t           ia_mode;
       uid_t           ia_uid;
       gid_t           ia_gid;
       loff_t           ia_size;
       struct timespec      ia_atime;
       struct timespec      ia_mtime;
       struct timespec      ia_ctime;
} FileAttributes;

typedef  pnfs_iomode OpenMode;


typedef struct  cq_file{
       struct   file cq_file;
       bool cq_isdelta;
       ClientID      cq_clientid;
} *FileHandle;



#endif
