#
# Makefile for the filesystem export support routines.

obj-$(CONFIG_EXPORTFS) += exportfs.o

exportfs-y				:= expfs.o
exportfs-$(CONFIG_EXPORTFS_FILE_LAYOUT)	+= nfs4filelayoutxdr.o
exportfs-$(CONFIG_EXPORTFS_OSD_LAYOUT)	+= pnfs_osd_xdr_srv.o
exportfs-$(CONFIG_EXPORTFS_BLOCK_LAYOUT) += nfs4blocklayoutxdr.o
