#	$NetBSD: Makefile,v 1.91.2.1 2005/05/07 11:21:29 tron Exp $
#	@(#)Makefile	8.5 (Berkeley) 3/31/94

# Not ported: XNSrouted enpload scsiformat startslip
# Missing: icheck ncheck

.include <bsd.own.mk>

SUBDIR=	atactl badsect bim brconfig ccdconfig disklabel dkctl dmesg \
	drvctl edlabel fastboot fdisk fsck fsirand ifconfig init ldconfig \
	lmcctl mbrlabel mknod modload modunload mount newbtconf nologin \
	pdisk ping pppoectl raidctl reboot rcorder rndctl route routed \
	savecore scsictl shutdown slattach swapctl sysctl ttyflags umount \
	veriexecctl vinum wdogctl wsconsctl

# support for various file systems
SUBDIR+= fsck_ext2fs
SUBDIR+= newfs fsck_ffs fsdb dump restore clri tunefs
SUBDIR+= newfs_lfs fsck_lfs dump_lfs resize_lfs
SUBDIR+= newfs_msdos fsck_msdos
SUBDIR+= mount_ados
SUBDIR+= mount_cd9660
SUBDIR+= mount_ext2fs
SUBDIR+= mount_fdesc
SUBDIR+= mount_filecore
SUBDIR+= mount_ffs
SUBDIR+= mount_kernfs
SUBDIR+= mount_lfs
SUBDIR+= mount_msdos
SUBDIR+= mount_nfs
SUBDIR+= mount_ntfs
SUBDIR+= mount_null
SUBDIR+= mount_overlay
SUBDIR+= mount_portal
SUBDIR+= mount_procfs
SUBDIR+= mount_ptyfs
SUBDIR+= mount_smbfs
SUBDIR+= mount_umap
SUBDIR+= mount_union

.if (${MKCRYPTO} != "no")
SUBDIR+= cgdconfig
.endif

.if (${MKINET6} != "no")
SUBDIR+= ping6 rtsol
.endif

# IPsec
SUBDIR+= setkey

.include <bsd.subdir.mk>
