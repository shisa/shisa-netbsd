#	$NetBSD: Makefile,v 1.1 2007/08/07 21:26:36 pooka Exp $
#

.include <bsd.own.mk>

LIB=	ext2fs

.PATH:  ${NETBSDSRCDIR}/sys/ufs/ext2fs

SRCS=	ext2fs_alloc.c ext2fs_balloc.c ext2fs_bmap.c ext2fs_bswap.c	\
	ext2fs_inode.c ext2fs_lookup.c ext2fs_readwrite.c ext2fs_subr.c	\
	ext2fs_vfsops.c ext2fs_vnops.c

CFLAGS+=-Wno-pointer-sign

.include <bsd.lib.mk>
.include <bsd.klinks.mk>
