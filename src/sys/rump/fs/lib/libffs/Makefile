#	$NetBSD: Makefile,v 1.3 2007/09/24 01:31:07 pooka Exp $
#

.include <bsd.own.mk>

LIB=	ffs

.PATH:  ${NETBSDSRCDIR}/sys/ufs/ffs

SRCS=	ffs_alloc.c ffs_balloc.c ffs_bswap.c ffs_inode.c		\
	ffs_softdep.stub.c ffs_subr.c ffs_tables.c ffs_vfsops.c		\
	ffs_vnops.c ffs_snapshot.c

CPPFLAGS+=	-DFFS_NO_SNAPSHOT -DFFS_EI
CFLAGS+=	-Wno-pointer-sign

.include <bsd.lib.mk>
.include <bsd.klinks.mk>
