#	$NetBSD: Makefile,v 1.54 2005/01/20 16:39:23 xtraeme Exp $
#	@(#)Makefile	8.2 (Berkeley) 3/17/94

PROG=	disklabel
SRCS=	disklabel.c dkcksum.c interact.c printlabel.c
MAN=	disklabel.5 disklabel.8
LDADD+= -lutil
DPADD+= ${LIBUTIL}

.if (${MACHINE} == "hp300") || (${MACHINE} == "vax") \
	|| (${MACHINE} == "arm32") || (${MACHINE} == "hp700")
CPPFLAGS+= -DNUMBOOT=1
.endif

# these have additional requirements on the alignment of a partition
.if (${MACHINE} == "sparc") || (${MACHINE} == "sparc64") \
	|| (${MACHINE} == "sun3")
CPPFLAGS+= -DSTRICT_CYLINDER_ALIGNMENT
.endif

.if (${MACHINE} == "alpha") || (${MACHINE} == "x68k") || (${MACHINE} == "hp700")
# preserve the non-disklabel portions of the first 8KB of the disk
CPPFLAGS+= -DSAVEBOOTAREA
.endif

.if ( 0 \
	|| ${MACHINE} == "acorn26" \
	|| ${MACHINE} == "acorn32" \
	|| ${MACHINE} == "amd64" \
	|| ${MACHINE} == "arc" \
	|| ${MACHINE} == "cats" \
	|| ${MACHINE} == "cobalt" \
	|| ${MACHINE} == "evbarm" \
	|| ${MACHINE} == "hpcarm" \
	|| ${MACHINE} == "hpcmips" \
	|| ${MACHINE} == "i386" \
	|| ${MACHINE} == "iyonix" \
	|| ${MACHINE} == "macppc" \
	|| ${MACHINE} == "netwinder" \
	|| ${MACHINE} == "playstation2" \
	|| ${MACHINE} == "prep" \
	|| ${MACHINE} == "shark" \
    )
# use MBR partition info
CPPFLAGS+= -DUSE_MBR
# preserve the non-disklabel portions of the first 8KB of the disk
CPPFLAGS+= -DSAVEBOOTAREA
# recognize old MBR partition ID for a while
CPPFLAGS+= -DCOMPAT_386BSD_MBRPART
.endif

.if (${MACHINE} == "acorn32" || ${MACHINE} == "acorn26")
# Support FileCore boot block
CPPFLAGS+= -DUSE_ACORN
.endif

.include <bsd.prog.mk>
