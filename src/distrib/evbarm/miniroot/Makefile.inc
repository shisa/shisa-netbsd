#	$NetBSD: Makefile.inc,v 1.10 2003/02/01 05:03:42 tsutsui Exp $

DBG=		-Os

IMAGESIZE=	5m
MAKEFS_FLAGS=	-o density=2k
IMAGEENDIAN=	le
MAKEDEVTARGETS=	all
IMAGEDEPENDS+=	${ARCHDIR}/dot.profile ${ARCHDIR}/termcap.vt100 \
		${DESTDIR}/.profile ${DESTDIR}/etc/disktab
SMALLPROG_INET6=1
#	$NetBSD: Makefile.inc,v 1.4 2002/04/10 14:53:43 lukem Exp $

.ifndef ABSTOP
ABSTOP!= cd ${.PARSEDIR}; pwd

.if (${.PARSEDIR} == ${.CURDIR})
RELTOP:= .
.else
RELTOP:= ${.PARSEDIR:S,^${.CURDIR},,}
.endif

# you can set BSD{SRC,OBJ}DIR in Makefile.local.inc
.if exists(${ABSTOP}/Makefile.local.inc)
.include "${ABSTOP}/Makefile.local.inc"
.endif
.endif
