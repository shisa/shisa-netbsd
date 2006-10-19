#	$NetBSD: Makefile.inc,v 1.5 1997/10/18 06:42:25 lukem Exp $
#	from: @(#)Makefile.inc	8.1 (Berkeley) 6/6/93

.include <bsd.own.mk>

DIST=	${NETBSDSRCDIR}/dist/shisa
.PATH:	${DIST}

.if ${HAVE_GCC} == 4
COPTS+=	-fno-strict-aliasing
.endif

CPPFLAGS+= -I${DIST}

.if exists(${.CURDIR}/../../Makefile.inc)
.include "${.CURDIR}/../../Makefile.inc"
.endif
