# $NetBSD: Makefile,v 1.6 2005/01/10 03:11:17 lukem Exp $

NOLINKLIB=	# defined
NOPIC=		# defined
NOPROFILE=	# defined

.include <bsd.own.mk>

DIST=		${NETBSDSRCDIR}/crypto/dist
.PATH:		${DIST}/heimdal/lib/vers

MKLINT=		# defined

LIB=		vers

includes: print_version.h

SRCS=		print_version.c
DPSRCS=		print_version.h

CPPFLAGS+= -I. \
	-I${NETBSDSRCDIR}/include/heimdal \
	-I${DIST}/heimdal/lib/roken \
	-DHAVE_CONFIG_H
 
HOST_CPPFLAGS+=	-I${NETBSDSRCDIR}/include/heimdal -DHAVE_CONFIG_H

.if (${USE_INET6} != "no")
CPPFLAGS+=-DHAVE_IPV6
HOST_CPPFLAGS+=-DHAVE_IPV6
.endif

make-print-version.lo: ${NETBSDSRCDIR}/include/heimdal/version.h

make-print-version: make-print-version.lo
	${HOST_CC} ${HOST_LDFLAGS} -o ${.TARGET} ${.ALLSRC}

print_version.h: make-print-version
	./make-print-version print_version.h

print_version.o print_version.ln: print_version.h

CLEANFILES+=	print_version.h make-print-version make-print-version.lo
 
.include <bsd.lib.mk>
