# $NetBSD: Makefile,v 1.3 2003/06/30 18:47:53 wiz Exp $

# $FreeBSD: src/gnu/usr.bin/groff/src/roff/groff/Makefile,v 1.7 2003/05/01 13:22:20 ru Exp $

DIST_SUBDIR=	src/roff/groff

PROG_CXX=	groff
SRCS=		groff.cpp pipeline.c
DPADD+=		${LIBGROFF} ${LIBM}
LDADD+=		${LIBGROFF} -lm
CLEANFILES=	${MAN}

.include <bsd.prog.mk>
