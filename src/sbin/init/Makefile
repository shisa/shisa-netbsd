#	$NetBSD: Makefile,v 1.35 2005/01/13 03:21:59 lukem Exp $
#	@(#)Makefile	8.1 (Berkeley) 7/19/93

PROG=	init
MAN=	init.8
DPADD=	${LIBUTIL}
LDADD=	-lutil
CPPFLAGS+=	-DMFS_DEV_IF_NO_CONSOLE -DSUPPORT_UTMP -DSUPPORT_UTMPX

.ifdef	SMALLPROG
CPPFLAGS+=	-DLETS_GET_SMALL
.else
CPPFLAGS+=	-DALTSHELL -DSECURE
DPADD+=		${LIBCRYPT}
LDADD+=		-lcrypt
.endif

.include <bsd.prog.mk>
