#	$NetBSD: Makefile,v 1.5.4.1 2005/09/30 22:58:59 tron Exp $

.include <bsd.own.mk>

LIB=	SM
.PATH:	${X11SRCDIR.xc}/lib/${LIB}

SRCS=	sm_auth.c sm_client.c sm_error.c sm_genid.c sm_manager.c sm_misc.c \
	sm_process.c

INCS=	SM.h SMlib.h SMproto.h
INCSDIR=${X11INCDIR}/X11/SM

CPPFLAGS+=	${X11FLAGS.THREADLIB}

CONN_DEFINES=	${X11FLAGS.CONNECTION} -DICE_t

CPPFLAGS.sm_manager.c=	$(CONN_DEFINES)
CPPFLAGS.sm_genid.c=	$(CONN_DEFINES)

LIBDPLIBS=\
	ICE	${.CURDIR}/../ICE

.include <bsd.x11.mk>
.include <bsd.lib.mk>
