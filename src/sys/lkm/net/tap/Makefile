# $NetBSD: Makefile,v 1.2 2005/01/19 14:59:08 cube Exp $

.include "../Makefile.inc"

.PATH: ${S}/net

SRCS=	if_tap_lkm.c if_tap.c
KMOD=	tap
WARNS=	3

CPPFLAGS+=	-DNBPFILTER=1

.include <bsd.kmod.mk>
