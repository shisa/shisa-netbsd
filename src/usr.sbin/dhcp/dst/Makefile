# $NetBSD: Makefile,v 1.7 2004/05/23 02:24:52 lukem Exp $

MKPRIVATELIB=	yes

LIB    = dst
SRCS    = dst_support.c dst_api.c hmac_link.c md5_dgst.c base64.c prandom.c

DHCPSRCDIR=	dst

CFLAGS += -DMINIRES_LIB -DHMAC_MD5

.include <bsd.lib.mk>
