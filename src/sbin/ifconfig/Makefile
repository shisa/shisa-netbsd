#	$NetBSD: Makefile,v 1.31 2006/08/26 16:20:20 matt Exp $
#	@(#)Makefile	8.1 (Berkeley) 6/5/93

# when making a change to this file, please check if the change is
# also needed for src/distrib/utils/x_ifconfig/Makefile.

.include <bsd.own.mk>

PROG=	ifconfig
MAN=	ifconfig.8

CPPFLAGS+=	-I${NETBSDSRCDIR}/sys/

.if (${USE_INET6} != "no")
CPPFLAGS+=-DINET6
CPPFLAGS+=-DMIP6
.endif

# KAME scope id hack
CPPFLAGS+=-DKAME_SCOPEID

DPADD+=${LIBUTIL}
LDADD+=-lutil

SRCS= ifconfig.c 

SRCS+= af_atalk.c
SRCS+= af_inet.c
.if (${USE_INET6} != "no")
SRCS+= af_inet6.c
.endif
SRCS+= af_iso.c
SRCS+= carp.c

SRCS+= agr.c
SRCS+= ieee80211.c
SRCS+= tunnel.c
SRCS+= vlan.c

.include <bsd.prog.mk>
