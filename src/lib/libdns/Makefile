#	$NetBSD: Makefile,v 1.1 2007/11/04 23:28:18 tls Exp $

LIB=dns

.include <bsd.own.mk>

.include "${NETBSDSRCDIR}/usr.sbin/bind/Makefile.inc"

DIST=	${IDIST}/lib/dns
.include "${DIST}/api"

.PATH.c:	${DIST}/unix ${DIST}/sec/dst ${DIST}
CPPFLAGS+=	-I${BIND_SRCDIR}/include/dns -I${DIST}

.if ${HAVE_GCC} == 4
.for f in lookup byaddr request sdb validator
COPTS.${f}.c+=  -Wno-pointer-sign -fno-strict-aliasing
.endfor
.endif

DNSSEC_SRCS=	dst_api.c dst_lib.c dst_parse.c dst_result.c \
	gssapi_link.c gssapictx.c hmac_link.c key.c openssl_link.c \
	openssldh_link.c openssldsa_link.c opensslrsa_link.c

SRCS=	acl.c acache.c adb.c byaddr.c cache.c callbacks.c compress.c \
	db.c dbiterator.c dbtable.c diff.c dispatch.c dlz.c dnssec.c ds.c \
	forward.c journal.c keytable.c lib.c log.c lookup.c \
	master.c masterdump.c message.c name.c ncache.c nsec.c \
	order.c peer.c portlist.c rbt.c rbtdb.c rbtdb64.c rcode.c \
	rdata.c rdatalist.c rdataset.c rdatasetiter.c rdataslab.c \
	request.c resolver.c result.c rootns.c sdb.c soa.c ssu.c \
	stats.c tcpmsg.c time.c timer.c tkey.c tsig.c ttl.c \
	validator.c version.c view.c xfrin.c zone.c zonekey.c \
	zt.c ${DNSSEC_SRCS}

.include <bsd.lib.mk>
