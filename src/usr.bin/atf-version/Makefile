# $NetBSD: Makefile,v 1.1 2007/11/12 15:00:02 jmmv Exp $

.include <bsd.own.mk>

SRCDIR=		${NETBSDSRCDIR}/dist/atf
.PATH:		${SRCDIR}/admin ${SRCDIR}/tools

PROG_CXX=	atf-version
SRCS=		atf-version.cpp
MAN=		atf-version.1

CPPFLAGS+=	-DHAVE_CONFIG_H
CPPFLAGS+=	-I${SRCDIR}/libs
CPPFLAGS+=	-I.
CPPFLAGS+=	-I${.CURDIR}/../../lib/libatf
LDADD+=		-latf

WARNS?=		2

CLEANFILES=	revision.h
atf-version.cpp: revision.h
revision.h: revision-dist.h
	cp ${SRCDIR}/admin/revision-dist.h revision.h

.include <bsd.prog.mk>
