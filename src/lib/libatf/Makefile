# $NetBSD: Makefile,v 1.1 2007/11/12 14:56:25 jmmv Exp $

.include <bsd.own.mk>

LIB=		atf
NOPIC=		yes # Interface is still too unstable

SRCDIR=		${NETBSDSRCDIR}/dist/atf
.PATH:		${SRCDIR}
.PATH:		${SRCDIR}/atf

CPPFLAGS+=	-I${.CURDIR}
CPPFLAGS+=	-I${SRCDIR}/libs
CPPFLAGS+=	-I.

CPPFLAGS+=	-DHAVE_CONFIG_H
CPPFLAGS+=	-DATF_CONFDIR=\"/etc/atf\"
CPPFLAGS+=	-DATF_LIBEXECDIR=\"/usr/libexec\"
CPPFLAGS+=	-DATF_PKGDATADIR=\"/usr/share/atf\"
CPPFLAGS+=	-DATF_SHELL=\"/bin/sh\"
CPPFLAGS+=	-DATF_WORKDIR=\"/tmp\"

WARNS?=		2

SRCS=		application.cpp \
		atffile.cpp \
		config.cpp \
		env.cpp \
		exceptions.cpp \
		expand.cpp \
		formats.cpp \
		fs.cpp \
		io.cpp \
		parser.cpp \
		sanity.cpp \
		tests.cpp \
		text.cpp \
		ui.cpp \
		user.cpp

INCS=		application.hpp \
		atffile.hpp \
		config.hpp \
		env.hpp \
		exceptions.hpp \
		expand.hpp \
		formats.hpp \
		fs.hpp \
		io.hpp \
		macros.hpp \
		parser.hpp \
		sanity.hpp \
		tests.hpp \
		text.hpp \
		ui.hpp \
		user.hpp \
		utils.hpp
INCSDIR=	/usr/include/atf

INCS+=		atf.hpp
INCSDIR_atf.hpp=/usr/include

MAN=		# empty

.include <bsd.lib.mk>
