#	$NetBSD: Makefile,v 1.3.8.1 2005/04/06 20:47:27 tron Exp $

.include <bsd.own.mk>

SUBDIR=services

.PATH:	${X11SRCDIR.xc}/extras/freetype2/include/freetype/internal

INCSDIR=${X11INCDIR}/freetype2/freetype/internal

INCS=	autohint.h ftcalc.h \
	ftdebug.h ftdriver.h ftgloadr.h \
	ftmemory.h ftobjs.h ftrfork.h ftserv.h ftstream.h \
	fttrace.h internal.h pcftypes.h psaux.h pshints.h \
	sfnt.h t1types.h tttypes.h

.include <bsd.x11.mk>
.include <bsd.prog.mk>
.include <bsd.subdir.mk>
