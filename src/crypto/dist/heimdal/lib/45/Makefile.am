# $Heimdal: Makefile.am,v 1.5 1999/03/20 13:58:17 joda Exp $
# $NetBSD: Makefile.am,v 1.1.1.3 2002/09/12 12:41:40 joda Exp $

include $(top_srcdir)/Makefile.am.common

INCLUDES += $(INCLUDE_krb4)

lib_LIBRARIES = @EXTRA_LIB45@

EXTRA_LIBRARIES = lib45.a

lib45_a_SOURCES = get_ad_tkt.c mk_req.c 45_locl.h
