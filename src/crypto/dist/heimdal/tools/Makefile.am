# $Heimdal: Makefile.am,v 1.6 2002/09/09 22:29:26 joda Exp $
# $NetBSD: Makefile.am,v 1.2 2002/09/12 13:19:24 joda Exp $

include $(top_srcdir)/Makefile.am.common

EXTRA_DIST = krb5-config.1

CLEANFILES = krb5-config

bin_SCRIPTS = krb5-config

man_MANS = krb5-config.1

krb5-config: krb5-config.in
	sed	-e "s,@PACKAGE\@,$(PACKAGE),g" \
		-e "s,@VERSION\@,$(VERSION),g" \
		-e "s,@prefix\@,$(prefix),g" \
		-e "s,@exec_prefix\@,$(exec_prefix),g" \
		-e "s,@libdir\@,$(libdir),g" \
		-e "s,@includedir\@,$(includedir),g" \
		-e "s,@LIB_crypt\@,$(LIB_crypt),g" \
		-e "s,@LIB_dbopen\@,$(LIB_dbopen),g" \
		-e "s,@INCLUDE_des\@,$(INCLUDE_des),g" \
		-e "s,@LIB_des_appl\@,$(LIB_des_appl),g" \
		-e "s,@LIBS\@,$(LIBS),g" \
		$(srcdir)/krb5-config.in > $@
	chmod +x $@
