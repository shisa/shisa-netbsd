# $Heimdal: Makefile.am,v 1.22 2001/08/28 18:44:41 nectar Exp $
# $NetBSD: Makefile.am,v 1.1.1.5 2002/09/12 12:41:40 joda Exp $

include $(top_srcdir)/Makefile.am.common

if KRB4
dir_45 = 45
endif
if OTP
dir_otp = otp
endif
if DCE
dir_dce = kdfs
endif

SUBDIRS = @DIR_roken@ vers editline @DIR_com_err@ sl asn1 @DIR_des@ krb5 \
	kafs hdb kadm5 gssapi auth $(dir_45) $(dir_otp) $(dir_dce)
