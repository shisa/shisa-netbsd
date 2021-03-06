# $NetBSD: Makefile,v 1.9 2004/06/21 18:20:08 jmc Exp $
#
# Makefile to generate windows VC++ project and workspace files from
# config files and templates

.include <bsd.sys.mk>		# for HOST_SH

PROJECT_DIRS=libsa pbsdboot libz

all: winfiles optfiles rom-boot

winfiles: 
	for name in $(PROJECT_DIRS); do \
	    ${HOST_SH} dspgen/config.sh vc6 $$name; \
	    ${HOST_SH} dspgen/config.sh evc3 $$name; \
	done
	${HOST_SH} dspgen/gen_workspace.sh vc6 hpcmips_stand.dsw $(PROJECT_DIRS)
	${HOST_SH} dspgen/gen_workspace.sh evc3 hpcmips_stand.vcw $(PROJECT_DIRS)

optfiles:
	echo "/* option \`SPEC_PLATFORM' not defined */" \
            > pbsdboot/opt_spec_platform.h

# remote transient build-related files globally and for each project:
#	* global 'class view' information (.ncb)
#	* Debug and Release compile dirs,
#	* .plg files (build logs), and
#	* .[0-9][0-9][0-9] files (old versions of auto-converted .dsp files).

rom-boot:
	(cd romboot; make)

clean:
	rm -f hpcmips_stand.ncb
	-for dir in $(PROJECT_DIRS); do \
	    (cd $$dir && rm -rf WMIPSDbg wmipsdbg WMIPSRel wmipsrel); \
	    (cd $$dir && rm -f $$dir.plg $$dir.vcl $$dir.[0-9][0-9][0-9]); \
	    (cd $$dir && rm -f $$dir.ncb $$dir.opt); \
	done
	rm -f pbsdboot/opt_spec_platform.h
	(cd romboot; make clean)

# remove all files which windows is likely to have created, in addition
# to transient build-related files:
#	* .opt workspace option file
#	* (probably automatic) updates to the .dsp and .dsw files,
#	  which should be identical to the auto-generated versions when
#	  clean.

distclean cleandir: clean winfiles
	rm -f hpcmips_stand.opt
	rm -f hpcmips_stand.vcw
	rm -f hpcmips_stand.vco
	rm -f hpcmips_stand.vcb
	for dir in $(PROJECT_DIRS); do \
	    (cd $$dir && rm -f $$dir.vcp); \
	done
