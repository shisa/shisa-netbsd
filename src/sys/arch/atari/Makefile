#	$NetBSD: Makefile,v 1.6 2003/01/06 17:40:23 lukem Exp $

# Makefile for atari tags file and boot blocks

# Find where m68k source files are for inclusion in tags
.include <../m68k/Makefile.inc>

TATARI=	../atari/tags
SATARI=	../atari/atari/*.[ch] ../atari/include/*.h \
	../atari/dev/*.[ch]
AATARI=	../atari/atari/*.s

# Directories in which to place tags links
DATARI=	atari dev include

.include "../../kern/Make.tags.inc"

tags:
	-ctags -wdtf ${TATARI} ${SATARI} ${SM68K} ${COMM}
	egrep "^ENTRY(.*)|^ALTENTRY(.*)" ${AATARI} ${AM68K} | \
	    sed "s;\([^:]*\):\([^(]*\)(\([^, )]*\)\(.*\);\3 \1 /^\2(\3\4$$/;" \
	    >> ${TATARI}
	sort -o ${TATARI} ${TATARI}

links:
	-for i in ${DATARI}; do \
	    cd $$i && rm -f tags; ln -s ../tags tags; done


SUBDIR=	compile dev include stand

.include <bsd.subdir.mk>
