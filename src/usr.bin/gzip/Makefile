#	$NetBSD: Makefile,v 1.9 2004/05/21 12:16:10 agc Exp $

PROG=		gzip
MAN=		gzip.1 gzexe.1 zdiff.1 zforce.1 zgrep.1 zmore.1 znew.1

DPADD=		${LIBZ} ${LIBBZ2}
LDADD=		-lz -lbz2
WARNS=		3

SCRIPTS=	gzexe zdiff zforce zgrep zmore znew

MLINKS+=	gzip.1 gunzip.1 \
		gzip.1 gzcat.1 \
		gzip.1 zcat.1 \
		zdiff.1 zcmp.1 \
		zgrep.1 zegrep.1 \
		zgrep.1 zfgrep.1

LINKS+=		${BINDIR}/gzip ${BINDIR}/gunzip \
		${BINDIR}/gzip ${BINDIR}/gzcat \
		${BINDIR}/gzip ${BINDIR}/zcat \
		${BINDIR}/zdiff ${BINDIR}/zcmp \
		${BINDIR}/zgrep ${BINDIR}/zegrep \
		${BINDIR}/zgrep ${BINDIR}/zfgrep

.include <bsd.prog.mk>
