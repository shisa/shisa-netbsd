#	$NetBSD: Makefile,v 1.7 2003/11/27 15:02:21 mrg Exp $

.include <bsd.own.mk>

TOP=		${NETBSDSRCDIR}/gnu

.include "${.CURDIR}/../common/Makefile.inc"
.include "${.CURDIR}/arch/${MACHINE_ARCH}/defs.mk"

PROG=		as
SRCS=		${G_OBJS:Nitbl-[pl]*:Nm68k-parse.o:.o=.c} \
		${G_OBJS:Mitbl-parse.o:.o=.y} \
		${G_OBJS:Mitbl-lex.o:.o=.l} \
		${G_OBJS:Mm68k-parse.o:.o=.y}

CPPFLAGS+=	-I${.CURDIR}/arch/${MACHINE_ARCH}
CPPFLAGS+=	-I${DIST}/gas -I${DIST}/gas/config
CPPFLAGS+=	-I${DIST}

LDADD=		-lintl
DPADD=		${LIBINTL}

OPCODESOBJ!=	cd ${TOP}/${BFDSUBDIR}/libopcodes && ${PRINTOBJDIR}
LDADD+=		-L${OPCODESOBJ} -lopcodes
.if ${MKPICLIB} != "no"
DPADD+=		${OPCODESOBJ}/libopcodes_pic.a
.else
DPADD+=		${OPCODESOBJ}/libopcodes.a
.endif

BFDOBJ!=	cd ${TOP}/${BFDSUBDIR}/libbfd && ${PRINTOBJDIR}
LDADD+=		-L${BFDOBJ} -lbfd
.if ${MKPICLIB} != "no"
DPADD+=		${BFDOBJ}/libbfd_pic.a
.else
DPADD+=		${BFDOBJ}/libbfd.a
.endif

IBERTYOBJ!=	cd ${TOP}/${BFDSUBDIR}/libiberty && ${PRINTOBJDIR}
LDADD+=		-L${IBERTYOBJ} -liberty
DPADD+=		${IBERTYOBJ}/libiberty.a

TEXINFO=	as.texinfo
INFOFLAGS=	-I${DIST}/gas/doc -I${.CURDIR}

.PATH: ${DIST}/gas ${DIST}/gas/config ${DIST}/gas/doc

.include <bsd.prog.mk>
.include <bsd.info.mk>
