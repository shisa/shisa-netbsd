#	$NetBSD: Makefile,v 1.4 2004/09/18 06:49:27 rtr Exp $

XMODULEDIR=	${X11USRLIBDIR}/modules/drivers

.include "../../../../Makefile.serverlib"

MODULE=	atimisc_drv

.PATH:	${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/drivers/ati
SRCS=	atiaccel.c atiadjust.c atiaudio.c aticlock.c aticonfig.c \
	aticonsole.c aticursor.c atidac.c atidecoder.c atidsp.c \
	atii2c.c atilock.c atimach64.c atimach64accel.c \
	atimach64cursor.c atimach64i2c.c atimach64io.c \
	atimach64xv.c atimode.c atipreinit.c atiprint.c \
	atirgb514.c atiscreen.c atituner.c atiutil.c ativalid.c \
        atixv.c atibank.c ativga.c atiwonder.c atiwonderio.c \
	atiload.c atimisc.c

# NOTICE: there is a corresponding CPPFLAG below that sets -DAVOID_DGA
#         if sparc.
.if ${MACHINE} != "sparc"
SRCS+=	atidga.c
.endif

CPPFLAGS+=	-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/drivers/ati \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/common \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/os-support \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86 \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/vbe \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/int10 \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/ddc \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/i2c \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/rac \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/ramdac \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/shadowfb \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/xaa \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/xf24_32bpp \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/xf4bpp \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/xf1bpp \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/vgahw \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/fbdevhw \
		-I${X11SRCDIR.xc}/programs/Xserver/cfb \
		-I${X11SRCDIR.xc}/programs/Xserver/mfb \
		-I${X11SRCDIR.xc}/programs/Xserver/fb \
		-I${X11SRCDIR.xc}/programs/Xserver/mi \
		-I${X11SRCDIR.xc}/programs/Xserver/miext/shadow \
		-I${X11SRCDIR.xc}/programs/Xserver/render \
		-I${X11SRCDIR.xc}/programs/Xserver/Xext \
		-I${X11SRCDIR.xc}/programs/Xserver/include \
		-I${X11SRCDIR.xc}/include/fonts \
		-I${DESTDIR}${X11INCDIR}/X11 \
		-I${DESTDIR}${X11INCDIR}/X11/extensions \
		-I${XSERVERINCDIR}

# XXX from the Imakefile
# -DAVOID_CPIO must be defined for os/arch combinations that do not
# provide or emulate a little-endian undirected PIO address space of
# at least 64KB in size.  The 'first cut' configuration only explicitly
# defines the following as providing.
.if !(${MACHINE} == "i386" || \
    ${MACHINE} == "x86_64" || \
    ${MACHINE} == "amd64"  || \
    ${MACHINE} == "alpha") 
CPPFLAGS+=	-DAVOID_CPIO
.endif

# XXX from the Imakefile
# -DAVOID_NON_PCI must be defined for those platforms that do not
# tolerate PCI master aborts.
.if ${MACHINE} == "macppc"
CPPFLAGS+=	-DAVOID_NON_PCI
.endif

.if ${MACHINE} == "sparc"
CPPFLAGS+=	-DAVOID_DGA
.endif

.include <bsd.x11.mk>
LIBDIR=	${XMODULEDIR}
.include "../../Makefile.drivermod"
