#	$NetBSD: Makefile,v 1.1 2004/03/06 11:44:41 rtr Exp $

.include <bsd.own.mk>

KMOD=	radeon
MKMAN=	no

.PATH:	${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/os-support/shared/drm/kernel
SRCS=	radeon_cp.c radeon_state.c radeon_irq.c radeon_mem.c

.PATH:	${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/os-support/bsd/drm/kernel
SRCS+=	radeon_drv.c

DPSRCS=	opt_drm.h

opt_drm.h:
	echo > opt_drm.h
	echo "#define DRM_DEBUG 1" >> opt_drm.h
	echo "#define DRM_LINUX 1" >> opt_drm.h

CPPFLAGS+=	-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/os-support/bsd/drm/kernel \
		-I${X11SRCDIR.xc}/programs/Xserver/hw/xfree86/os-support/shared/drm/kernel

.include <bsd.kmod.mk>
