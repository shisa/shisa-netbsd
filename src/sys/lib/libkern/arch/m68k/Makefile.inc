#	$NetBSD: Makefile.inc,v 1.25 2003/10/29 23:32:15 mycroft Exp $

SRCS+=	__main.c __assert.c \
	imax.c imin.c lmax.c lmin.c max.c min.c ulmax.c ulmin.c \
	bswap16.S bswap32.S bswap64.S \
	bcmp.S bzero.S \
	memchr.c memcmp.S memcpy.S memmove.S memset.S \
	strcat.S strchr.S strcmp.S strcasecmp.c \
	strcpy.S strlen.S strncmp.S strncasecmp.c strncpy.S strrchr.S \
	strtoul.c \
	scanc.S skpc.S \
	htonl.S htons.S ntohl.S ntohs.S \
	ffs.S
.if defined(MACHINE_ARCH) && (${MACHINE_ARCH} == "m68000")
SRCS+=	mulsi3.S divsi3.S udivsi3.S modsi3.S umodsi3.S
SRCS+=	random.c
random.o random.d: random.c
.else
SRCS+=	random.S
.endif
