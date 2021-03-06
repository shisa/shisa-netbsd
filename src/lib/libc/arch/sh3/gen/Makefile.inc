#	$NetBSD: Makefile.inc,v 1.16.6.1 2005/04/19 12:32:00 tron Exp $

SRCS+=	_setjmp.S setjmp.S sigsetjmp.S __setjmp14.S __sigsetjmp14.S

SRCS+=	makecontext.c resumecontext.c swapcontext.S

SRCS+=	_lwp.c

SRCS+=	fabs.c flt_rounds.c bswap16.c bswap32.c bswap64.c

# Common ieee754 constants and functions
SRCS+=	infinityf_ieee754.c infinity_ieee754.c infinityl_dbl_ieee754.c
SRCS+=	fpclassifyf_ieee754.c fpclassifyd_ieee754.c
SRCS+=	frexp_ieee754.c
SRCS+=	isinff_ieee754.c isinfd_ieee754.c
SRCS+=	isnanf_ieee754.c isnand_ieee754.c
SRCS+=	isfinitef_ieee754.c isfinited_ieee754.c
SRCS+=	ldexp_ieee754.c modf_ieee754.c
SRCS+=	signbitf_ieee754.c signbitd_ieee754.c

SRCS+=	nanf.c

# In gcc3 dynamic world these functions must be ".hidden" in libgcc*.a,
# as they are gcc "millicode" with different calling conventions.
.if ${HAVE_GCC3} == "no"
SRCS+=	ashiftrt.S ashlsi3.S ashrsi3.S lshrsi3.S movstr.S movstr_i4.S \
	movstrSI.S mulsi3.S sdivsi3.S udivsi3.S
.endif

KMSRCS+= ashiftrt.S ashlsi3.S ashrsi3.S lshrsi3.S movstr.S movstr_i4.S \
	movstrSI.S mulsi3.S sdivsi3.S udivsi3.S

SRCS.sh3.gen=	Lint_swapcontext.c
LSRCS+=		${SRCS.sh3.gen}
DPSRCS+=	${SRCS.sh3.gen}
CLEANFILES+=	${SRCS.sh3.gen}
