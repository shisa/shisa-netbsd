/* $NetBSD: e_acosf.S,v 1.5 2000/05/16 19:07:35 is Exp $ */

/*
 * FPLSP wrapper for __ieee754_acosf
 * DO NOT EDIT - this file is automatically generated.
 */

#include <machine/asm.h>

ENTRY(__ieee754_acosf)
#ifdef __SVR4_ABI__
	jbra _C_LABEL(__fplsp060_0000)
#else
	movel %sp@(4),%sp@-
	jbsr _C_LABEL(__fplsp060_0000)
	fmoves %fp0,%sp@
	movel %sp@+,%d0
	rts
#endif
