/*	$NetBSD: nanf.c,v 1.3.2.1 2005/04/19 12:30:50 tron Exp $	*/

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: nanf.c,v 1.3.2.1 2005/04/19 12:30:50 tron Exp $");
#endif /* LIBC_SCCS and not lint */

#include <math.h>
#include <machine/endian.h>

/* bytes for quiet NaN (IEEE single precision) */
const union __float_u __nanf =
		{ { 0x7f, 0xc0,    0,    0 } };
