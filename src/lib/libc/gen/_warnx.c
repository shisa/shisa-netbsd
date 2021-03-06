/*	$NetBSD: _warnx.c,v 1.7 1998/01/09 03:15:32 perry Exp $	*/

/*
 * J.T. Conklin, December 12, 1994
 * Public Domain
 */

#include <sys/cdefs.h>

#ifdef __indr_reference
__indr_reference(_warnx, warnx)
#else

#define	__NO_NAMESPACE_H	/* XXX */
#define _warnx	warnx
#define	_vwarnx	vwarnx
#define rcsid   _rcsid
#include "warnx.c"

#endif
