/*	$NetBSD: inttoa.c,v 1.2 2003/12/04 16:23:36 drochner Exp $	*/

/*
 * inttoa - return an asciized signed integer
 */
#include <stdio.h>

#include "lib_strbuf.h"
#include "ntp_stdlib.h"

char *
inttoa(
	long ival
	)
{
	register char *buf;

	LIB_GETBUF(buf);

	(void) sprintf(buf, "%ld", (long)ival);
	return buf;
}
