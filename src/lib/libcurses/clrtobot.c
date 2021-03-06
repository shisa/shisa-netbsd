/*	$NetBSD: clrtobot.c,v 1.15 2003/08/07 16:44:19 agc Exp $	*/

/*
 * Copyright (c) 1981, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifndef lint
#if 0
static char sccsid[] = "@(#)clrtobot.c	8.2 (Berkeley) 5/4/94";
#else
__RCSID("$NetBSD: clrtobot.c,v 1.15 2003/08/07 16:44:19 agc Exp $");
#endif
#endif				/* not lint */

#include "curses.h"
#include "curses_private.h"

#ifndef _CURSES_USE_MACROS

/*
 * clrtobot --
 *	Erase everything on stdscr.
 */
int
clrtobot(void)
{
	return wclrtobot(stdscr);
}

#endif

/*
 * wclrtobot --
 *	Erase everything on the window.
 */
int
wclrtobot(WINDOW *win)
{
	int	 minx, startx, starty, y;
	__LDATA	*sp, *end, *maxx;

#ifdef __GNUC__
	maxx = NULL;		/* XXX gcc -Wuninitialized */
#endif
	if (win->lines[win->cury]->flags & __ISPASTEOL) {
		starty = win->cury + 1;
		startx = 0;
	} else {
		starty = win->cury;
		startx = win->curx;
	}
	for (y = starty; y < win->maxy; y++) {
		minx = -1;
		end = &win->lines[y]->line[win->maxx];
		for (sp = &win->lines[y]->line[startx]; sp < end; sp++)
			if (sp->ch != ' ' || sp->attr != 0 ||
			    sp->bch != win->bch || sp->battr != win->battr) {
				maxx = sp;
				if (minx == -1)
					minx = sp - win->lines[y]->line;
				sp->ch = ' ';
				sp->bch = win->bch;
				sp->attr = 0;
				sp->battr = win->battr;
			}
		if (minx != -1)
			__touchline(win, y, minx, maxx - win->lines[y]->line);
		startx = 0;
	}
	return (OK);
}
