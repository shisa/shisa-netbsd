/*	$NetBSD: extern.h,v 1.9 2003/08/07 11:13:44 agc Exp $	*/

/*-
 * Copyright (c) 1991, 1993
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
 *
 *	@(#)extern.h	8.2 (Berkeley) 4/28/95
 */

extern time_t now;			/* Current time. */
extern char tbuf[1024];			/* Temp buffer for anybody. */
extern int entries;			/* Number of people. */
extern DB *db;				/* Database. */
extern int lflag;
extern int oflag;
extern int gflag;
extern int eightflag;
extern int pplan;

void	 enter_lastlog __P((PERSON *));
PERSON	*enter_person __P((struct passwd *));
void	 enter_where __P((struct utmpentry *, PERSON *));
void	 expandusername __P((const char *, const char *, char *, int));
PERSON	*find_person __P((char *));
int	 hash __P((char *));
void	 lflag_print __P((void));
int	 match __P((struct passwd *, char *));
void	 netfinger __P((char *));
PERSON	*palloc __P((void));
char	*prphone __P((char *));
int	 psort __P((const void *, const void *));
void	 sflag_print __P((void));
PERSON **sort __P((void));
