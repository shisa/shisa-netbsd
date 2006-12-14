/*	$Id: in6_mtun.h,v 1.1.2.1 2006/12/14 05:12:12 keiichi Exp $	*/
/*	$NetBSD: in6_gif.h,v 1.11 2005/12/10 23:39:56 elad Exp $	*/
/*	$KAME: in6_gif.h,v 1.7 2001/07/26 06:53:16 jinmei Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NETINET6_IN6_MTUN_H_
#define _NETINET6_IN6_MTUN_H_

#define MTUN_HLIM	30
extern int	ip6_mtun_hlim;		/* Hop limit for gif encap packet */

struct mtun_softc;
struct sockaddr;
int in6_mtun_input(struct mbuf **, int *, int);
int in6_mtun_output(struct ifnet *, int, struct mbuf *);
int in6_mtun_attach(struct mtun_softc *);
int in6_mtun_detach(struct mtun_softc *);
void in6_mtun_ctlinput(int, struct sockaddr *, void *);

#endif /* !_NETINET6_IN6_MTUN_H_ */
