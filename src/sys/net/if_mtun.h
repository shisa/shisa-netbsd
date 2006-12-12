/*	$Id: if_mtun.h,v 1.1 2006/12/12 11:14:09 keiichi Exp $	*/
/*	$NetBSD: if_gif.h,v 1.13 2005/12/11 23:05:25 thorpej Exp $	*/
/*	$KAME: if_gif.h,v 1.23 2001/07/27 09:21:42 itojun Exp $	*/

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

/*
 * if_mtun.h
 */

#ifndef _NET_IF_MTUN_H_
#define _NET_IF_MTUN_H_

#include <sys/queue.h>

#if defined(_KERNEL) && !defined(_LKM)
#include "opt_inet.h"
#include "opt_mip6.h"
#endif

#include <netinet/in.h>
/* xxx sigh, why route have struct route instead of pointer? */

struct encaptab;

struct mtun_softc {
	struct ifnet	mtun_if;   /* common area - must be at the top */
	struct sockaddr	*mtun_psrc; /* Physical src addr */
	struct sockaddr	*mtun_pdst; /* Physical dst addr */
	union {
		struct route  mtunscr_ro;    /* xxx */
#ifdef INET6
		struct route_in6 mtunscr_ro6; /* xxx */
#endif
	} mtunsc_mtunscr;
	int		mtun_flags;
	const struct encaptab *encap_cookie4;
	const struct encaptab *encap_cookie6;
	LIST_ENTRY(mtun_softc) mtun_list;	/* list of all mtuns */
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	void	*mtun_si;		/* softintr handle */
#endif
	long	mtun_route_expire;
	struct sockaddr *mtun_nexthop;	/* nexthop address */
};
#define MTUN_ROUTE_TTL	10

#define mtun_ro mtunsc_mtunscr.mtunscr_ro
#ifdef INET6
#define mtun_ro6 mtunsc_mtunscr.mtunscr_ro6
#endif

#define MTUN_MTU	(1280)	/* Default MTU */
#define	MTUN_MTU_MIN	(1280)	/* Minimum MTU */
#define	MTUN_MTU_MAX	(8192)	/* Maximum MTU */

/* Prototypes */
void	mtunattach0(struct mtun_softc *);
void	mtun_input(struct mbuf *, int, struct ifnet *);
int	mtun_output(struct ifnet *, struct mbuf *,
		   struct sockaddr *, struct rtentry *);
int	mtun_ioctl(struct ifnet *, u_long, caddr_t);
int	mtun_set_tunnel(struct ifnet *, struct sockaddr *, struct sockaddr *);
void	mtun_delete_tunnel(struct ifnet *);

#endif /* !_NET_IF_MTUN_H_ */
