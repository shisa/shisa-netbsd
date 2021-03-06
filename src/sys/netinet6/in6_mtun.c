/*	$Id: in6_mtun.c,v 1.9 2008/02/07 05:01:04 keiichi Exp $	*/
/*	$NetBSD: in6_gif.c,v 1.44.4.1 2006/09/09 02:58:55 rpaulo Exp $	*/
/*	$KAME: in6_gif.c,v 1.62 2001/07/29 04:27:25 itojun Exp $	*/

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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$Id: in6_mtun.c,v 1.9 2008/02/07 05:01:04 keiichi Exp $");

#include "opt_inet.h"
#include "opt_iso.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#ifdef INET
#include <netinet/ip.h>
#endif
#include <netinet/ip_encap.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_mtun.h>
#include <netinet6/in6_var.h>
#ifdef MOBILE_IPV6
#include <netinet6/scope6_var.h>
#include "mip.h"
#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#endif /* MOBILE_IPV6 */
#endif /* INET6 */
#include <netinet6/ip6protosw.h>
#include <netinet/ip_ecn.h>

#include <net/if_mtun.h>

#include <net/net_osdep.h>

static int mtun_validate6 __P((const struct ip6_hdr *, struct mtun_softc *,
	struct ifnet *));

int	ip6_mtun_hlim = MTUN_HLIM;

extern struct domain inet6domain;
const struct ip6protosw in6_mtun_protosw =
{ SOCK_RAW,	&inet6domain,	0/* IPPROTO_IPV[46] */,	PR_ATOMIC|PR_ADDR,
  in6_mtun_input, rip6_output,	in6_mtun_ctlinput, rip6_ctloutput,
  rip6_usrreq,
  0,            0,              0,              0,
};

extern LIST_HEAD(, mtun_softc) mtun_softc_list;

int
in6_mtun_output(ifp, family, m)
	struct ifnet *ifp;
	int family; /* family of the packet to be encapsulate. */
	struct mbuf *m;
{
	struct rtentry *rt;
	struct mtun_softc *sc = (struct mtun_softc*)ifp;
	struct sockaddr_in6 *sin6_src = (struct sockaddr_in6 *)sc->mtun_psrc;
	struct sockaddr_in6 *sin6_dst = (struct sockaddr_in6 *)sc->mtun_pdst;
	struct ip6_hdr *ip6;
	int proto, error;
	u_int8_t itos, otos;
	union {
		struct sockaddr dst;
		struct sockaddr_in6 dst6;
	} u;
	struct ip6_pktopts pktopt;

	if (sin6_src == NULL || sin6_dst == NULL ||
	    sin6_src->sin6_family != AF_INET6 ||
	    sin6_dst->sin6_family != AF_INET6) {
		m_freem(m);
		return EAFNOSUPPORT;
	}

	switch (family) {
#ifdef INET
	case AF_INET:
	    {
		struct ip *ip;

		proto = IPPROTO_IPV4;
		if (m->m_len < sizeof(*ip)) {
			m = m_pullup(m, sizeof(*ip));
			if (!m)
				return ENOBUFS;
		}
		ip = mtod(m, struct ip *);
		itos = ip->ip_tos;
		break;
	    }
#endif
#ifdef INET6
	case AF_INET6:
	    {
#if defined (MOBILE_IPV6) && NMIP > 0
		struct in6_addr innersrc, innerdst;
#endif /* MOBILE_IPV6 && NMIP > 0 */
		proto = IPPROTO_IPV6;
		if (m->m_len < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return ENOBUFS;
		}
		ip6 = mtod(m, struct ip6_hdr *);
		itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
#if defined(MOBILE_IPV6) && NMIP > 0
		/* send a hint to start the RR procedure to the tunnel destination node */
		innersrc = ip6->ip6_src;
		in6_setscope(&innersrc, ifp, NULL);
		innerdst = ip6->ip6_dst;
		in6_setscope(&innerdst, ifp, NULL);
		mip6_notify_rr_hint(&innersrc, &innerdst);
#endif /* MOBILE_IPV6 && NMIP > 0 */
		break;
	    }
#endif
#ifdef ISO
	case AF_ISO:
		proto = IPPROTO_EON;
		itos = 0;
		break;
#endif
	default:
#ifdef DEBUG
		printf("in6_mtun_output: warning: unknown family %d passed\n",
			family);
#endif
		m_freem(m);
		return EAFNOSUPPORT;
	}

	/* prepend new IP header */
	M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip6_hdr))
		m = m_pullup(m, sizeof(struct ip6_hdr));
	if (m == NULL)
		return ENOBUFS;

	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow	= 0;
	ip6->ip6_vfc	&= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc	|= IPV6_VERSION;
#if 0	/* ip6->ip6_plen will be filled by ip6_output */
	ip6->ip6_plen	= htons((u_int16_t)m->m_pkthdr.len);
#endif
	ip6->ip6_nxt	= proto;
	ip6->ip6_hlim	= ip6_mtun_hlim;
	ip6->ip6_src	= sin6_src->sin6_addr;
	/* bidirectional configured tunnel mode */
	if (!IN6_IS_ADDR_UNSPECIFIED(&sin6_dst->sin6_addr))
		ip6->ip6_dst = sin6_dst->sin6_addr;
	else  {
		m_freem(m);
		return ENETUNREACH;
	}
	if (ifp->if_flags & IFF_LINK1)
		ip_ecn_ingress(ECN_ALLOWED, &otos, &itos);
	else
		ip_ecn_ingress(ECN_NOCARE, &otos, &itos);
	ip6->ip6_flow &= ~ntohl(0xff00000);
	ip6->ip6_flow |= htonl((u_int32_t)otos << 20);

	sockaddr_in6_init(&u.dst6, &sin6_dst->sin6_addr, 0, 0, 0);
	if ((rt = rtcache_lookup(&sc->mtun_ro, &u.dst)) == NULL) {
		printf("no cached route\n");
		m_freem(m);
		return ENETUNREACH;
	}

	/* If the route constitutes infinite encapsulation, punt. */
	if (rt->rt_ifp == ifp
		&& sc->mtun_nexthop == NULL) {
		m_freem(m);
		return ENETUNREACH;	/* XXX */
	}

	/* 
	 * if mtun has a nexthop address in the mtun_softc, point the
	 * route entry of the nexthop address and pass it to
	 * ip6_output
	 */
	bzero(&pktopt, sizeof(pktopt));
	pktopt.ip6po_hlim = -1;	/* -1 means default hop limit */
	if (sc->mtun_nexthop) {
		pktopt.ip6po_nexthop =
		    (struct sockaddr *)malloc(sizeof(struct sockaddr_in6),
		    M_IP6OPT, M_NOWAIT); 

		if (pktopt.ip6po_nexthop == NULL) {
			m_freem(m);
			return ENOMEM;
		}

		bzero(pktopt.ip6po_nexthop, sizeof(struct sockaddr_in6));
		bcopy(sc->mtun_nexthop, pktopt.ip6po_nexthop,
		    sizeof(struct sockaddr_in6));
		satosin6(pktopt.ip6po_nexthop)->sin6_scope_id = 0; /* XXX */
	}

#ifdef IPV6_MINMTU
	/*
	 * force fragmentation to minimum MTU, to avoid path MTU discovery.
	 * it is too painful to ask for resend of inner packet, to achieve
	 * path MTU discovery for encapsulated packets.
	 */
	error = ip6_output(m, &pktopt, &sc->mtun_ro, IPV6_MINMTU,
		    (struct ip6_moptions *)NULL, (struct socket *)NULL, NULL);
#else
	error = ip6_output(m, &pktopt, &sc->mtun_ro, 0,
		    (struct ip6_moptions *)NULL, (struct socket *)NULL, NULL);
#endif

	if (sc->mtun_nexthop) {
		ip6_clearpktopts(&pktopt, IPV6_NEXTHOP);
	}

	return (error);
}

int in6_mtun_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	struct mbuf *m = *mp;
	struct ifnet *mtunp = NULL;
	struct ip6_hdr *ip6;
	int af = 0;
	u_int32_t otos;

	ip6 = mtod(m, struct ip6_hdr *);

	mtunp = (struct ifnet *)encap_getarg(m);

	if (mtunp == NULL || (mtunp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		ip6stat.ip6s_nomtun++;
		return IPPROTO_DONE;
	}
	if (!mtun_validate6(ip6, (struct mtun_softc *)mtunp, m->m_pkthdr.rcvif)) {
		m_freem(m);
		ip6stat.ip6s_nomtun++;
		return IPPROTO_DONE;
	}

	otos = ip6->ip6_flow;
	m_adj(m, *offp);

	switch (proto) {
#ifdef INET
	case IPPROTO_IPV4:
	    {
		struct ip *ip;
		u_int8_t otos8;
		af = AF_INET;
		otos8 = (ntohl(otos) >> 20) & 0xff;
		if (m->m_len < sizeof(*ip)) {
			m = m_pullup(m, sizeof(*ip));
			if (!m)
				return IPPROTO_DONE;
		}
		ip = mtod(m, struct ip *);
		if (mtunp->if_flags & IFF_LINK1)
			ip_ecn_egress(ECN_ALLOWED, &otos8, &ip->ip_tos);
		else
			ip_ecn_egress(ECN_NOCARE, &otos8, &ip->ip_tos);
		break;
	    }
#endif /* INET */
#ifdef INET6
	case IPPROTO_IPV6:
	    {
		struct ip6_hdr *ip6x;
#if defined (MOBILE_IPV6) && NMIP > 0
		struct in6_addr innersrc, innerdst;
#endif /* MOBILE_IPV6 && NMIP > 0 */
		af = AF_INET6;
		if (m->m_len < sizeof(*ip6x)) {
			m = m_pullup(m, sizeof(*ip6x));
			if (!m)
				return IPPROTO_DONE;
		}
		ip6x = mtod(m, struct ip6_hdr *);
		if (mtunp->if_flags & IFF_LINK1)
			ip6_ecn_egress(ECN_ALLOWED, &otos, &ip6x->ip6_flow);
		else
			ip6_ecn_egress(ECN_NOCARE, &otos, &ip6x->ip6_flow);
#if defined(MOBILE_IPV6) && NMIP > 0
		/* send a hint to start the RR procedure to the tunnel destination node */
		innersrc = ip6x->ip6_src;
		in6_setscope(&innersrc, mtunp, NULL);
		innerdst = ip6x->ip6_dst;
		in6_setscope(&innerdst, mtunp, NULL);
		mip6_notify_rr_hint(&innerdst, &innersrc);
#endif /* MOBILE_IPV6 && NMIP > 0 */
		break;
	    }
#endif
#ifdef ISO
	case IPPROTO_EON:
		af = AF_ISO;
		break;
#endif
	default:
		ip6stat.ip6s_nomtun++;
		m_freem(m);
		return IPPROTO_DONE;
	}

	mtun_input(m, af, mtunp);
	return IPPROTO_DONE;
}

/*
 * validate outer address.
 */
static int
mtun_validate6(ip6, sc, ifp)
	const struct ip6_hdr *ip6;
	struct mtun_softc *sc;
	struct ifnet *ifp;
{
	struct sockaddr_in6 *src, *dst, *nexthop;

	src = (struct sockaddr_in6 *)sc->mtun_psrc;
	dst = (struct sockaddr_in6 *)sc->mtun_pdst;
	nexthop = (struct sockaddr_in6 *)sc->mtun_nexthop;

	/* check if the nexthop address of this mtun i/f is set */
	if (nexthop == NULL)
		return 0;

	/* check for address match */
	if (!IN6_ARE_ADDR_EQUAL(&src->sin6_addr, &ip6->ip6_dst) ||
	    !IN6_ARE_ADDR_EQUAL(&dst->sin6_addr, &ip6->ip6_src))
		return 0;

	/* martian filters on outer source - done in ip6_input */

	/* ingress filters on outer source */
	if ((sc->mtun_if.if_flags & IFF_LINK2) == 0 && ifp) {
		struct sockaddr_in6 sin6;
		struct rtentry *rt;

		bzero(&sin6, sizeof(sin6));
		bcopy(nexthop, &sin6, sizeof(sin6));
		sa6_embedscope(&sin6, ip6_use_defzone);
		rt = rtalloc1((struct sockaddr *)&sin6, 0);
		if (!rt || rt->rt_ifp != ifp) {
#if 0
			log(LOG_WARNING, "%s: packet from %s dropped "
			    "due to ingress filter\n", if_name(&sc->mtun_if),
			    ip6_sprintf(&ip6->ip6_src));
#endif
			if (rt)
				rtfree(rt);
			return 0;
		}
		rtfree(rt);
	}

	return 128 * 2;
}

int
in6_mtun_attach(sc)
	struct mtun_softc *sc;
{
	struct sockaddr_in6 mask6;

	bzero(&mask6, sizeof(mask6));
	mask6.sin6_len = sizeof(struct sockaddr_in6);
	mask6.sin6_addr.s6_addr32[0] = mask6.sin6_addr.s6_addr32[1] =
	    mask6.sin6_addr.s6_addr32[2] = mask6.sin6_addr.s6_addr32[3] = ~0;

	if (!sc->mtun_psrc || !sc->mtun_pdst)
		return EINVAL;
	sc->encap_cookie6 = encap_attach(AF_INET6, -1, sc->mtun_psrc,
	    (struct sockaddr *)&mask6, sc->mtun_pdst, (struct sockaddr *)&mask6,
	    (const void *)&in6_mtun_protosw, sc);
	if (sc->encap_cookie6 == NULL)
		return EEXIST;
	return 0;
}

int
in6_mtun_detach(sc)
	struct mtun_softc *sc;
{
	int error;

	error = encap_detach(sc->encap_cookie6);
	if (error == 0)
		sc->encap_cookie6 = NULL;

	rtcache_free(&sc->mtun_ro);

	return error;
}

void
in6_mtun_ctlinput(cmd, sa, d)
	int cmd;
	const struct sockaddr *sa;
	void *d;
{
	struct mtun_softc *sc;
	struct ip6ctlparam *ip6cp = NULL;
	struct ip6_hdr *ip6;
	const struct sockaddr_in6 *dst6;

	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;
	if (cmd == PRC_HOSTDEAD)
		d = NULL;
	else if (inet6ctlerrmap[cmd] == 0)
		return;

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ip6ctlparam *)d;
		ip6 = ip6cp->ip6c_ip6;
	} else {
		ip6 = NULL;
	}

	if (!ip6)
		return;

	/*
	 * for now we don't care which type it was, just flush the route cache.
	 * XXX slow.  sc (or sc->encap_cookie6) should be passed from
	 * ip_encap.c.
	 */
	LIST_FOREACH(sc, &mtun_softc_list, mtun_list) {
		if ((sc->mtun_if.if_flags & IFF_RUNNING) == 0)
			continue;
		if (sc->mtun_psrc->sa_family != AF_INET6)
			continue;

		dst6 = satocsin6(rtcache_getdst(&sc->mtun_ro));
		/* XXX scope */
		if (dst6 == NULL)
			;
		else if (IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &dst6->sin6_addr))
			rtcache_free(&sc->mtun_ro);
	}
}
