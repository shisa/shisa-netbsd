/*	$Id: in_mtun.c,v 1.5 2007/02/20 02:00:23 keiichi Exp $	*/
/*	$NetBSD: in_gif.c,v 1.51 2006/11/23 04:07:07 rpaulo Exp $	*/
/*	$KAME: in_gif.c,v 1.66 2001/07/29 04:46:09 itojun Exp $	*/

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
__KERNEL_RCSID(0, "$Id: in_mtun.c,v 1.5 2007/02/20 02:00:23 keiichi Exp $");

#include "opt_inet.h"
#include "opt_iso.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_mtun.h>
#include <netinet/in_var.h>
#include <netinet/ip_encap.h>
#include <netinet/ip_ecn.h>

#ifdef INET6
#include <netinet/ip6.h>
#endif

#include <net/if_mtun.h>

#include "mtun.h"

#include <machine/stdarg.h>

#include <net/net_osdep.h>

static int mtun_validate4(const struct ip *, struct mtun_softc *,
	struct ifnet *);

#if NMTUN > 0
int ip_mtun_ttl = MTUN_TTL;
#else
int ip_mtun_ttl = 0;
#endif

const struct protosw in_mtun_protosw =
{ SOCK_RAW,	&inetdomain,	0/* IPPROTO_IPV[46] */,	PR_ATOMIC|PR_ADDR,
  in_mtun_input, rip_output,	0,		rip_ctloutput,
  rip_usrreq,
  0,            0,              0,              0,
};

int
in_mtun_output(struct ifnet *ifp, int family, struct mbuf *m)
{
	struct mtun_softc *sc = (struct mtun_softc*)ifp;
	struct sockaddr_in *dst = (struct sockaddr_in *)&sc->mtun_ro.ro_dst;
	struct sockaddr_in *sin_src = (struct sockaddr_in *)sc->mtun_psrc;
	struct sockaddr_in *sin_dst = (struct sockaddr_in *)sc->mtun_pdst;
	struct ip iphdr;	/* capsule IP header, host byte ordered */
	int proto, error;
	u_int8_t tos;

	if (sin_src == NULL || sin_dst == NULL ||
	    sin_src->sin_family != AF_INET ||
	    sin_dst->sin_family != AF_INET) {
		m_freem(m);
		return EAFNOSUPPORT;
	}

	switch (family) {
#ifdef INET
	case AF_INET:
	    {
		const struct ip *ip;

		proto = IPPROTO_IPV4;
		if (m->m_len < sizeof(*ip)) {
			m = m_pullup(m, sizeof(*ip));
			if (m == NULL)
				return ENOBUFS;
		}
		ip = mtod(m, const struct ip *);
		tos = ip->ip_tos;
		break;
	    }
#endif /* INET */
#ifdef INET6
	case AF_INET6:
	    {
		const struct ip6_hdr *ip6;
		proto = IPPROTO_IPV6;
		if (m->m_len < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return ENOBUFS;
		}
		ip6 = mtod(m, const struct ip6_hdr *);
		tos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
		break;
	    }
#endif /* INET6 */
#ifdef ISO
	case AF_ISO:
		proto = IPPROTO_EON;
		tos = 0;
		break;
#endif
	default:
#ifdef DEBUG
		printf("in_mtun_output: warning: unknown family %d passed\n",
			family);
#endif
		m_freem(m);
		return EAFNOSUPPORT;
	}

	bzero(&iphdr, sizeof(iphdr));
	iphdr.ip_src = sin_src->sin_addr;
	/* bidirectional configured tunnel mode */
	if (sin_dst->sin_addr.s_addr != INADDR_ANY)
		iphdr.ip_dst = sin_dst->sin_addr;
	else {
		m_freem(m);
		return ENETUNREACH;
	}
	iphdr.ip_p = proto;
	/* version will be set in ip_output() */
	iphdr.ip_ttl = ip_mtun_ttl;
	iphdr.ip_len = htons(m->m_pkthdr.len + sizeof(struct ip));
	if (ifp->if_flags & IFF_LINK1)
		ip_ecn_ingress(ECN_ALLOWED, &iphdr.ip_tos, &tos);
	else
		ip_ecn_ingress(ECN_NOCARE, &iphdr.ip_tos, &tos);

	/* prepend new IP header */
	M_PREPEND(m, sizeof(struct ip), M_DONTWAIT);
	/* XXX Is m_pullup really necessary after M_PREPEND? */
	if (m != NULL && M_UNWRITABLE(m, sizeof(struct ip)))
		m = m_pullup(m, sizeof(struct ip));
	if (m == NULL)
		return ENOBUFS;
	bcopy(&iphdr, mtod(m, struct ip *), sizeof(struct ip));

	if (sc->mtun_route_expire - time_second <= 0 ||
	    dst->sin_family != sin_dst->sin_family ||
	    !in_hosteq(dst->sin_addr, sin_dst->sin_addr)) {
		/* cache route doesn't match */
		bzero(dst, sizeof(*dst));
		dst->sin_family = sin_dst->sin_family;
		dst->sin_len = sizeof(struct sockaddr_in);
		dst->sin_addr = sin_dst->sin_addr;
		if (sc->mtun_ro.ro_rt) {
			RTFREE(sc->mtun_ro.ro_rt);
			sc->mtun_ro.ro_rt = NULL;
		}
	}

	if (sc->mtun_ro.ro_rt == NULL) {
		rtalloc(&sc->mtun_ro);
		if (sc->mtun_ro.ro_rt == NULL) {
			m_freem(m);
			return ENETUNREACH;
		}

		/* if it constitutes infinite encapsulation, punt. */
		if (sc->mtun_ro.ro_rt->rt_ifp == ifp) {
			m_freem(m);
			return ENETUNREACH;	/*XXX*/
		}

		sc->mtun_route_expire = time_second + MTUN_ROUTE_TTL;
	}

	error = ip_output(m, NULL, &sc->mtun_ro, 0, NULL, NULL);
	return (error);
}

void
in_mtun_input(struct mbuf *m, ...)
{
	int off, proto;
	struct ifnet *mtunp = NULL;
	const struct ip *ip;
	va_list ap;
	int af;
	u_int8_t otos;

	va_start(ap, m);
	off = va_arg(ap, int);
	proto = va_arg(ap, int);
	va_end(ap);

	ip = mtod(m, const struct ip *);

	mtunp = (struct ifnet *)encap_getarg(m);

	if (mtunp == NULL || (mtunp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		ipstat.ips_nomtun++;
		return;
	}
	if (!mtun_validate4(ip, (struct mtun_softc *)mtunp, m->m_pkthdr.rcvif)) {
		m_freem(m);
		ipstat.ips_nomtun++;
		return;
	}

	otos = ip->ip_tos;
	m_adj(m, off);

	switch (proto) {
#ifdef INET
	case IPPROTO_IPV4:
	    {
		struct ip *xip;
		af = AF_INET;
		if (M_UNWRITABLE(m, sizeof(*xip))) {
			if ((m = m_pullup(m, sizeof(*xip))) == NULL)
				return;
		}
		xip = mtod(m, struct ip *);
		if (mtunp->if_flags & IFF_LINK1)
			ip_ecn_egress(ECN_ALLOWED, &otos, &xip->ip_tos);
		else
			ip_ecn_egress(ECN_NOCARE, &otos, &xip->ip_tos);
		break;
	    }
#endif
#ifdef INET6
	case IPPROTO_IPV6:
	    {
		struct ip6_hdr *ip6;
		u_int8_t itos;
		af = AF_INET6;
		if (M_UNWRITABLE(m, sizeof(*ip6))) {
			if ((m = m_pullup(m, sizeof(*ip6))) == NULL)
				return;
		}
		ip6 = mtod(m, struct ip6_hdr *);
		itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
		if (mtunp->if_flags & IFF_LINK1)
			ip_ecn_egress(ECN_ALLOWED, &otos, &itos);
		else
			ip_ecn_egress(ECN_NOCARE, &otos, &itos);
		ip6->ip6_flow &= ~htonl(0xff << 20);
		ip6->ip6_flow |= htonl((u_int32_t)itos << 20);
		break;
	    }
#endif /* INET6 */
#ifdef ISO
	case IPPROTO_EON:
		af = AF_ISO;
		break;
#endif
	default:
		ipstat.ips_nomtun++;
		m_freem(m);
		return;
	}
	mtun_input(m, af, mtunp);
	return;
}

/*
 * validate outer address.
 */
static int
mtun_validate4(const struct ip *ip, struct mtun_softc *sc, struct ifnet *ifp)
{
	struct sockaddr_in *src, *dst;
	struct in_ifaddr *ia4;

	src = (struct sockaddr_in *)sc->mtun_psrc;
	dst = (struct sockaddr_in *)sc->mtun_pdst;

	/* check for address match */
	if (src->sin_addr.s_addr != ip->ip_dst.s_addr ||
	    dst->sin_addr.s_addr != ip->ip_src.s_addr)
		return 0;

	/* martian filters on outer source - NOT done in ip_input! */
	if (IN_MULTICAST(ip->ip_src.s_addr))
		return 0;
	switch ((ntohl(ip->ip_src.s_addr) & 0xff000000) >> 24) {
	case 0: case 127: case 255:
		return 0;
	}
	/* reject packets with broadcast on source */
	TAILQ_FOREACH(ia4, &in_ifaddrhead, ia_list) {
		if ((ia4->ia_ifa.ifa_ifp->if_flags & IFF_BROADCAST) == 0)
			continue;
		if (ip->ip_src.s_addr == ia4->ia_broadaddr.sin_addr.s_addr)
			return 0;
	}

	/* ingress filters on outer source */
	if ((sc->mtun_if.if_flags & IFF_LINK2) == 0 && ifp) {
		struct sockaddr_in sin;
		struct rtentry *rt;

		bzero(&sin, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(struct sockaddr_in);
		sin.sin_addr = ip->ip_src;
		rt = rtalloc1((struct sockaddr *)&sin, 0);
		if (!rt || rt->rt_ifp != ifp) {
#if 0
			log(LOG_WARNING, "%s: packet from 0x%x dropped "
			    "due to ingress filter\n", if_name(&sc->mtun_if),
			    (u_int32_t)ntohl(sin.sin_addr.s_addr));
#endif
			if (rt)
				rtfree(rt);
			return 0;
		}
		rtfree(rt);
	}

	return 32 * 2;
}


int
in_mtun_attach(struct mtun_softc *sc)
{
	struct sockaddr_in mask4;

	bzero(&mask4, sizeof(mask4));
	mask4.sin_len = sizeof(struct sockaddr_in);
	mask4.sin_addr.s_addr = ~0;

	if (!sc->mtun_psrc || !sc->mtun_pdst)
		return EINVAL;
	sc->encap_cookie4 = encap_attach(AF_INET, -1, sc->mtun_psrc,
	    (struct sockaddr *)&mask4, sc->mtun_pdst, (struct sockaddr *)&mask4,
	    (const struct protosw *)&in_mtun_protosw, sc);
	if (sc->encap_cookie4 == NULL)
		return EEXIST;
	return 0;
}

int
in_mtun_detach(struct mtun_softc *sc)
{
	int error;

	error = encap_detach(sc->encap_cookie4);
	if (error == 0)
		sc->encap_cookie4 = NULL;

	if (sc->mtun_ro.ro_rt) {
		RTFREE(sc->mtun_ro.ro_rt);
		sc->mtun_ro.ro_rt = NULL;
	}

	return error;
}
