/*	$Id: if_mtun.c,v 1.2 2007/01/13 18:54:44 keiichi Exp $	*/
/*	$NetBSD: if_gif.c,v 1.64 2006/11/23 04:07:07 rpaulo Exp $	*/
/*	$KAME: if_gif.c,v 1.76 2001/08/20 02:01:02 kjc Exp $	*/

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
__KERNEL_RCSID(0, "$Id: if_mtun.c,v 1.2 2007/01/13 18:54:44 keiichi Exp $");

#include "opt_inet.h"
#include "opt_iso.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/kauth.h>

#include <machine/cpu.h>
#include <machine/intr.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef	INET
#include <netinet/in_var.h>
#endif	/* INET */
#include <netinet/in_mtun.h>

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_mtun.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/scope6_var.h>
#endif /* INET6 */

#ifdef ISO
#include <netiso/iso.h>
#include <netiso/iso_var.h>
#endif

#include <netinet/ip_encap.h>
#include <net/if_mtun.h>

#include "bpfilter.h"

#include <net/net_osdep.h>

void	mtunattach(int);
#ifndef __HAVE_GENERIC_SOFT_INTERRUPTS
static void	mtunnetisr(void);
#endif
static void	mtunintr(void *);
#ifdef ISO
static struct mbuf *mtun_eon_encap(struct mbuf *);
static struct mbuf *mtun_eon_decap(struct ifnet *, struct mbuf *);
#endif

/*
 * mtun global variable definitions
 */
LIST_HEAD(, mtun_softc) mtun_softc_list;	/* XXX should be static */

static int	mtun_clone_create(struct if_clone *, int);
static int	mtun_clone_destroy(struct ifnet *);

static struct if_clone mtun_cloner =
    IF_CLONE_INITIALIZER("mtun", mtun_clone_create, mtun_clone_destroy);

#ifndef MAX_MTUN_NEST
/*
 * This macro controls the upper limitation on nesting of mtun tunnels.
 * Since, setting a large value to this macro with a careless configuration
 * may introduce system crash, we don't allow any nestings by default.
 * If you need to configure nested mtun tunnels, you can define this macro
 * in your kernel configuration file.  However, if you do so, please be
 * careful to configure the tunnels so that it won't make a loop.
 */
#define MAX_MTUN_NEST 1
#endif
static int max_mtun_nesting = MAX_MTUN_NEST;

/* ARGSUSED */
void
mtunattach(int count)
{

	LIST_INIT(&mtun_softc_list);
	if_clone_attach(&mtun_cloner);
}

static int
mtun_clone_create(struct if_clone *ifc, int unit)
{
	struct mtun_softc *sc;

	sc = malloc(sizeof(struct mtun_softc), M_DEVBUF, M_WAIT);
	memset(sc, 0, sizeof(struct mtun_softc));

	snprintf(sc->mtun_if.if_xname, sizeof(sc->mtun_if.if_xname), "%s%d",
	    ifc->ifc_name, unit);

	mtunattach0(sc);

	LIST_INSERT_HEAD(&mtun_softc_list, sc, mtun_list);
	return (0);
}

void
mtunattach0(struct mtun_softc *sc)
{

	sc->encap_cookie4 = sc->encap_cookie6 = NULL;

	sc->mtun_if.if_addrlen = 0;
	sc->mtun_if.if_mtu    = MTUN_MTU;
	sc->mtun_if.if_flags  = IFF_POINTOPOINT | IFF_MULTICAST;
	sc->mtun_if.if_ioctl  = mtun_ioctl;
	sc->mtun_if.if_output = mtun_output;
	sc->mtun_if.if_type   = IFT_MTUN;
	sc->mtun_if.if_dlt    = DLT_NULL;
	IFQ_SET_READY(&sc->mtun_if.if_snd);
	if_attach(&sc->mtun_if);
	if_alloc_sadl(&sc->mtun_if);
#if NBPFILTER > 0
	bpfattach(&sc->mtun_if, DLT_NULL, sizeof(u_int));
#endif
}

static int
mtun_clone_destroy(struct ifnet *ifp)
{
	struct mtun_softc *sc = (void *) ifp;

	mtun_delete_tunnel(&sc->mtun_if);
	LIST_REMOVE(sc, mtun_list);
#ifdef INET6
	encap_detach(sc->encap_cookie6);
#endif
#ifdef INET
	encap_detach(sc->encap_cookie4);
#endif

#if NBPFILTER > 0
	bpfdetach(ifp);
#endif
	if_detach(ifp);

	free(sc, M_DEVBUF);

	return (0);
}

int
mtun_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
    struct rtentry *rt)
{
	struct mtun_softc *sc = (struct mtun_softc*)ifp;
	int error = 0;
	static int called = 0;	/* XXX: MUTEX */
	ALTQ_DECL(struct altq_pktattr pktattr;)
	int s;

	IFQ_CLASSIFY(&ifp->if_snd, m, dst->sa_family, &pktattr);

	/*
	 * mtun may cause infinite recursion calls when misconfigured.
	 * We'll prevent this by introducing upper limit.
	 * XXX: this mechanism may introduce another problem about
	 *      mutual exclusion of the variable CALLED, especially if we
	 *      use kernel thread.
	 */
	if (++called > max_mtun_nesting) {
		log(LOG_NOTICE,
		    "mtun_output: recursively called too many times(%d)\n",
		    called);
		m_freem(m);
		error = EIO;	/* is there better errno? */
		goto end;
	}

	m->m_flags &= ~(M_BCAST|M_MCAST);
	if (!(ifp->if_flags & IFF_UP) ||
	    sc->mtun_psrc == NULL || sc->mtun_pdst == NULL) {
		m_freem(m);
		error = ENETDOWN;
		goto end;
	}

	/* inner AF-specific encapsulation */
	switch (dst->sa_family) {
#ifdef ISO
	case AF_ISO:
		m = mtun_eon_encap(m);
		if (!m) {
			error = ENOBUFS;
			goto end;
		}
		break;
#endif
	default:
		break;
	}

	/* XXX should we check if our outer source is legal? */

	/* use DLT_NULL encapsulation here to pass inner af type */
	M_PREPEND(m, sizeof(int), M_DONTWAIT);
	if (!m) {
		error = ENOBUFS;
		goto end;
	}
	*mtod(m, int *) = dst->sa_family;

	s = splnet();
	IFQ_ENQUEUE(&ifp->if_snd, m, &pktattr, error);
	if (error) {
		splx(s);
		goto end;
	}
	splx(s);

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	softintr_schedule(sc->mtun_si);
#else
	/* XXX bad spl level? */
	mtunnetisr();
#endif
	error = 0;

  end:
	called = 0;		/* reset recursion counter */
	if (error)
		ifp->if_oerrors++;
	return error;
}

#ifndef __HAVE_GENERIC_SOFT_INTERRUPTS
static void
mtunnetisr(void)
{
	struct mtun_softc *sc;

	for (sc = LIST_FIRST(&mtun_softc_list); sc != NULL;
	     sc = LIST_NEXT(sc, mtun_list)) {
		mtunintr(sc);
	}
}
#endif

static void
mtunintr(void *arg)
{
	struct mtun_softc *sc;
	struct ifnet *ifp;
	struct mbuf *m;
	int family;
	int len;
	int s;
	int error;

	sc = (struct mtun_softc *)arg;
	ifp = &sc->mtun_if;

	/* output processing */
	while (1) {
		s = splnet();
		IFQ_DEQUEUE(&sc->mtun_if.if_snd, m);
		splx(s);
		if (m == NULL)
			break;

		/* grab and chop off inner af type */
		if (sizeof(int) > m->m_len) {
			m = m_pullup(m, sizeof(int));
			if (!m) {
				ifp->if_oerrors++;
				continue;
			}
		}
		family = *mtod(m, int *);
#if NBPFILTER > 0
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, m);
#endif
		m_adj(m, sizeof(int));

		len = m->m_pkthdr.len;

		/* dispatch to output logic based on outer AF */
		switch (sc->mtun_psrc->sa_family) {
#ifdef INET
		case AF_INET:
			error = in_mtun_output(ifp, family, m);
			break;
#endif
#ifdef INET6
		case AF_INET6:
			error = in6_mtun_output(ifp, family, m);
			break;
#endif
		default:
			m_freem(m);
			error = ENETDOWN;
			break;
		}

		if (error)
			ifp->if_oerrors++;
		else {
			ifp->if_opackets++;
			ifp->if_obytes += len;
		}
	}
}

void
mtun_input(struct mbuf *m, int af, struct ifnet *ifp)
{
	int s, isr;
	struct ifqueue *ifq = NULL;

	if (ifp == NULL) {
		/* just in case */
		m_freem(m);
		return;
	}

	m->m_pkthdr.rcvif = ifp;

#if NBPFILTER > 0
	if (ifp->if_bpf)
		bpf_mtap_af(ifp->if_bpf, af, m);
#endif /*NBPFILTER > 0*/

	/*
	 * Put the packet to the network layer input queue according to the
	 * specified address family.
	 * Note: older versions of mtun_input directly called network layer
	 * input functions, e.g. ip6_input, here.  We changed the policy to
	 * prevent too many recursive calls of such input functions, which
	 * might cause kernel panic.  But the change may introduce another
	 * problem; if the input queue is full, packets are discarded.
	 * The kernel stack overflow really happened, and we believed
	 * queue-full rarely occurs, so we changed the policy.
	 */
	switch (af) {
#ifdef INET
	case AF_INET:
		ifq = &ipintrq;
		isr = NETISR_IP;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		ifq = &ip6intrq;
		isr = NETISR_IPV6;
		break;
#endif
#ifdef ISO
	case AF_ISO:
		m = mtun_eon_decap(ifp, m);
		if (!m)
			return;
		ifq = &clnlintrq;
		isr = NETISR_ISO;
		break;
#endif
	default:
		m_freem(m);
		return;
	}

	s = splnet();
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);	/* update statistics */
		m_freem(m);
		splx(s);
		return;
	}
	ifp->if_ipackets++;
	ifp->if_ibytes += m->m_pkthdr.len;
	IF_ENQUEUE(ifq, m);
	/* we need schednetisr since the address family may change */
	schednetisr(isr);
	splx(s);
}

/* XXX how should we handle IPv6 scope on SIOC[GS]IFPHYADDR? */
int
mtun_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct lwp *l = curlwp;	/* XXX */
	struct mtun_softc *sc  = (struct mtun_softc*)ifp;
	struct ifreq     *ifr = (struct ifreq*)data;
	int error = 0, size;
	struct sockaddr *dst, *src;
#ifdef SIOCSIFMTU
	u_long mtu;
#endif

	switch (cmd) {
	case SIOCSIFMTU:
	case SIOCSLIFPHYADDR:
#ifdef SIOCDIFPHYADDR
	case SIOCDIFPHYADDR:
#endif
		if ((error = kauth_authorize_network(l->l_cred,
		    KAUTH_NETWORK_INTERFACE,
		    KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ifp, (void *)cmd,
		    NULL)) != 0)
			return (error);
		/* FALLTHROUGH */
	default:
		break;
	}

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		break;

	case SIOCSIFDSTADDR:
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		switch (ifr->ifr_addr.sa_family) {
#ifdef INET
		case AF_INET:	/* IP supports Multicast */
			break;
#endif /* INET */
#ifdef INET6
		case AF_INET6:	/* IP6 supports Multicast */
			break;
#endif /* INET6 */
		default:  /* Other protocols doesn't support Multicast */
			error = EAFNOSUPPORT;
			break;
		}
		break;

#ifdef	SIOCSIFMTU /* xxx */
	case SIOCGIFMTU:
		break;

	case SIOCSIFMTU:
		mtu = ifr->ifr_mtu;
		if (mtu < MTUN_MTU_MIN || mtu > MTUN_MTU_MAX)
			return (EINVAL);
		ifp->if_mtu = mtu;
		break;
#endif /* SIOCSIFMTU */

#ifdef INET
	case SIOCSIFPHYADDR:
#endif
#ifdef INET6
	case SIOCSIFPHYADDR_IN6:
#endif /* INET6 */
	case SIOCSLIFPHYADDR:
		switch (cmd) {
#ifdef INET
		case SIOCSIFPHYADDR:
			src = (struct sockaddr *)
				&(((struct in_aliasreq *)data)->ifra_addr);
			dst = (struct sockaddr *)
				&(((struct in_aliasreq *)data)->ifra_dstaddr);
			break;
#endif
#ifdef INET6
		case SIOCSIFPHYADDR_IN6:
			src = (struct sockaddr *)
				&(((struct in6_aliasreq *)data)->ifra_addr);
			dst = (struct sockaddr *)
				&(((struct in6_aliasreq *)data)->ifra_dstaddr);
			break;
#endif
		case SIOCSLIFPHYADDR:
			src = (struct sockaddr *)
				&(((struct if_laddrreq *)data)->addr);
			dst = (struct sockaddr *)
				&(((struct if_laddrreq *)data)->dstaddr);
			break;
		default:
			return EINVAL;
		}

		/* sa_family must be equal */
		if (src->sa_family != dst->sa_family)
			return EINVAL;

		/* validate sa_len */
		switch (src->sa_family) {
#ifdef INET
		case AF_INET:
			if (src->sa_len != sizeof(struct sockaddr_in))
				return EINVAL;
			break;
#endif
#ifdef INET6
		case AF_INET6:
			if (src->sa_len != sizeof(struct sockaddr_in6))
				return EINVAL;
			break;
#endif
		default:
			return EAFNOSUPPORT;
		}
		switch (dst->sa_family) {
#ifdef INET
		case AF_INET:
			if (dst->sa_len != sizeof(struct sockaddr_in))
				return EINVAL;
			break;
#endif
#ifdef INET6
		case AF_INET6:
			if (dst->sa_len != sizeof(struct sockaddr_in6))
				return EINVAL;
			break;
#endif
		default:
			return EAFNOSUPPORT;
		}

		/* check sa_family looks sane for the cmd */
		switch (cmd) {
		case SIOCSIFPHYADDR:
			if (src->sa_family == AF_INET)
				break;
			return EAFNOSUPPORT;
#ifdef INET6
		case SIOCSIFPHYADDR_IN6:
			if (src->sa_family == AF_INET6)
				break;
			return EAFNOSUPPORT;
#endif /* INET6 */
		case SIOCSLIFPHYADDR:
			/* checks done in the above */
			break;
		}

		error = mtun_set_tunnel(&sc->mtun_if, src, dst);
		break;

#ifdef SIOCDIFPHYADDR
	case SIOCDIFPHYADDR:
		mtun_delete_tunnel(&sc->mtun_if);
		break;
#endif

	case SIOCGIFPSRCADDR:
#ifdef INET6
	case SIOCGIFPSRCADDR_IN6:
#endif /* INET6 */
		if (sc->mtun_psrc == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->mtun_psrc;
		switch (cmd) {
#ifdef INET
		case SIOCGIFPSRCADDR:
			dst = &ifr->ifr_addr;
			size = sizeof(ifr->ifr_addr);
			break;
#endif /* INET */
#ifdef INET6
		case SIOCGIFPSRCADDR_IN6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof(((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:
			error = EADDRNOTAVAIL;
			goto bad;
		}
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		break;

	case SIOCGIFPDSTADDR:
#ifdef INET6
	case SIOCGIFPDSTADDR_IN6:
#endif /* INET6 */
		if (sc->mtun_pdst == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->mtun_pdst;
		switch (cmd) {
#ifdef INET
		case SIOCGIFPDSTADDR:
			dst = &ifr->ifr_addr;
			size = sizeof(ifr->ifr_addr);
			break;
#endif /* INET */
#ifdef INET6
		case SIOCGIFPDSTADDR_IN6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof(((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:
			error = EADDRNOTAVAIL;
			goto bad;
		}
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		break;

	case SIOCGLIFPHYADDR:
		if (sc->mtun_psrc == NULL || sc->mtun_pdst == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}

		/* copy src */
		src = sc->mtun_psrc;
		dst = (struct sockaddr *)
			&(((struct if_laddrreq *)data)->addr);
		size = sizeof(((struct if_laddrreq *)data)->addr);
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);

		/* copy dst */
		src = sc->mtun_pdst;
		dst = (struct sockaddr *)
			&(((struct if_laddrreq *)data)->dstaddr);
		size = sizeof(((struct if_laddrreq *)data)->dstaddr);
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		break;

	case SIOCSIFFLAGS:
		/* if_ioctl() takes care of it */
		break;

	case SIOCSIFPHYNEXTHOP: 
#ifdef INET6
	case SIOCSIFPHYNEXTHOP_IN6: {
#endif /* INET6 */
		struct sockaddr *nh = NULL;
		int nhlen = 0;

		switch (ifr->ifr_addr.sa_family) {
#ifdef INET
		case AF_INET:	/* IP supports Multicast */
			error = EAFNOSUPPORT;
			break;
#endif /* INET */
#ifdef INET6
		case AF_INET6:	/* IP6 supports Multicast */
			nh = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			nhlen = sizeof(((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:  /* Other protocols doesn't support Multicast */
			error = EAFNOSUPPORT;
			break;
		}

		if (error)
			return error;

		/* if pointer is null, allocate memory */
		if (sc->mtun_nexthop == NULL) {
			sc->mtun_nexthop = (struct sockaddr *)malloc(nhlen, M_IFADDR, M_WAITOK);
			if (sc->mtun_nexthop == NULL)
				return ENOMEM;

			bzero(sc->mtun_nexthop, nhlen);
		}
		/* set request address into mtun_nexthop */
		bcopy(nh, sc->mtun_nexthop, nhlen);
		sa6_embedscope(satosin6(sc->mtun_nexthop), ip6_use_defzone);
		break;
	}
	case SIOCGIFPHYNEXTHOP: 
#ifdef INET6
	case SIOCGIFPHYNEXTHOP_IN6: {
#endif /* INET6 */
		if (sc->mtun_nexthop == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->mtun_nexthop;
		switch (cmd) {
#ifdef INET
		case SIOCGIFPHYNEXTHOP:
			dst = &ifr->ifr_addr;
			size = sizeof(ifr->ifr_addr);
			break;
#endif /* INET */
#ifdef INET6
		case SIOCGIFPHYNEXTHOP_IN6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof(((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:
			error = EADDRNOTAVAIL;
			goto bad;
		}
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
#ifdef INET6
		if (dst->sa_family == AF_INET6) {
			error = sa6_recoverscope((struct sockaddr_in6 *)dst);
			if (error != 0)
				goto bad;
		}
#endif
		break;
	}
	case SIOCDIFPHYNEXTHOP: 
		/* if pointer is not null, free the memory */
		if (sc->mtun_nexthop) 
			free(sc->mtun_nexthop, M_IFADDR);
		sc->mtun_nexthop = NULL;
		break;

	default:
		error = EINVAL;
		break;
	}
 bad:
	return error;
}

int
mtun_set_tunnel(struct ifnet *ifp, struct sockaddr *src, struct sockaddr *dst)
{
	struct mtun_softc *sc = (struct mtun_softc *)ifp;
	struct mtun_softc *sc2;
	struct sockaddr *osrc, *odst, *sa;
	int s;
	int error;

	s = splsoftnet();

	for (sc2 = LIST_FIRST(&mtun_softc_list); sc2 != NULL;
	     sc2 = LIST_NEXT(sc2, mtun_list)) {
		if (sc2 == sc)
			continue;
		if (!sc2->mtun_pdst || !sc2->mtun_psrc)
			continue;
		if (sc2->mtun_pdst->sa_family != dst->sa_family ||
		    sc2->mtun_pdst->sa_len != dst->sa_len ||
		    sc2->mtun_psrc->sa_family != src->sa_family ||
		    sc2->mtun_psrc->sa_len != src->sa_len)
			continue;
		/* can't configure same pair of address onto two mtuns */
		if (bcmp(sc2->mtun_pdst, dst, dst->sa_len) == 0 &&
		    bcmp(sc2->mtun_psrc, src, src->sa_len) == 0) {
			error = EADDRNOTAVAIL;
			goto bad;
		}

		/* XXX both end must be valid? (I mean, not 0.0.0.0) */
	}

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	if (sc->mtun_si) {
		softintr_disestablish(sc->mtun_si);
		sc->mtun_si = NULL;
	}
#endif

	/* XXX we can detach from both, but be polite just in case */
	if (sc->mtun_psrc)
		switch (sc->mtun_psrc->sa_family) {
#ifdef INET
		case AF_INET:
			(void)in_mtun_detach(sc);
			break;
#endif
#ifdef INET6
		case AF_INET6:
			(void)in6_mtun_detach(sc);
			break;
#endif
		}

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	sc->mtun_si = softintr_establish(IPL_SOFTNET, mtunintr, sc);
	if (sc->mtun_si == NULL) {
		error = ENOMEM;
		goto bad;
	}
#endif

	osrc = sc->mtun_psrc;
	sa = (struct sockaddr *)malloc(src->sa_len, M_IFADDR, M_WAITOK);
	bcopy((caddr_t)src, (caddr_t)sa, src->sa_len);
	sc->mtun_psrc = sa;

	odst = sc->mtun_pdst;
	sa = (struct sockaddr *)malloc(dst->sa_len, M_IFADDR, M_WAITOK);
	bcopy((caddr_t)dst, (caddr_t)sa, dst->sa_len);
	sc->mtun_pdst = sa;

	switch (sc->mtun_psrc->sa_family) {
#ifdef INET
	case AF_INET:
		error = in_mtun_attach(sc);
		break;
#endif
#ifdef INET6
	case AF_INET6:
		error = in6_mtun_attach(sc);
		break;
#endif
	default:
		error = EINVAL;
		break;
	}
	if (error) {
		/* rollback */
		free((caddr_t)sc->mtun_psrc, M_IFADDR);
		free((caddr_t)sc->mtun_pdst, M_IFADDR);
		sc->mtun_psrc = osrc;
		sc->mtun_pdst = odst;
		goto bad;
	}

	if (osrc)
		free((caddr_t)osrc, M_IFADDR);
	if (odst)
		free((caddr_t)odst, M_IFADDR);

	if (sc->mtun_psrc && sc->mtun_pdst)
		ifp->if_flags |= IFF_RUNNING;
	else
		ifp->if_flags &= ~IFF_RUNNING;
	splx(s);

	return 0;

 bad:
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	if (sc->mtun_si) {
		softintr_disestablish(sc->mtun_si);
		sc->mtun_si = NULL;
	}
#endif
	if (sc->mtun_psrc && sc->mtun_pdst)
		ifp->if_flags |= IFF_RUNNING;
	else
		ifp->if_flags &= ~IFF_RUNNING;
	splx(s);

	return error;
}

void
mtun_delete_tunnel(struct ifnet *ifp)
{
	struct mtun_softc *sc = (struct mtun_softc *)ifp;
	int s;

	s = splsoftnet();

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	if (sc->mtun_si) {
		softintr_disestablish(sc->mtun_si);
		sc->mtun_si = NULL;
	}
#endif
	if (sc->mtun_psrc) {
		free((caddr_t)sc->mtun_psrc, M_IFADDR);
		sc->mtun_psrc = NULL;
	}
	if (sc->mtun_pdst) {
		free((caddr_t)sc->mtun_pdst, M_IFADDR);
		sc->mtun_pdst = NULL;
	}
	/* it is safe to detach from both */
#ifdef INET
	(void)in_mtun_detach(sc);
#endif
#ifdef INET6
	(void)in6_mtun_detach(sc);
#endif

	if (sc->mtun_psrc && sc->mtun_pdst)
		ifp->if_flags |= IFF_RUNNING;
	else
		ifp->if_flags &= ~IFF_RUNNING;
	splx(s);
}

#ifdef ISO
struct eonhdr {
	u_int8_t version;
	u_int8_t class;
	u_int16_t cksum;
};

/*
 * prepend EON header to ISO PDU
 */
static struct mbuf *
mtun_eon_encap(struct mbuf *m)
{
	struct eonhdr *ehdr;

	M_PREPEND(m, sizeof(*ehdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(*ehdr))
		m = m_pullup(m, sizeof(*ehdr));
	if (m == NULL)
		return NULL;
	ehdr = mtod(m, struct eonhdr *);
	ehdr->version = 1;
	ehdr->class = 0;		/* always unicast */
#if 0
	/* calculate the checksum of the eonhdr */
	{
		struct mbuf mhead;
		memset(&mhead, 0, sizeof(mhead));
		ehdr->cksum = 0;
		mhead.m_data = (caddr_t)ehdr;
		mhead.m_len = sizeof(*ehdr);
		mhead.m_next = 0;
		iso_gen_csum(&mhead, offsetof(struct eonhdr, cksum),
		    mhead.m_len);
	}
#else
	/* since the data is always constant we'll just plug the value in */
	ehdr->cksum = htons(0xfc02);
#endif
	return m;
}

/*
 * remove EON header and check checksum
 */
static struct mbuf *
mtun_eon_decap(struct ifnet *ifp, struct mbuf *m)
{
	struct eonhdr *ehdr;

	if (m->m_len < sizeof(*ehdr) &&
	    (m = m_pullup(m, sizeof(*ehdr))) == NULL) {
		ifp->if_ierrors++;
		return NULL;
	}
	if (iso_check_csum(m, sizeof(struct eonhdr))) {
		m_freem(m);
		return NULL;
	}
	m_adj(m, sizeof(*ehdr));
	return m;
}
#endif /*ISO*/
