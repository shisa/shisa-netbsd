/*	$NetBSD: bus_dma.c,v 1.19.2.3 2005/08/25 20:57:24 tron Exp $	*/

/*-
 * Copyright (c) 1996, 1997, 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum and by Jason R. Thorpe of the Numerical Aerospace
 * Simulation Facility, NASA Ames Research Center.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: bus_dma.c,v 1.19.2.3 2005/08/25 20:57:24 tron Exp $");

/*
 * The following is included because _bus_dma_uiomove is derived from
 * uiomove() in kern_subr.c.
 */

/*
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * All advertising materials mentioning features or use of this software
 * must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Lawrence Berkeley Laboratory.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>

#include <machine/bus.h>
#include <machine/bus_private.h>

#include <dev/isa/isareg.h>
#include <dev/isa/isavar.h>

#include <uvm/uvm_extern.h>

#include "ioapic.h"

#if NIOAPIC > 0
#include <machine/i82093var.h>
#include <machine/mpbiosvar.h>
#endif

extern	paddr_t avail_end;

#define	IDTVEC(name)	__CONCAT(X,name)
typedef void (vector) __P((void));
extern vector *IDTVEC(intr)[];

#ifdef BUSDMA_BOUNCESTATS
int bus_dma_stats_nbouncebufs;
int bus_dma_stats_loads;
int bus_dma_stats_bounces;
#define STAT_INCR(x)	(x)++
#define STAT_DECR(x)	(x)++
#else
#define STAT_INCR(x)
#define STAT_DECR(x)
#endif

static int _bus_dma_uiomove(void *, struct uio *, size_t, int);
static int _bus_dma_alloc_bouncebuf(bus_dma_tag_t t, bus_dmamap_t map,
	    bus_size_t size, int flags);
static void _bus_dma_free_bouncebuf(bus_dma_tag_t t, bus_dmamap_t map);
static int _bus_dmamap_load_buffer(bus_dma_tag_t t, bus_dmamap_t map,
	    void *buf, bus_size_t buflen, struct proc *p, int flags);
static __inline int _bus_dmamap_load_busaddr(bus_dma_tag_t, bus_dmamap_t,
    bus_addr_t, int);

#ifndef _BUS_DMAMEM_ALLOC_RANGE
#define _BUS_DMAMEM_ALLOC_RANGE _bus_dmamem_alloc_range

/*
 * Allocate physical memory from the given physical address range.
 * Called by DMA-safe memory allocation methods.
 */
int
_bus_dmamem_alloc_range(bus_dma_tag_t t, bus_size_t size, bus_size_t alignment,
    bus_size_t boundary, bus_dma_segment_t *segs, int nsegs, int *rsegs,
    int flags, bus_addr_t low, bus_addr_t high)
{
	paddr_t curaddr, lastaddr;
	struct vm_page *m;
	struct pglist mlist;
	int curseg, error;

	/* Always round the size. */
	size = round_page(size);

	/*
	 * Allocate pages from the VM system.
	 */
	error = uvm_pglistalloc(size, low, high, alignment, boundary,
	    &mlist, nsegs, (flags & BUS_DMA_NOWAIT) == 0);
	if (error)
		return (error);

	/*
	 * Compute the location, size, and number of segments actually
	 * returned by the VM code.
	 */
	m = mlist.tqh_first;
	curseg = 0;
	lastaddr = segs[curseg].ds_addr = VM_PAGE_TO_PHYS(m);
	segs[curseg].ds_len = PAGE_SIZE;
	m = m->pageq.tqe_next;

	for (; m != NULL; m = m->pageq.tqe_next) {
		curaddr = VM_PAGE_TO_PHYS(m);
#ifdef DIAGNOSTIC
		if (curaddr < low || curaddr >= high) {
			printf("vm_page_alloc_memory returned non-sensical"
			    " address 0x%lx\n", curaddr);
			panic("_bus_dmamem_alloc_range");
		}
#endif
		if (curaddr == (lastaddr + PAGE_SIZE))
			segs[curseg].ds_len += PAGE_SIZE;
		else {
			curseg++;
			segs[curseg].ds_addr = curaddr;
			segs[curseg].ds_len = PAGE_SIZE;
		}
		lastaddr = curaddr;
	}

	*rsegs = curseg + 1;

	return (0);
}
#endif /* _BUS_DMAMEM_ALLOC_RANGE */

/*
 * Create a DMA map.
 */
int
_bus_dmamap_create(bus_dma_tag_t t, bus_size_t size, int nsegments,
    bus_size_t maxsegsz, bus_size_t boundary, int flags, bus_dmamap_t *dmamp)
{
	struct x86_bus_dma_cookie *cookie;
	bus_dmamap_t map;
	int error, cookieflags;
	void *cookiestore, *mapstore;
	size_t cookiesize, mapsize;

	/*
	 * Allocate and initialize the DMA map.  The end of the map
	 * is a variable-sized array of segments, so we allocate enough
	 * room for them in one shot.
	 *
	 * Note we don't preserve the WAITOK or NOWAIT flags.  Preservation
	 * of ALLOCNOW notifies others that we've reserved these resources,
	 * and they are not to be freed.
	 *
	 * The bus_dmamap_t includes one bus_dma_segment_t, hence
	 * the (nsegments - 1).
	 */
	error = 0;
	mapsize = sizeof(struct x86_bus_dmamap) +
	    (sizeof(bus_dma_segment_t) * (nsegments - 1));
	if ((mapstore = malloc(mapsize, M_DMAMAP,
	    (flags & BUS_DMA_NOWAIT) ? M_NOWAIT : M_WAITOK)) == NULL)
		return (ENOMEM);

	memset(mapstore, 0, mapsize);
	map = (struct x86_bus_dmamap *)mapstore;
	map->_dm_size = size;
	map->_dm_segcnt = nsegments;
	map->_dm_maxmaxsegsz = maxsegsz;
	map->_dm_boundary = boundary;
	map->_dm_bounce_thresh = t->_bounce_thresh;
	map->_dm_flags = flags & ~(BUS_DMA_WAITOK|BUS_DMA_NOWAIT);
	map->dm_maxsegsz = maxsegsz;
	map->dm_mapsize = 0;		/* no valid mappings */
	map->dm_nsegs = 0;

	*dmamp = map;

	if (t->_bounce_thresh == 0 || _BUS_AVAIL_END <= t->_bounce_thresh)
		map->_dm_bounce_thresh = 0;
	cookieflags = 0;

	if (t->_may_bounce != NULL) {
		error = t->_may_bounce(t, map, flags, &cookieflags);
		if (error != 0)
			goto out;
	}

	if (map->_dm_bounce_thresh != 0)
		cookieflags |= X86_DMA_MIGHT_NEED_BOUNCE;

	if ((cookieflags & X86_DMA_MIGHT_NEED_BOUNCE) == 0)
		return 0;

	cookiesize = sizeof(struct x86_bus_dma_cookie) +
	    (sizeof(bus_dma_segment_t) * map->_dm_segcnt);

	/*
	 * Allocate our cookie.
	 */
	if ((cookiestore = malloc(cookiesize, M_DMAMAP,
	    (flags & BUS_DMA_NOWAIT) ? M_NOWAIT : M_WAITOK)) == NULL) {
		error = ENOMEM;
		goto out;
	}
	memset(cookiestore, 0, cookiesize);
	cookie = (struct x86_bus_dma_cookie *)cookiestore;
	cookie->id_flags = cookieflags;
	map->_dm_cookie = cookie;

	error = _bus_dma_alloc_bouncebuf(t, map, size, flags);
 out:
	if (error)
		_bus_dmamap_destroy(t, map);

	return (error);
}

/*
 * Destroy a DMA map.
 */
void
_bus_dmamap_destroy(bus_dma_tag_t t, bus_dmamap_t map)
{
	struct x86_bus_dma_cookie *cookie = map->_dm_cookie;

	/*
	 * Free any bounce pages this map might hold.
	 */
	if (cookie != NULL) {
		if (cookie->id_flags & X86_DMA_HAS_BOUNCE)
			_bus_dma_free_bouncebuf(t, map);
		free(cookie, M_DMAMAP);
	}

	free(map, M_DMAMAP);
}

/*
 * Load a DMA map with a linear buffer.
 */
int
_bus_dmamap_load(bus_dma_tag_t t, bus_dmamap_t map, void *buf,
    bus_size_t buflen, struct proc *p, int flags)
{
	struct x86_bus_dma_cookie *cookie = map->_dm_cookie;
	int error;

	STAT_INCR(bus_dma_stats_loads);

	/*
	 * Make sure that on error condition we return "no valid mappings."
	 */
	map->dm_mapsize = 0;
	map->dm_nsegs = 0;
	KASSERT(map->dm_maxsegsz <= map->_dm_maxmaxsegsz);

	if (buflen > map->_dm_size)
		return EINVAL;

	error = _bus_dmamap_load_buffer(t, map, buf, buflen, p, flags);
	if (error == 0) {
		map->dm_mapsize = buflen;
		return 0;
	}

	if (cookie == NULL)
		return error;
	if ((cookie->id_flags & X86_DMA_MIGHT_NEED_BOUNCE) == 0)
		return error;


	/*
	 * First attempt failed; bounce it.
	 */

	STAT_INCR(bus_dma_stats_bounces);

	/*
	 * Allocate bounce pages, if necessary.
	 */
	if ((cookie->id_flags & X86_DMA_HAS_BOUNCE) == 0) {
		error = _bus_dma_alloc_bouncebuf(t, map, buflen, flags);
		if (error)
			return (error);
	}

	/*
	 * Cache a pointer to the caller's buffer and load the DMA map
	 * with the bounce buffer.
	 */
	cookie->id_origbuf = buf;
	cookie->id_origbuflen = buflen;
	cookie->id_buftype = X86_DMA_BUFTYPE_LINEAR;
	map->dm_nsegs = 0;
	error = _bus_dmamap_load(t, map, cookie->id_bouncebuf, buflen,
	    p, flags);
	if (error)
		return (error);

	/* ...so _bus_dmamap_sync() knows we're bouncing */
	cookie->id_flags |= X86_DMA_IS_BOUNCING;
	return (0);
}

static __inline int
_bus_dmamap_load_busaddr(bus_dma_tag_t t, bus_dmamap_t map,
    bus_addr_t addr, int size)
{
	bus_dma_segment_t * const segs = map->dm_segs;
	int nseg = map->dm_nsegs;
	bus_addr_t bmask = ~(map->_dm_boundary - 1);
	bus_addr_t lastaddr = 0xdead; /* XXX gcc */
	int sgsize;
	int error = 0;

	if (nseg > 0)
		lastaddr = segs[nseg-1].ds_addr + segs[nseg-1].ds_len;
again:
	sgsize = size;
	/*
	 * Make sure we don't cross any boundaries.
	 */
	if (map->_dm_boundary > 0) {
		bus_addr_t baddr; /* next boundary address */

		baddr = (addr + map->_dm_boundary) & bmask;
		if (sgsize > (baddr - addr))
			sgsize = (baddr - addr);
	}

	/*
	 * Insert chunk into a segment, coalescing with
	 * previous segment if possible.
	 */
	if (nseg > 0 && addr == lastaddr &&
	    segs[nseg-1].ds_len + sgsize <= map->dm_maxsegsz &&
	    (map->_dm_boundary == 0 ||
	     (segs[nseg-1].ds_addr & bmask) == (addr & bmask))) {
		/* coalesce */
		segs[nseg-1].ds_len += sgsize;
	} else if (nseg >= map->_dm_segcnt) {
		return EFBIG;
	} else {
		/* new segment */
		segs[nseg].ds_addr = addr;
		segs[nseg].ds_len = sgsize;
		nseg++;
	}

	lastaddr = addr + sgsize;
	if (map->_dm_bounce_thresh != 0 && lastaddr > map->_dm_bounce_thresh)
		return EINVAL;

	addr += sgsize;
	size -= sgsize;
	if (size > 0)
		goto again;

	map->dm_nsegs = nseg;
	return error;
}

/*
 * Like _bus_dmamap_load(), but for mbufs.
 */
int
_bus_dmamap_load_mbuf(bus_dma_tag_t t, bus_dmamap_t map, struct mbuf *m0,
    int flags)
{
	struct x86_bus_dma_cookie *cookie = map->_dm_cookie;
	int error;
	struct mbuf *m;

	/*
	 * Make sure on error condition we return "no valid mappings."
	 */
	map->dm_mapsize = 0;
	map->dm_nsegs = 0;
	KASSERT(map->dm_maxsegsz <= map->_dm_maxmaxsegsz);

#ifdef DIAGNOSTIC
	if ((m0->m_flags & M_PKTHDR) == 0)
		panic("_bus_dmamap_load_mbuf: no packet header");
#endif

	if (m0->m_pkthdr.len > map->_dm_size)
		return (EINVAL);

	error = 0;
	for (m = m0; m != NULL && error == 0; m = m->m_next) {
		int offset;
		int remainbytes;
		const struct vm_page * const *pgs;
		paddr_t paddr;
		int size;

		if (m->m_len == 0)
			continue;
		switch (m->m_flags & (M_EXT|M_EXT_CLUSTER|M_EXT_PAGES)) {
		case M_EXT|M_EXT_CLUSTER:
			/* XXX KDASSERT */
			KASSERT(m->m_ext.ext_paddr != M_PADDR_INVALID);
			paddr = m->m_ext.ext_paddr +
			    (m->m_data - m->m_ext.ext_buf);
			size = m->m_len;
			error = _bus_dmamap_load_busaddr(t, map,
			    _BUS_PHYS_TO_BUS(paddr), size);
			break;

		case M_EXT|M_EXT_PAGES:
			KASSERT(m->m_ext.ext_buf <= m->m_data);
			KASSERT(m->m_data <=
			    m->m_ext.ext_buf + m->m_ext.ext_size);

			offset = (vaddr_t)m->m_data -
			    trunc_page((vaddr_t)m->m_ext.ext_buf);
			remainbytes = m->m_len;

			/* skip uninteresting pages */
			pgs = (const struct vm_page * const *)
			    m->m_ext.ext_pgs + (offset >> PAGE_SHIFT);

			offset &= PAGE_MASK; /* offset in the first page */

			/* load each pages */
			while (remainbytes > 0) {
				const struct vm_page *pg;
				bus_addr_t busaddr;

				size = MIN(remainbytes, PAGE_SIZE - offset);

				pg = *pgs++;
				KASSERT(pg);
				busaddr = _BUS_VM_PAGE_TO_BUS(pg) + offset;

				error = _bus_dmamap_load_busaddr(t, map,
				    busaddr, size);
				if (error)
					break;
				offset = 0;
				remainbytes -= size;
			}
			break;

		case 0:
			paddr = m->m_paddr + M_BUFOFFSET(m) +
			    (m->m_data - M_BUFADDR(m));
			size = m->m_len;
			error = _bus_dmamap_load_busaddr(t, map,
			    _BUS_PHYS_TO_BUS(paddr), size);
			break;

		default:
			error = _bus_dmamap_load_buffer(t, map, m->m_data,
			    m->m_len, NULL, flags);
		}
	}
	if (error == 0) {
		map->dm_mapsize = m0->m_pkthdr.len;
		return 0;
	}

	map->dm_nsegs = 0;

	if (cookie == NULL ||
	    ((cookie->id_flags & X86_DMA_MIGHT_NEED_BOUNCE) == 0))
		return error;

	/*
	 * First attempt failed; bounce it.
	 */

	STAT_INCR(bus_dma_stats_bounces);

	/*
	 * Allocate bounce pages, if necessary.
	 */
	if ((cookie->id_flags & X86_DMA_HAS_BOUNCE) == 0) {
		error = _bus_dma_alloc_bouncebuf(t, map, m0->m_pkthdr.len,
		    flags);
		if (error)
			return (error);
	}

	/*
	 * Cache a pointer to the caller's buffer and load the DMA map
	 * with the bounce buffer.
	 */
	cookie->id_origbuf = m0;
	cookie->id_origbuflen = m0->m_pkthdr.len;	/* not really used */
	cookie->id_buftype = X86_DMA_BUFTYPE_MBUF;
	error = _bus_dmamap_load(t, map, cookie->id_bouncebuf,
	    m0->m_pkthdr.len, NULL, flags);
	if (error)
		return (error);

	/* ...so _bus_dmamap_sync() knows we're bouncing */
	cookie->id_flags |= X86_DMA_IS_BOUNCING;
	return (0);
}

/*
 * Like _bus_dmamap_load(), but for uios.
 */
int
_bus_dmamap_load_uio(bus_dma_tag_t t, bus_dmamap_t map, struct uio *uio,
    int flags)
{
	int i, error;
	bus_size_t minlen, resid;
	struct proc *p = NULL;
	struct iovec *iov;
	caddr_t addr;
	struct x86_bus_dma_cookie *cookie = map->_dm_cookie;

	/*
	 * Make sure that on error condition we return "no valid mappings."
	 */
	map->dm_mapsize = 0;
	map->dm_nsegs = 0;
	KASSERT(map->dm_maxsegsz <= map->_dm_maxmaxsegsz);

	resid = uio->uio_resid;
	iov = uio->uio_iov;

	if (uio->uio_segflg == UIO_USERSPACE) {
		p = uio->uio_procp;
#ifdef DIAGNOSTIC
		if (p == NULL)
			panic("_bus_dmamap_load_uio: USERSPACE but no proc");
#endif
	}

	error = 0;
	for (i = 0; i < uio->uio_iovcnt && resid != 0 && error == 0; i++) {
		/*
		 * Now at the first iovec to load.  Load each iovec
		 * until we have exhausted the residual count.
		 */
		minlen = resid < iov[i].iov_len ? resid : iov[i].iov_len;
		addr = (caddr_t)iov[i].iov_base;

		error = _bus_dmamap_load_buffer(t, map, addr, minlen,
		    p, flags);

		resid -= minlen;
	}
	if (error == 0) {
		map->dm_mapsize = uio->uio_resid;
		return 0;
	}

	map->dm_nsegs = 0;

	if (cookie == NULL ||
	    ((cookie->id_flags & X86_DMA_MIGHT_NEED_BOUNCE) == 0))
		return error;

	STAT_INCR(bus_dma_stats_bounces);

	/*
	 * Allocate bounce pages, if necessary.
	 */
	if ((cookie->id_flags & X86_DMA_HAS_BOUNCE) == 0) {
		error = _bus_dma_alloc_bouncebuf(t, map, uio->uio_resid,
		    flags);
		if (error)
			return (error);
	}

	/*
	 * Cache a pointer to the caller's buffer and load the DMA map
	 * with the bounce buffer.
	 */
	cookie->id_origbuf = uio;
	cookie->id_origbuflen = uio->uio_resid;
	cookie->id_buftype = X86_DMA_BUFTYPE_UIO;
	error = _bus_dmamap_load(t, map, cookie->id_bouncebuf,
	    uio->uio_resid, NULL, flags);
	if (error)
		return (error);

	/* ...so _bus_dmamap_sync() knows we're bouncing */
	cookie->id_flags |= X86_DMA_IS_BOUNCING;
	return (0);
}

/*
 * Like _bus_dmamap_load(), but for raw memory allocated with
 * bus_dmamem_alloc().
 */
int
_bus_dmamap_load_raw(bus_dma_tag_t t, bus_dmamap_t map, bus_dma_segment_t *segs,
    int nsegs, bus_size_t size, int flags)
{

	panic("_bus_dmamap_load_raw: not implemented");
}

/*
 * Unload a DMA map.
 */
void
_bus_dmamap_unload(bus_dma_tag_t t, bus_dmamap_t map)
{
	struct x86_bus_dma_cookie *cookie = map->_dm_cookie;

	/*
	 * If we have bounce pages, free them, unless they're
	 * reserved for our exclusive use.
	 */
	if (cookie != NULL) {
		cookie->id_flags &= ~X86_DMA_IS_BOUNCING;
		cookie->id_buftype = X86_DMA_BUFTYPE_INVALID;
	}
	map->dm_maxsegsz = map->_dm_maxmaxsegsz;
	map->dm_mapsize = 0;
	map->dm_nsegs = 0;
}

/*
 * Synchronize a DMA map.
 */
void
_bus_dmamap_sync(bus_dma_tag_t t, bus_dmamap_t map, bus_addr_t offset,
    bus_size_t len, int ops)
{
	struct x86_bus_dma_cookie *cookie = map->_dm_cookie;

	/*
	 * Mixing PRE and POST operations is not allowed.
	 */
	if ((ops & (BUS_DMASYNC_PREREAD|BUS_DMASYNC_PREWRITE)) != 0 &&
	    (ops & (BUS_DMASYNC_POSTREAD|BUS_DMASYNC_POSTWRITE)) != 0)
		panic("_bus_dmamap_sync: mix PRE and POST");

#ifdef DIAGNOSTIC
	if ((ops & (BUS_DMASYNC_PREWRITE|BUS_DMASYNC_POSTREAD)) != 0) {
		if (offset >= map->dm_mapsize)
			panic("_bus_dmamap_sync: bad offset");
		if ((offset + len) > map->dm_mapsize)
			panic("_bus_dmamap_sync: bad length");
	}
#endif

	/*
	 * If we're not bouncing, just return; nothing to do.
	 */
	if (len == 0 || cookie == NULL ||
	    (cookie->id_flags & X86_DMA_IS_BOUNCING) == 0)
		return;

	switch (cookie->id_buftype) {
	case X86_DMA_BUFTYPE_LINEAR:
		/*
		 * Nothing to do for pre-read.
		 */

		if (ops & BUS_DMASYNC_PREWRITE) {
			/*
			 * Copy the caller's buffer to the bounce buffer.
			 */
			memcpy((char *)cookie->id_bouncebuf + offset,
			    (char *)cookie->id_origbuf + offset, len);
		}

		if (ops & BUS_DMASYNC_POSTREAD) {
			/*
			 * Copy the bounce buffer to the caller's buffer.
			 */
			memcpy((char *)cookie->id_origbuf + offset,
			    (char *)cookie->id_bouncebuf + offset, len);
		}

		/*
		 * Nothing to do for post-write.
		 */
		break;

	case X86_DMA_BUFTYPE_MBUF:
	    {
		struct mbuf *m, *m0 = cookie->id_origbuf;
		bus_size_t minlen, moff;

		/*
		 * Nothing to do for pre-read.
		 */

		if (ops & BUS_DMASYNC_PREWRITE) {
			/*
			 * Copy the caller's buffer to the bounce buffer.
			 */
			m_copydata(m0, offset, len,
			    (char *)cookie->id_bouncebuf + offset);
		}

		if (ops & BUS_DMASYNC_POSTREAD) {
			/*
			 * Copy the bounce buffer to the caller's buffer.
			 */
			for (moff = offset, m = m0; m != NULL && len != 0;
			     m = m->m_next) {
				/* Find the beginning mbuf. */
				if (moff >= m->m_len) {
					moff -= m->m_len;
					continue;
				}

				/*
				 * Now at the first mbuf to sync; nail
				 * each one until we have exhausted the
				 * length.
				 */
				minlen = len < m->m_len - moff ?
				    len : m->m_len - moff;

				memcpy(mtod(m, caddr_t) + moff,
				    (char *)cookie->id_bouncebuf + offset,
				    minlen);

				moff = 0;
				len -= minlen;
				offset += minlen;
			}
		}

		/*
		 * Nothing to do for post-write.
		 */
		break;
	    }
	case X86_DMA_BUFTYPE_UIO:
	    {
		struct uio *uio;

		uio = (struct uio *)cookie->id_origbuf;

		/*
		 * Nothing to do for pre-read.
		 */

		if (ops & BUS_DMASYNC_PREWRITE) {
			/*
			 * Copy the caller's buffer to the bounce buffer.
			 */
			_bus_dma_uiomove((char *)cookie->id_bouncebuf + offset,
			    uio, len, UIO_WRITE);
		}

		if (ops & BUS_DMASYNC_POSTREAD) {
			_bus_dma_uiomove((char *)cookie->id_bouncebuf + offset,
			    uio, len, UIO_READ);
		}

		/*
		 * Nothing to do for post-write.
		 */
		break;
	    }

	case X86_DMA_BUFTYPE_RAW:
		panic("_bus_dmamap_sync: X86_DMA_BUFTYPE_RAW");
		break;

	case X86_DMA_BUFTYPE_INVALID:
		panic("_bus_dmamap_sync: X86_DMA_BUFTYPE_INVALID");
		break;

	default:
		printf("unknown buffer type %d\n", cookie->id_buftype);
		panic("_bus_dmamap_sync");
	}
}

/*
 * Allocate memory safe for DMA.
 */
int
_bus_dmamem_alloc(bus_dma_tag_t t, bus_size_t size, bus_size_t alignment,
    bus_size_t boundary, bus_dma_segment_t *segs, int nsegs, int *rsegs,
    int flags)
{
	bus_addr_t high;

	if (t->_bounce_alloc_hi != 0 && _BUS_AVAIL_END > t->_bounce_alloc_hi)
		high = trunc_page(t->_bounce_alloc_hi);
	else
		high = trunc_page(_BUS_AVAIL_END);

	return (_BUS_DMAMEM_ALLOC_RANGE(t, size, alignment, boundary,
	    segs, nsegs, rsegs, flags, t->_bounce_alloc_lo, high));
}

static int
_bus_dma_alloc_bouncebuf(bus_dma_tag_t t, bus_dmamap_t map,
    bus_size_t size, int flags)
{
	struct x86_bus_dma_cookie *cookie = map->_dm_cookie;
	int error = 0;

#ifdef DIAGNOSTIC
	if (cookie == NULL)
		panic("_bus_dma_alloc_bouncebuf: no cookie");
#endif

	cookie->id_bouncebuflen = round_page(size);
	error = _bus_dmamem_alloc(t, cookie->id_bouncebuflen,
	    PAGE_SIZE, map->_dm_boundary, cookie->id_bouncesegs,
	    map->_dm_segcnt, &cookie->id_nbouncesegs, flags);
	if (error)
		goto out;
	error = _bus_dmamem_map(t, cookie->id_bouncesegs,
	    cookie->id_nbouncesegs, cookie->id_bouncebuflen,
	    (caddr_t *)&cookie->id_bouncebuf, flags);

 out:
	if (error) {
		_bus_dmamem_free(t, cookie->id_bouncesegs,
		    cookie->id_nbouncesegs);
		cookie->id_bouncebuflen = 0;
		cookie->id_nbouncesegs = 0;
	} else {
		cookie->id_flags |= X86_DMA_HAS_BOUNCE;
		STAT_INCR(bus_dma_stats_nbouncebufs);
	}

	return (error);
}

static void
_bus_dma_free_bouncebuf(bus_dma_tag_t t, bus_dmamap_t map)
{
	struct x86_bus_dma_cookie *cookie = map->_dm_cookie;

#ifdef DIAGNOSTIC
	if (cookie == NULL)
		panic("_bus_dma_alloc_bouncebuf: no cookie");
#endif

	STAT_DECR(bus_dma_stats_nbouncebufs);

	_bus_dmamem_unmap(t, cookie->id_bouncebuf, cookie->id_bouncebuflen);
	_bus_dmamem_free(t, cookie->id_bouncesegs,
	    cookie->id_nbouncesegs);
	cookie->id_bouncebuflen = 0;
	cookie->id_nbouncesegs = 0;
	cookie->id_flags &= ~X86_DMA_HAS_BOUNCE;
}


/*
 * This function does the same as uiomove, but takes an explicit
 * direction, and does not update the uio structure.
 */
static int
_bus_dma_uiomove(void *buf, struct uio *uio, size_t n, int direction)
{
	struct iovec *iov;
	int error;
	struct proc *p;
	char *cp;
	size_t resid, cnt;
	int i;

	iov = uio->uio_iov;
	p = uio->uio_procp;
	cp = buf;
	resid = n;

	for (i = 0; i < uio->uio_iovcnt && resid > 0; i++) {
		iov = &uio->uio_iov[i];
		if (iov->iov_len == 0)
			continue;
		cnt = MIN(resid, iov->iov_len);

		if (uio->uio_segflg == UIO_USERSPACE) {
			if (curlwp != NULL &&
			    curlwp->l_cpu->ci_schedstate.spc_flags &
			      SPCF_SHOULDYIELD)
				preempt(1);
			if (p == curproc) {
				if (direction == UIO_READ)
					error = copyout(cp, iov->iov_base, cnt);
				else
					error = copyin(iov->iov_base, cp, cnt);
			} else {
				if (direction == UIO_READ)
					error = copyout_proc(p, cp,
					    iov->iov_base, cnt);
				else
					error = copyin_proc(p, iov->iov_base,
					    cp, cnt);
			}
			if (error)
				return (error);
		} else {
			if (direction == UIO_READ)
				error = kcopy(cp, iov->iov_base, cnt);
			else
				error = kcopy(iov->iov_base, cp, cnt);
			if (error)
				return (error);
		}
		cp += cnt;
		resid -= cnt;
	}
	return (0);
}

/*
 * Common function for freeing DMA-safe memory.  May be called by
 * bus-specific DMA memory free functions.
 */
void
_bus_dmamem_free(bus_dma_tag_t t, bus_dma_segment_t *segs, int nsegs)
{
	struct vm_page *m;
	bus_addr_t addr;
	struct pglist mlist;
	int curseg;

	/*
	 * Build a list of pages to free back to the VM system.
	 */
	TAILQ_INIT(&mlist);
	for (curseg = 0; curseg < nsegs; curseg++) {
		for (addr = segs[curseg].ds_addr;
		    addr < (segs[curseg].ds_addr + segs[curseg].ds_len);
		    addr += PAGE_SIZE) {
			m = PHYS_TO_VM_PAGE(addr);
			TAILQ_INSERT_TAIL(&mlist, m, pageq);
		}
	}

	uvm_pglistfree(&mlist);
}

/*
 * Common function for mapping DMA-safe memory.  May be called by
 * bus-specific DMA memory map functions.
 * This supports BUS_DMA_NOCACHE.
 */
int
_bus_dmamem_map(bus_dma_tag_t t, bus_dma_segment_t *segs, int nsegs,
    size_t size, caddr_t *kvap, int flags)
{
	vaddr_t va;
	bus_addr_t addr;
	int curseg;
	int32_t cpumask;
	int nocache;
	int marked;
	pt_entry_t *pte;

	size = round_page(size);
	cpumask = 0;
	nocache = (flags & BUS_DMA_NOCACHE) != 0 && pmap_cpu_has_pg_n();
	marked = 0;

	va = uvm_km_valloc(kernel_map, size);

	if (va == 0)
		return (ENOMEM);

	*kvap = (caddr_t)va;

	for (curseg = 0; curseg < nsegs; curseg++) {
		for (addr = segs[curseg].ds_addr;
		    addr < (segs[curseg].ds_addr + segs[curseg].ds_len);
		    addr += PAGE_SIZE, va += PAGE_SIZE, size -= PAGE_SIZE) {
			if (size == 0)
				panic("_bus_dmamem_map: size botch");
			pmap_enter(pmap_kernel(), va, addr,
			    VM_PROT_READ | VM_PROT_WRITE,
			    PMAP_WIRED | VM_PROT_READ | VM_PROT_WRITE);
			/*
			 * mark page as non-cacheable
			 */
			if (nocache) {
				pte = kvtopte(va);
				if ((*pte & PG_N) == 0) {
					*pte |= PG_N;
					pmap_tlb_shootdown(pmap_kernel(), va,
					    *pte, &cpumask);
					marked = 1;
				}
			}
		}
	}
	if (marked)
		pmap_tlb_shootnow(cpumask);
	pmap_update(pmap_kernel());

	return (0);
}

/*
 * Common function for unmapping DMA-safe memory.  May be called by
 * bus-specific DMA memory unmapping functions.
 */

void
_bus_dmamem_unmap(bus_dma_tag_t t, caddr_t kva, size_t size)
{
	pt_entry_t *pte;
	vaddr_t va, endva;
	int cpumask;
	int marked;

	cpumask = 0;
	marked = 0;
#ifdef DIAGNOSTIC
	if ((u_long)kva & PGOFSET)
		panic("_bus_dmamem_unmap");
#endif

	size = round_page(size);
	/*
         * mark pages cacheable again.
         */
	for (va = (vaddr_t)kva, endva = (vaddr_t)kva + size;
	     va < endva; va += PAGE_SIZE) {
		pte = kvtopte(va);
		if ((*pte & PG_N) != 0) {
			*pte &= ~PG_N;
			pmap_tlb_shootdown(pmap_kernel(), va, *pte, &cpumask);
			marked = 1;
		}
	}
	if (marked)
		pmap_tlb_shootnow(cpumask);

	uvm_km_free(kernel_map, (vaddr_t)kva, size);
}

/*
 * Common functin for mmap(2)'ing DMA-safe memory.  May be called by
 * bus-specific DMA mmap(2)'ing functions.
 */
paddr_t
_bus_dmamem_mmap(bus_dma_tag_t t, bus_dma_segment_t *segs, int nsegs,
    off_t off, int prot, int flags)
{
	int i;

	for (i = 0; i < nsegs; i++) {
#ifdef DIAGNOSTIC
		if (off & PGOFSET)
			panic("_bus_dmamem_mmap: offset unaligned");
		if (segs[i].ds_addr & PGOFSET)
			panic("_bus_dmamem_mmap: segment unaligned");
		if (segs[i].ds_len & PGOFSET)
			panic("_bus_dmamem_mmap: segment size not multiple"
			    " of page size");
#endif
		if (off >= segs[i].ds_len) {
			off -= segs[i].ds_len;
			continue;
		}

		return (x86_btop((caddr_t)segs[i].ds_addr + off));
	}

	/* Page not found. */
	return (-1);
}

/**********************************************************************
 * DMA utility functions
 **********************************************************************/

/*
 * Utility function to load a linear buffer.
 */
static int
_bus_dmamap_load_buffer(bus_dma_tag_t t, bus_dmamap_t map, void *buf,
    bus_size_t buflen, struct proc *p, int flags)
{
	bus_size_t sgsize;
	bus_addr_t curaddr;
	vaddr_t vaddr = (vaddr_t)buf;
	pmap_t pmap;

	if (p != NULL)
		pmap = p->p_vmspace->vm_map.pmap;
	else
		pmap = pmap_kernel();

	while (buflen > 0) {
		int error;

		/*
		 * Get the bus address for this segment.
		 */
		curaddr = _BUS_VIRT_TO_BUS(pmap, vaddr);

		/*
		 * If we're beyond the bounce threshold, notify
		 * the caller.
		 */
		if (map->_dm_bounce_thresh != 0 &&
		    curaddr >= map->_dm_bounce_thresh)
			return (EINVAL);

		/*
		 * Compute the segment size, and adjust counts.
		 */
		sgsize = PAGE_SIZE - ((u_long)vaddr & PGOFSET);
		if (buflen < sgsize)
			sgsize = buflen;

		error = _bus_dmamap_load_busaddr(t, map, curaddr, sgsize);
		if (error)
			return error;

		vaddr += sgsize;
		buflen -= sgsize;
	}

	return (0);
}

