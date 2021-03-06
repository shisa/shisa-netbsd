/*	$NetBSD: bus_dma.c,v 1.7 2005/03/09 19:04:45 matt Exp $	*/

/*-
 * Copyright (c) 1997, 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
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
__KERNEL_RCSID(0, "$NetBSD: bus_dma.c,v 1.7 2005/03/09 19:04:45 matt Exp $");

#define DEBUG 1

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/mbuf.h>

#include <uvm/uvm.h>
#include <uvm/uvm_extern.h>

#define _POWERPC_BUS_DMA_PRIVATE
#include <machine/bus.h>
#include <machine/intr.h>
#include <machine/cpu.h>		/* for CACHELINESIZE */

#ifdef DEBUG
int busdmadebug = 0;
# define DPRINTF(x)	do { if (busdmadebug) printf x ; } while (0)
#else
# define DPRINTF(x)
#endif

static inline void
invaldcache(vaddr_t va, bus_size_t sz)
{
	int off;

	DPRINTF(("invaldcache: %#lx %ld\n", va, (long) sz));
	KASSERT(sz != 0);

	__asm __volatile("eieio;");
	off = (u_int)va & (CACHELINESIZE - 1);
	sz += off;
	va -= off;
	while ((int)sz > 0) {
		__asm __volatile("dcbi 0, %0;" :: "r"(va));
		va += CACHELINESIZE;
		sz -= CACHELINESIZE;
	}
	__asm __volatile("sync;");
}

static inline void
flushdcache(vaddr_t va, bus_size_t sz)
{
	int off;

	DPRINTF(("flushdcache: %#lx %ld\n", va, (long) sz));
	KASSERT(sz != 0);

	__asm __volatile("eieio;");
	off = (u_int)va & (CACHELINESIZE - 1);
	sz += off;
	va -= off;
	while ((int)sz > CACHELINESIZE) {
		__asm __volatile("dcbf 0, %0;" :: "r"(va));
		va += CACHELINESIZE;
		sz -= CACHELINESIZE;
	}

	/*
	 * eieio ensures the last cache line flushed is ordered last
	 * read-after-write ensures last cache line
	 * (and therefore all cache lines) made it to  memory
	 */
	__asm __volatile("eieio; dcbf 0, %0;" :: "r"(va));
	__asm __volatile("lwz %0,0(%0); sync;" : "+r"(va));
}

static inline void
storedcache(vaddr_t va, bus_size_t sz)
{
	int off;

	DPRINTF(("storedcache: %#lx %ld\n", va, (long) sz));
	KASSERT(sz != 0);

	__asm __volatile("eieio;");
	off = (u_int)va & (CACHELINESIZE - 1);
	sz += off;
	va -= off;
	while ((int)sz > 0) {
		__asm __volatile("dcbst 0, %0;" :: "r"(va));
		va += CACHELINESIZE;
		sz -= CACHELINESIZE;
	}
	__asm __volatile("sync;");
}

int	_bus_dmamap_load_buffer __P((bus_dma_tag_t, bus_dmamap_t, void *,
	    bus_size_t, struct proc *, int, paddr_t *, int *, int));

/*
 * Common function for DMA map creation.  May be called by bus-specific
 * DMA map creation functions.
 */
int
_bus_dmamap_create(t, size, nsegments, maxsegsz, boundary, flags, dmamp)
	bus_dma_tag_t t;
	bus_size_t size;
	int nsegments;
	bus_size_t maxsegsz;
	bus_size_t boundary;
	int flags;
	bus_dmamap_t *dmamp;
{
	struct powerpc_bus_dmamap *map;
	void *mapstore;
	size_t mapsize;

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
	mapsize = sizeof(struct powerpc_bus_dmamap) +
	    (sizeof(bus_dma_segment_t) * (nsegments - 1));
	if ((mapstore = malloc(mapsize, M_DMAMAP,
	    (flags & BUS_DMA_NOWAIT) ? M_NOWAIT : M_WAITOK)) == NULL)
		return (ENOMEM);

	bzero(mapstore, mapsize);
	map = (struct powerpc_bus_dmamap *)mapstore;
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
	return (0);
}

/*
 * Common function for DMA map destruction.  May be called by bus-specific
 * DMA map destruction functions.
 */
void
_bus_dmamap_destroy(t, map)
	bus_dma_tag_t t;
	bus_dmamap_t map;
{

	free(map, M_DMAMAP);
}

/*
 * Utility function to load a linear buffer.  lastaddrp holds state
 * between invocations (for multiple-buffer loads).  segp contains
 * the starting segment on entrance, and the ending segment on exit.
 * first indicates if this is the first invocation of this function.
 */
int
_bus_dmamap_load_buffer(t, map, buf, buflen, p, flags, lastaddrp, segp, first)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	void *buf;
	bus_size_t buflen;
	struct proc *p;
	int flags;
	paddr_t *lastaddrp;
	int *segp;
	int first;
{
	bus_size_t sgsize;
	bus_addr_t curaddr, lastaddr, baddr, bmask;
	vaddr_t vaddr = (vaddr_t)buf;
	int seg;

	lastaddr = *lastaddrp;
	bmask = ~(map->_dm_boundary - 1);

	for (seg = *segp; buflen > 0 ; ) {
		/*
		 * Get the physical address for this segment.
		 */
		KASSERT(p == NULL);	/* we "never" use the p!=NULL case */
		if (p != NULL)
			(void) pmap_extract(p->p_vmspace->vm_map.pmap,
			    vaddr, (paddr_t *)&curaddr);
		else
			curaddr = vtophys(vaddr);

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

		/*
		 * Make sure we don't cross any boundaries.
		 */
		if (map->_dm_boundary > 0) {
			baddr = (curaddr + map->_dm_boundary) & bmask;
			if (sgsize > (baddr - curaddr))
				sgsize = (baddr - curaddr);
		}

		/*
		 * Insert chunk into a segment, coalescing with
		 * the previous segment if possible.
		 */
		if (first) {
			map->dm_segs[seg].ds_addr = curaddr;
			map->dm_segs[seg].ds_len = sgsize;
			map->dm_segs[seg].ds_vaddr = vaddr;
			first = 0;
		} else {
			if ((curaddr == lastaddr) &&
			   (vaddr == map->dm_segs[seg].ds_vaddr +
				(curaddr - map->dm_segs[seg].ds_addr)) &&
			    ((map->dm_segs[seg].ds_len + sgsize) <=
			     map->dm_maxsegsz) &&
			    ((map->_dm_boundary == 0) ||
			     ((map->dm_segs[seg].ds_addr & bmask) ==
			     (curaddr & bmask)))) {
				map->dm_segs[seg].ds_len += sgsize;
			} else {
				if (++seg >= map->_dm_segcnt) {
#ifdef DEBUG
					panic("_bus_dmamap_load_buffer: "
						"seg %d >= _dm_segcnt %d\n",
						seg, map->_dm_segcnt);
#endif
					break;
				}
				map->dm_segs[seg].ds_addr = curaddr;
				map->dm_segs[seg].ds_len = sgsize;
				map->dm_segs[seg].ds_vaddr = vaddr;
			}
		}

		lastaddr = curaddr + sgsize;
		vaddr += sgsize;
		buflen -= sgsize;
	}

	*segp = seg;
	*lastaddrp = lastaddr;

	/*
	 * Did we fit?
	 */
	if (buflen != 0)
		return (EFBIG);		/* XXX better return value here? */

	return (0);
}

/*
 * Common function for loading a DMA map with a linear buffer.  May
 * be called by bus-specific DMA map load functions.
 */
int
_bus_dmamap_load(t, map, buf, buflen, p, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	void *buf;
	bus_size_t buflen;
	struct proc *p;
	int flags;
{
	paddr_t lastaddr;
	int seg, error;

	/*
	 * Make sure that on error condition we return "no valid mappings".
	 */
	map->dm_mapsize = 0;
	map->dm_nsegs = 0;
	KASSERT(map->dm_maxsegsz <= map->_dm_maxmaxsegsz);

	if (buflen > map->_dm_size)
		return (EINVAL);

	seg = 0;
	error = _bus_dmamap_load_buffer(t, map, buf, buflen, p, flags,
		&lastaddr, &seg, 1);
	if (error == 0) {
		map->dm_mapsize = buflen;
		map->dm_nsegs = seg + 1;
	}
	return (error);
}

/*
 * Like _bus_dmamap_load(), but for mbufs.
 */
int
_bus_dmamap_load_mbuf(t, map, m0, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	struct mbuf *m0;
	int flags;
{
	paddr_t lastaddr;
	int seg, error, first;
	struct mbuf *m;

	/*
	 * Make sure that on error condition we return "no valid mappings."
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

	first = 1;
	seg = 0;
	error = 0;
	for (m = m0; m != NULL && error == 0; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		error = _bus_dmamap_load_buffer(t, map, m->m_data, m->m_len,
		    NULL, flags, &lastaddr, &seg, first);
		first = 0;
	}
	if (error == 0) {
		map->dm_mapsize = m0->m_pkthdr.len;
		map->dm_nsegs = seg + 1;
	}
	return (error);
}

/*
 * Like _bus_dmamap_load(), but for uios.
 */
int
_bus_dmamap_load_uio(t, map, uio, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	struct uio *uio;
	int flags;
{
	paddr_t lastaddr;
	int seg, i, error, first;
	bus_size_t minlen, resid;
	struct proc *p = NULL;
	struct iovec *iov;
	caddr_t addr;

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

	first = 1;
	seg = 0;
	error = 0;
	for (i = 0; i < uio->uio_iovcnt && resid != 0 && error == 0; i++) {
		/*
		 * Now at the first iovec to load.  Load each iovec
		 * until we have exhausted the residual count.
		 */
		minlen = resid < iov[i].iov_len ? resid : iov[i].iov_len;
		addr = (caddr_t)iov[i].iov_base;

		error = _bus_dmamap_load_buffer(t, map, addr, minlen,
		    p, flags, &lastaddr, &seg, first);
		first = 0;

		resid -= minlen;
	}
	if (error == 0) {
		map->dm_mapsize = uio->uio_resid;
		map->dm_nsegs = seg + 1;
	}
	return (error);
}

/*
 * Like _bus_dmamap_load(), but for raw memory.
 */
int
_bus_dmamap_load_raw(t, map, segs, nsegs, size, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	bus_dma_segment_t *segs;
	int nsegs;
	bus_size_t size;
	int flags;
{

	panic("_bus_dmamap_load_raw: not implemented");
}

/*
 * Common function for unloading a DMA map.  May be called by
 * chipset-specific DMA map unload functions.
 */
void
_bus_dmamap_unload(t, map)
	bus_dma_tag_t t;
	bus_dmamap_t map;
{
	/*
	 * No resources to free; just mark the mappings as
	 * invalid.
	 */
	map->dm_maxsegsz = map->_dm_maxmaxsegsz;
	map->dm_mapsize = 0;
	map->dm_nsegs = 0;
}

/*
 * DMA map synchronization, provides software coherency
 */
void
_bus_dmamap_sync(t, map, offset, len, ops)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	bus_addr_t offset;
	bus_size_t len;
	int ops;
{
	int i;
	bus_size_t dslen;
	bus_size_t minlen;

	DPRINTF(("_bus_dmamap_sync %p %p %#lx %ld %#x\n",
		t, map, (unsigned long) offset, (unsigned long) len, ops));

	/*
	 * Mixing PRE and POST operations is not allowed.
	 */
	if (((ops & (BUS_DMASYNC_PREREAD|BUS_DMASYNC_PREWRITE)) != 0) &&
	    ((ops & (BUS_DMASYNC_POSTREAD|BUS_DMASYNC_POSTWRITE)) != 0))
		panic("_bus_dmamap_sync: mix PRE and POST");

#ifdef DIAGNOSTIC
	if (offset >= map->dm_mapsize)
		panic("_bus_dmamap_sync: bad offset %#lx (map size is %#lx)",
		      (unsigned long) offset, (unsigned long) map->dm_mapsize);
	if (len == 0 || (offset + len) > map->dm_mapsize)
		panic("_bus_dmamap_sync: bad length");
#endif

	switch(ops) {
	case BUS_DMASYNC_PREWRITE:
		for (i=0; i < map->dm_nsegs && len != 0; i++) {
			/* find the beginning segment */
			dslen = map->dm_segs[i].ds_len;
			if (offset >= dslen) {
				offset -= dslen;
				continue;
			}
			dslen -= offset;
			minlen = len;
			if (len > dslen)
				minlen = dslen;
			storedcache(map->dm_segs[i].ds_vaddr + offset, minlen);
			len -= minlen;
			offset = 0;
		}
		break;
	case BUS_DMASYNC_PREREAD:
		for (i=0; i < map->dm_nsegs && len != 0; i++) {
			vaddr_t va;

			/* find the beginning segment */
			dslen = map->dm_segs[i].ds_len;
			if (offset >= dslen) {
				offset -= dslen;
				continue;
			}
			dslen -= offset;
			minlen = len;
			if (len > dslen)
				minlen = dslen;
			va = map->dm_segs[i].ds_vaddr + offset;
			if (va & (CACHELINESIZE-1))
				storedcache(va, 1);
			va += minlen;
			if (va & (CACHELINESIZE-1))
				storedcache(va, 1);
			invaldcache(map->dm_segs[i].ds_vaddr + offset, minlen);
			len -= minlen;
			offset = 0;
		}
		break;
	case BUS_DMASYNC_POSTREAD:
		for (i=0; i < map->dm_nsegs && len != 0; i++) {
			/* find the beginning segment */
			dslen = map->dm_segs[i].ds_len;
			if (offset >= dslen) {
				offset -= dslen;
				continue;
			}
			dslen -= offset;
			minlen = len;
			if (len > dslen)
				minlen = dslen;
			invaldcache(map->dm_segs[i].ds_vaddr + offset, minlen);
			len -= minlen;
			offset = 0;
		}
		break;
	case BUS_DMASYNC_POSTWRITE:
		break;
	case BUS_DMASYNC_PREREAD|BUS_DMASYNC_PREWRITE:
		for (i=0; i < map->dm_nsegs && len != 0; i++) {
			/* find the beginning segment */
			dslen = map->dm_segs[i].ds_len;
			if (offset >= dslen) {
				offset -= dslen;
				continue;
			}
			dslen -= offset;
			minlen = len;
			if (len > dslen)
				minlen = dslen;
			flushdcache(map->dm_segs[i].ds_vaddr + offset, minlen);
			len -= minlen;
			offset = 0;
		}
		break;
	case BUS_DMASYNC_POSTREAD|BUS_DMASYNC_POSTWRITE:
		for (i=0; i < map->dm_nsegs && len != 0; i++) {
			/* find the beginning segment */
			dslen = map->dm_segs[i].ds_len;
			if (offset >= dslen) {
				offset -= dslen;
				continue;
			}
			dslen -= offset;
			minlen = len;
			if (len > dslen)
				minlen = dslen;
			invaldcache(map->dm_segs[i].ds_vaddr + offset, minlen);
			len -= minlen;
			offset = 0;
		}
		break;
	}
}

/*
 * Common function for DMA-safe memory allocation.  May be called
 * by bus-specific DMA memory allocation functions.
 */
int
_bus_dmamem_alloc(t, size, alignment, boundary, segs, nsegs, rsegs, flags)
	bus_dma_tag_t t;
	bus_size_t size, alignment, boundary;
	bus_dma_segment_t *segs;
	int nsegs;
	int *rsegs;
	int flags;
{
	paddr_t avail_start = 0xffffffff, avail_end = 0;
	paddr_t curaddr, lastaddr, high;
	struct vm_page *m;    
	struct pglist mlist;
	int curseg, error, bank;

	for (bank = 0; bank < vm_nphysseg; bank++) {
		if (avail_start > vm_physmem[bank].avail_start << PGSHIFT)
			avail_start = vm_physmem[bank].avail_start << PGSHIFT;
		if (avail_end < vm_physmem[bank].avail_end << PGSHIFT)
			avail_end = vm_physmem[bank].avail_end << PGSHIFT;
	}


	/* Always round the size. */
	size = round_page(size);

	high = avail_end - PAGE_SIZE;

	/*
	 * Allocate pages from the VM system.
	 */
	TAILQ_INIT(&mlist);
	error = uvm_pglistalloc(size, avail_start, high, alignment, boundary,
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
	segs[curseg].ds_vaddr = (vaddr_t)0xdeadbeef;
	m = m->pageq.tqe_next;

	for (; m != NULL; m = m->pageq.tqe_next) {
		curaddr = VM_PAGE_TO_PHYS(m);
#ifdef DIAGNOSTIC
		if (curaddr < avail_start || curaddr >= high) {
			printf("vm_page_alloc_memory returned non-sensical"
			    " address 0x%lx\n", curaddr);
			panic("_bus_dmamem_alloc");
		}
#endif
		if (curaddr == (lastaddr + PAGE_SIZE))
			segs[curseg].ds_len += PAGE_SIZE;
		else {
			curseg++;
			segs[curseg].ds_addr = curaddr;
			segs[curseg].ds_len = PAGE_SIZE;
			segs[curseg].ds_vaddr = (vaddr_t)0xdeadbeef;
		}
		lastaddr = curaddr;
	}

	*rsegs = curseg + 1;

	return (0);
}

/*
 * Common function for freeing DMA-safe memory.  May be called by
 * bus-specific DMA memory free functions.
 */
void
_bus_dmamem_free(t, segs, nsegs)
	bus_dma_tag_t t;
	bus_dma_segment_t *segs;
	int nsegs;
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
 */
int
_bus_dmamem_map(t, segs, nsegs, size, kvap, flags)
	bus_dma_tag_t t;
	bus_dma_segment_t *segs;
	int nsegs;
	size_t size;
	caddr_t *kvap;
	int flags;
{
	vaddr_t va;
	bus_addr_t addr;
	int curseg;

	size = round_page(size);

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
			    VM_PROT_READ | VM_PROT_WRITE | PMAP_WIRED|
				    (flags & BUS_DMA_COHERENT ? PMAP_NC : 0));
		}
	}

	return (0);
}

/*
 * Common function for unmapping DMA-safe memory.  May be called by
 * bus-specific DMA memory unmapping functions.
 */
void
_bus_dmamem_unmap(t, kva, size)
	bus_dma_tag_t t;
	caddr_t kva;
	size_t size;
{

#ifdef DIAGNOSTIC
	if ((u_long)kva & PGOFSET)
		panic("_bus_dmamem_unmap");
#endif

	size = round_page(size);

	uvm_km_free(kernel_map, (vaddr_t)kva, size);
}

/*
 * Common functin for mmap(2)'ing DMA-safe memory.  May be called by
 * bus-specific DMA mmap(2)'ing functions.
 */
paddr_t
_bus_dmamem_mmap(t, segs, nsegs, off, prot, flags)
	bus_dma_tag_t t;
	bus_dma_segment_t *segs;
	int nsegs, prot, flags;
	off_t off;
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

		return (segs[i].ds_addr + off);
	}

	/* Page not found. */
	return (-1);
}
