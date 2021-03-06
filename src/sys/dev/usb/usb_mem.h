/*	$NetBSD: usb_mem.h,v 1.22 2004/12/21 19:49:56 fvdl Exp $	*/
/*	$FreeBSD: src/sys/dev/usb/usb_mem.h,v 1.9 1999/11/17 22:33:47 n_hibma Exp $	*/

/*
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Lennart Augustsson (lennart@augustsson.net) at
 * Carlstedt Research & Technology.
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
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

#if defined(__NetBSD__) || defined(__OpenBSD__)
typedef struct usb_dma_block {
	bus_dma_tag_t tag;
	bus_dmamap_t map;
        caddr_t kaddr;
        bus_dma_segment_t segs[1];
        int nsegs;
        size_t size;
        size_t align;
	int flags;
#define USB_DMA_FULLBLOCK	0x0001
#define USB_DMA_RESERVE		0x0002
	LIST_ENTRY(usb_dma_block) next;
} usb_dma_block_t;

#define DMAADDR(dma, o) ((dma)->block->map->dm_segs[0].ds_addr + (dma)->offs + (o))
#define KERNADDR(dma, o) \
	((void *)((char *)((dma)->block->kaddr + (dma)->offs) + (o)))

usbd_status	usb_allocmem(usbd_bus_handle,size_t,size_t, usb_dma_t *);
void		usb_freemem(usbd_bus_handle, usb_dma_t *);

#ifdef __NetBSD__
struct extent;

struct usb_dma_reserve {
	bus_dma_tag_t dtag;
	bus_dmamap_t map;
	caddr_t vaddr;
	bus_addr_t paddr;
	size_t size;
	struct extent *extent;
	void *softc;
};

#if defined(_KERNEL_OPT)
#include "opt_usb_mem_reserve.h"
#endif

#ifndef USB_MEM_RESERVE
#define USB_MEM_RESERVE (256 * 1024)
#endif

usbd_status usb_reserve_allocm(struct usb_dma_reserve *, usb_dma_t *,
				u_int32_t);
int usb_setup_reserve(void *, struct usb_dma_reserve *, bus_dma_tag_t, size_t);
void usb_reserve_freem(struct usb_dma_reserve *, usb_dma_t *);

#endif

#elif defined(__FreeBSD__)

/*
 * FreeBSD does not have special functions for DMA memory, so let's keep it
 * simple for now.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/proc.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/pmap.h>       /* for vtophys */

#define		usb_allocmem(t,s,a,p)	(*(p) = malloc(s, M_USB, M_NOWAIT), (*(p) == NULL? USBD_NOMEM: USBD_NORMAL_COMPLETION))
#define		usb_freemem(t,p)	(free(*(p), M_USB))

#ifdef __alpha__
#define DMAADDR(dma, o)	(alpha_XXX_dmamap((vm_offset_t) *(dma) + (o)))
#else
#define DMAADDR(dma, o)	(vtophys(*(dma) + (o)))
#endif
#define KERNADDR(dma, o)	((void *) ((char *)*(dma) + (o)))
#endif /* __FreeBSD__ */

