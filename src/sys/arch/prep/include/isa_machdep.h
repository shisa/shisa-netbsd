/*	$NetBSD: isa_machdep.h,v 1.8 2003/08/07 16:29:20 agc Exp $	*/

/*-
 * Copyright (c) 1996, 1997, 1998 The NetBSD Foundation, Inc.
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

/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 *	@(#)isa.h	5.7 (Berkeley) 5/9/91
 */

/*
 * Various pieces of the prep port want to include this file without
 * or in spite of using isavar.h, and should be fixed.
 */

#ifndef _PREP_ISA_MACHDEP_H_
#define _PREP_ISA_MACHDEP_H_

#include <machine/bus.h>
#include <dev/isa/isadmavar.h>

/*
 * XXX THIS FILE IS A MESS.  copyright: berkeley's probably.
 * contents from isavar.h and isareg.h, mostly the latter.
 * perhaps charles's?
 *
 * copyright from berkeley's isa.h which is now dev/isa/isareg.h.
 */

/*
 * Types provided to machine-independent ISA code.
 */
struct prep_isa_chipset {
	struct isa_dma_state ic_dmastate;
};

typedef struct prep_isa_chipset *isa_chipset_tag_t;

struct device;			/* XXX */
struct isabus_attach_args;	/* XXX */

/*
 * Functions provided to machine-independent ISA code.
 */
void	isa_attach_hook(struct device *, struct device *,
	    struct isabus_attach_args *);
const struct evcnt *isa_intr_evcnt(isa_chipset_tag_t ic, int irq);
void	*isa_intr_establish(isa_chipset_tag_t ic, int irq, int type,
	    int level, int (*ih_fun)(void *), void *ih_arg);
void	isa_intr_disestablish(isa_chipset_tag_t ic, void *handler);
int	isa_intr_alloc(isa_chipset_tag_t, int, int, int *);

#define	isa_dmainit(ic, bst, dmat, d)					\
	_isa_dmainit(&(ic)->ic_dmastate, (bst), (dmat), (d))
#define	isa_dmacascade(ic, c)						\
	_isa_dmacascade(&(ic)->ic_dmastate, (c))
#define	isa_dmamaxsize(ic, c)						\
	_isa_dmamaxsize(&(ic)->ic_dmastate, (c))
#define	isa_dmamap_create(ic, c, s, f)					\
	_isa_dmamap_create(&(ic)->ic_dmastate, (c), (s), (f))
#define	isa_dmamap_destroy(ic, c)					\
	_isa_dmamap_destroy(&(ic)->ic_dmastate, (c))
#define	isa_dmastart(ic, c, a, n, p, f, bf)				\
	_isa_dmastart(&(ic)->ic_dmastate, (c), (a), (n), (p), (f), (bf))
#define	isa_dmaabort(ic, c)						\
	_isa_dmaabort(&(ic)->ic_dmastate, (c))
#define	isa_dmacount(ic, c)						\
	_isa_dmacount(&(ic)->ic_dmastate, (c))
#define	isa_dmafinished(ic, c)						\
	_isa_dmafinished(&(ic)->ic_dmastate, (c))
#define	isa_dmadone(ic, c)						\
	_isa_dmadone(&(ic)->ic_dmastate, (c))
#define	isa_dmafreeze(ic)						\
	_isa_dmafreeze(&(ic)->ic_dmastate)
#define	isa_dmathaw(ic)							\
	_isa_dmathaw(&(ic)->ic_dmastate)
#define	isa_dmamem_alloc(ic, c, s, ap, f)				\
	_isa_dmamem_alloc(&(ic)->ic_dmastate, (c), (s), (ap), (f))
#define	isa_dmamem_free(ic, c, a, s)					\
	_isa_dmamem_free(&(ic)->ic_dmastate, (c), (a), (s))
#define	isa_dmamem_map(ic, c, a, s, kp, f)				\
	_isa_dmamem_map(&(ic)->ic_dmastate, (c), (a), (s), (kp), (f))
#define	isa_dmamem_unmap(ic, c, k, s)					\
	_isa_dmamem_unmap(&(ic)->ic_dmastate, (c), (k), (s))
#define	isa_dmamem_mmap(ic, c, a, s, o, p, f)				\
	_isa_dmamem_mmap(&(ic)->ic_dmastate, (c), (a), (s), (o), (p), (f))
#define isa_drq_alloc(ic, c)						\
	_isa_drq_alloc(&(ic)->ic_dmastate, c)
#define isa_drq_free(ic, c)						\
	_isa_drq_free(&(ic)->ic_dmastate, c)
#define	isa_drq_isfree(ic, c)						\
	_isa_drq_isfree(&(ic)->ic_dmastate, (c))
#define	isa_malloc(ic, c, s, p, f)					\
	_isa_malloc(&(ic)->ic_dmastate, (c), (s), (p), (f))
#define	isa_free(a, p)							\
	_isa_free((a), (p))
#define	isa_mappage(m, o, p)						\
	_isa_mappage((m), (o), (p))

/*
 * ALL OF THE FOLLOWING ARE MACHINE-DEPENDENT, AND SHOULD NOT BE USED
 * BY PORTABLE CODE.
 */

#define	isa_outb(x,y)	outb(PREP_BUS_SPACE_IO + (x), y)
#define isa_inb(x)	inb(PREP_BUS_SPACE_IO + (x))

extern struct powerpc_bus_dma_tag isa_bus_dma_tag;

/*
 * XXX Various seemingly PC-specific constants, some of which may be
 * unnecessary anyway.
 */

/*
 * stuff that used to be in pccons.c
 */
#define	MONO_BASE	0x3B4
#define	MONO_BUF	0xB0000
#define	CGA_BASE	0x3D4
#define	CGA_BUF		0xB8000

/*
 * Miscellanous functions.
 */
void isabeep(int, int);		/* beep with the system speaker */
void init_icu(int);		/* change ELCR */

#endif /* _PREP_ISA_MACHDEP_H_ */
