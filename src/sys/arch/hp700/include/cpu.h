/*	$NetBSD: cpu.h,v 1.13 2004/09/22 11:32:02 yamt Exp $	*/

/*	$OpenBSD: cpu.h,v 1.20 2001/01/29 00:01:58 mickey Exp $	*/

/*
 * Copyright (c) 2000-2001 Michael Shalayeff
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Michael Shalayeff.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR HIS RELATIVES BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF MIND, USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/* 
 * Copyright (c) 1988-1994, The University of Utah and
 * the Computer Systems Laboratory at the University of Utah (CSL).
 * All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software is hereby
 * granted provided that (1) source code retains these copyright, permission,
 * and disclaimer notices, and (2) redistributions including binaries
 * reproduce the notices in supporting documentation, and (3) all advertising
 * materials mentioning features or use of this software display the following
 * acknowledgement: ``This product includes software developed by the
 * Computer Systems Laboratory at the University of Utah.''
 *
 * THE UNIVERSITY OF UTAH AND CSL ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSL DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSL requests users of this software to return to csl-dist@cs.utah.edu any
 * improvements that they make and grant CSL redistribution rights.
 *
 * 	Utah $Hdr: cpu.h 1.19 94/12/16$
 */

#ifndef	_MACHINE_CPU_H_
#define	_MACHINE_CPU_H_

#include <machine/trap.h>
#include <machine/frame.h>

/*
 * CPU types and features
 */
#define	HPPA_FTRS_BTLBS		0x00000001
#define	HPPA_FTRS_BTLBU		0x00000002
#define	HPPA_FTRS_HVT		0x00000004
#define	HPPA_FTRS_W32B		0x00000008

#ifndef _LOCORE

/*
 * A CPU description.
 */
struct hppa_cpu_info { 

	/* The official name of the chip. */
	const char *hppa_cpu_info_chip_name;

	/* The nickname for the chip. */
	const char *hppa_cpu_info_chip_nickname;

	/* The type and PA-RISC specification of the chip. */
	const char *hppa_cpu_info_chip_type;
	unsigned short hppa_cpu_info_pa_spec;
#define HPPA_PA_SPEC_MAKE(major, minor, letter) \
  (((major) << 8) | \
   ((minor) << 4) | \
   ((letter) == '\0' ? 0 : ((letter) + 0xa - 'a')))
#define HPPA_PA_SPEC_MAJOR(x) (((x) >> 8) & 0xf)
#define HPPA_PA_SPEC_MINOR(x) (((x) >> 4) & 0xf)
#define HPPA_PA_SPEC_LETTER(x) \
  (((x) & 0xf) == 0 ? '\0' : 'a' + ((x) & 0xf) - 0xa)

	int (*desidhash) __P((void));
	const u_int *itlbh, *dtlbh, *dtlbnah, *tlbdh;
	int (*hptinit) __P((vaddr_t hpt, vsize_t hptsize));
};
extern const struct hppa_cpu_info *hppa_cpu_info;
#endif

/*
 * COPR/SFUs
 */
#define	HPPA_FPUS	0xc0
#define	HPPA_PMSFUS	0x20	/* ??? */

/*
 * Exported definitions unique to hp700/PA-RISC cpu support.
 */

/*
 * COPR/SFUs
 */
#define	HPPA_FPUVER(w)	(((w) & 0x003ff800) >> 11)
#define	HPPA_FPU_OP(w)	((w) >> 26)
#define	HPPA_FPU_UNMPL	0x01	/* exception reg, the rest is << 1 */
#define	HPPA_FPU_ILL	0x80	/* software-only */
#define	HPPA_FPU_I	0x01
#define	HPPA_FPU_U	0x02
#define	HPPA_FPU_O	0x04
#define	HPPA_FPU_Z	0x08
#define	HPPA_FPU_V	0x10
#define	HPPA_FPU_D	0x20
#define	HPPA_FPU_T	0x40
#define	HPPA_FPU_XMASK	0x7f
#define	HPPA_FPU_T_POS	25
#define	HPPA_FPU_RM	0x00000600
#define	HPPA_FPU_CQ	0x00fff800
#define	HPPA_FPU_C	0x04000000
#define	HPPA_FPU_INIT	(0)
#define	HPPA_FPU_FORK(s) ((s) & ~((uint64_t)(HPPA_FPU_XMASK) << 32))

/*
 * definitions of cpu-dependent requirements
 * referenced in generic code
 */

#define	HPPA_PGALIAS	0x00100000
#define	HPPA_PGAMASK	0xfff00000
#define	HPPA_PGAOFF	0x000fffff
#define	HPPA_SPAMASK	0xf0f0f000

#define	HPPA_IOSPACE	0xf0000000
#define	HPPA_IOBCAST	0xfffc0000
#define	HPPA_PDC_LOW	0xef000000
#define	HPPA_PDC_HIGH	0xf1000000
#define	HPPA_FPA	0xfff80000
#define	HPPA_FLEX_DATA	0xfff80001
#define	HPPA_DMA_ENABLE	0x00000001
#define	HPPA_FLEX_MASK	0xfffc0000
#define	HPPA_SPA_ENABLE	0x00000020
#define	HPPA_NMODSPBUS	64

#ifndef _LOCORE
#ifdef _KERNEL

#if defined(_KERNEL_OPT)
#include "opt_lockdebug.h"
#endif

/*
 * External definitions unique to PA-RISC cpu support.
 * These are the "public" declarations - those needed in
 * machine-independent source code.  The "private" ones
 * are in machdep.h.
 *
 * Note that the name of this file is NOT meant to imply
 * that it has anything to do with PA-RISC CPU stuff.
 * The name "cpu" is historical, and used in the common
 * code to identify machine-dependent functions, etc.
 */

/* clockframe describes the system before we took an interrupt. */
struct clockframe {
	int	cf_flags;
	int	cf_spl;
	u_int	cf_pc;
};
#define	CLKF_BASEPRI(framep)	((framep)->cf_spl == 0)
#define	CLKF_PC(framep)		((framep)->cf_pc)
#define	CLKF_INTR(framep)	((framep)->cf_flags & TFF_INTR)
#define	CLKF_USERMODE(framep)	((framep)->cf_flags & T_USER)

#define	signotify(p)		(setsoftast())
#define	need_resched(ci)	(want_resched = 1, setsoftast())
#define	need_proftick(p)	((p)->p_flag |= P_OWEUPC, setsoftast())

#include <sys/cpu_data.h>
struct cpu_info {
	struct cpu_data ci_data;	/* MI per-cpu data */
};

#include <machine/intr.h>

extern struct cpu_info cpu_info_store;

#define	curcpu()			(&cpu_info_store)

/*
 * definitions of cpu-dependent requirements
 * referenced in generic code
 */
#define	cpu_number()			0

#define cpu_proc_fork(p1, p2)

#define MD_CACHE_FLUSH 0
#define MD_CACHE_PURGE 1
#define	HPPA_SID_KERNEL 0
#define MD_CACHE_CTL(a,s,t)	\
	(((t)? pdcache : fdcache) (HPPA_SID_KERNEL,(vaddr_t)(a),(s)))

extern int want_resched;

#define DELAY(x) delay(x)

static __inline long
kvtop (const caddr_t va)
{
	long ret;
	__asm __volatile ("lpa %%r0(%1), %0" : "=r" (ret) : "r" (va));
	return ret;
}

extern int (*cpu_desidhash)(void);

void	delay(u_int);
void	hppa_init(paddr_t);
void	trap(int, struct trapframe *);
void	hppa_ras(struct lwp *);
int	dma_cachectl(caddr_t, int);
int	spcopy(pa_space_t, const void *, pa_space_t, void *, size_t);
int	spstrcpy(pa_space_t, const void *, pa_space_t, void *, size_t,
		 size_t *);
int	copy_on_fault(void);
void	switch_trampoline(void);
void	switch_exit(struct lwp *, void (*)(struct lwp *));
int	cpu_dumpsize(void);
int	cpu_dump(void);
#endif

/*
 * Boot arguments stuff
 */

#define	BOOTARG_LEN	(PAGE_SIZE)
#define	BOOTARG_OFF	(0x10000)

/*
 * CTL_MACHDEP definitions.
 */
#define	CPU_CONSDEV		1	/* dev_t: console terminal device */
#define	CPU_MAXID		2	/* number of valid machdep ids */

#define CTL_MACHDEP_NAMES { \
	{ 0, 0 }, \
	{ "console_device", CTLTYPE_STRUCT }, \
}
#endif

#endif /* _MACHINE_CPU_H_ */
