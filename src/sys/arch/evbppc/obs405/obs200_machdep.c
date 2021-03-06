/*	$NetBSD: obs200_machdep.c,v 1.3 2006/03/29 17:50:33 shige Exp $	*/
/*	Original: machdep.c,v 1.3 2005/01/17 17:24:09 shige Exp	*/

/*
 * Copyright 2001, 2002 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Eduardo Horvath and Simon Burge for Wasabi Systems, Inc.
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
 *      This product includes software developed for the NetBSD Project by
 *      Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (C) 1995, 1996 Wolfgang Solfrank.
 * Copyright (C) 1995, 1996 TooLs GmbH.
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
 *	This product includes software developed by TooLs GmbH.
 * 4. The name of TooLs GmbH may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY TOOLS GMBH ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL TOOLS GMBH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: obs200_machdep.c,v 1.3 2006/03/29 17:50:33 shige Exp $");

#include "opt_compat_netbsd.h"
#include "opt_ddb.h"
#include "opt_ipkdb.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/ksyms.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/systm.h>

#include <uvm/uvm.h>
#include <uvm/uvm_extern.h>

#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/obs200.h>
#include <machine/century_bios.h>
#include <powerpc/spr.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pciconf.h>

#include <powerpc/ibm4xx/dcr405gp.h>

#include "ksyms.h"

/*
 * Global variables used here and there
 */
char bootpath[256];

extern paddr_t msgbuf_paddr;

#if NKSYMS || defined(DDB) || defined(LKM)
void *startsym, *endsym;
#endif

void initppc(u_int, u_int, char *, void *);
int lcsplx(int);


void
initppc(u_int startkernel, u_int endkernel, char *args, void *info_block)
{
	u_int32_t pllmode;
	u_int32_t psr;
	u_int memsize;

	/* Disable all external interrupts */
	mtdcr(DCR_UIC0_ER, 0);
	pllmode = mfdcr(DCR_CPC0_PLLMR);
	psr = mfdcr(DCR_CPC0_PSR);

	/* Setup board from BIOS */
	bios_board_init(info_block, startkernel);
	memsize = bios_board_memsize_get();

	/* Initialize IBM405GPr CPU */
	ibm40x_memsize_init(memsize, startkernel);
	ibm4xx_init((void (*)(void))ext_intr);

	/*
	 * Initialize console.
	 */
	consinit();

	/*
	 * Set the page size.
	 */
	uvm_setpagesize();

	/*
	 * Initialize pmap module.
	 */
	pmap_bootstrap(startkernel, endkernel);

#ifdef DEBUG
	bios_board_print();
	printf("  PLL Mode Register = 0x%08x\n", pllmode);
	printf("  Chip Pin Strapping Register = 0x%08x\n", psr);
#endif

#if NKSYMS || defined(DDB) || defined(LKM)
	ksyms_init((int)((u_int)endsym - (u_int)startsym), startsym, endsym);
#endif
#ifdef DDB
	if (boothowto & RB_KDB)
		Debugger();
#endif
#ifdef IPKDB
	/*
	 * Now trap to IPKDB
	 */
	ipkdb_init();
	if (boothowto & RB_KDB)
		ipkdb_connect(0);
#endif
}

void
consinit(void)
{

	obs405_consinit(OBS200_COM_FREQ);
}

int
lcsplx(int ipl)
{

	return spllower(ipl); 	/* XXX */
}


/*
 * Machine dependent startup code.
 */
void
cpu_startup(void)
{

	/*
	 * cpu common startup
	 */
	ibm4xx_cpu_startup("OpenBlockS S/R IBM PowerPC 405GP Board");

	/*
	 * Set up the board properties database.
	 */
	bios_board_info_set();

	/*
	 * Now that we have VM, malloc()s are OK in bus_space.
	 */
	bus_space_mallocok();

	/*
	 * no fake mapiodev
	 */
	fake_mapiodev = 0;
}

/*
 * Halt or reboot the machine after syncing/dumping according to howto.
 */
void
cpu_reboot(int howto, char *what)
{
	static int syncing;
	static char str[256];
	char *ap = str, *ap1 = ap;

	boothowto = howto;
	if (!cold && !(howto & RB_NOSYNC) && !syncing) {
		syncing = 1;
		vfs_shutdown();		/* sync */
		resettodr();		/* set wall clock */
	}

	splhigh();

	if (!cold && (howto & RB_DUMP))
		ibm4xx_dumpsys();

	doshutdownhooks();

	if ((howto & RB_POWERDOWN) == RB_POWERDOWN) {
	  /* Power off here if we know how...*/
	}

	if (howto & RB_HALT) {
		printf("halted\n\n");

#if 0
		goto reboot;	/* XXX for now... */
#endif

#ifdef DDB
		printf("dropping to debugger\n");
		while(1)
			Debugger();
#endif
	}

	printf("rebooting\n\n");
	if (what && *what) {
		if (strlen(what) > sizeof str - 5)
			printf("boot string too large, ignored\n");
		else {
			strcpy(str, what);
			ap1 = ap = str + strlen(str);
			*ap++ = ' ';
		}
	}
	*ap++ = '-';
	if (howto & RB_SINGLE)
		*ap++ = 's';
	if (howto & RB_KDB)
		*ap++ = 'd';
	*ap++ = 0;
	if (ap[-2] == '-')
		*ap1 = 0;

	/* flush cache for msgbuf */
	__syncicache((void *)msgbuf_paddr, round_page(MSGBUFSIZE));

#if 0
 reboot:
#endif
	ppc4xx_reset();

	printf("ppc4xx_reset() failed!\n");
#ifdef DDB
	while(1)
		Debugger();
#else
	while (1)
		/* nothing */;
#endif
}

int
pci_intr_map(struct pci_attach_args *pa, pci_intr_handle_t *ihp)
{
	/*
	 * We need to map the interrupt pin to the interrupt bit
	 * in the UIC associated with it.
	 *
	 * This platform has 4 PCI devices.
	 *
	 # External IRQ Mappings:
	 *  dev 7 (Ext IRQ3):	Realtek 8139 Ethernet
	 *  dev 8 (Ext IRQ0):	PCI Connector
	 */
	static const int irqmap[15/*device*/][4/*pin*/] = {
		{ -1, -1, -1, -1 },	/*  1: none */
		{ -1, -1, -1, -1 },	/*  2: none */
		{ -1, -1, -1, -1 },	/*  3: none */
		{ -1, -1, -1, -1 },	/*  4: none */
		{ -1, -1, -1, -1 },	/*  5: none */
		{ -1, -1, -1, -1 },	/*  6: none */
		{  3, -1, -1, -1 },	/*  7: none */
		{  0, -1, -1, -1 },	/*  8: none */
		{ -1, -1, -1, -1 },	/*  9: none */
		{ -1, -1, -1, -1 },	/* 10: none */
		{ -1, -1, -1, -1 },	/* 11: none */
		{ -1, -1, -1, -1 },	/* 12: none */
		{ -1, -1, -1, -1 },	/* 13: none */
		{ -1, -1, -1, -1 },	/* 14: none */
		{ -1, -1, -1, -1 },	/* 15: none */
	};

	int pin, dev, irq;

	pin = pa->pa_intrpin;
	dev = pa->pa_device;
        *ihp = -1;

	/* if interrupt pin not used... */
	if (pin == 0)
		return 1;

	if (pin > 4) {
		printf("pci_intr_map: bad interrupt pin %d\n", pin);
		return 1;
	}

	if ((dev < 1) || (dev > 15)) {
		printf("pci_intr_map: bad device %d\n", dev);
		return 1;
	}


	if ((irq = irqmap[dev - 1][pin - 1]) == -1) {
		printf("pci_intr_map: no IRQ routing for device %d pin %d\n",
			dev, pin);
		return 1;
	}

	*ihp = irq + 25;
	return 0;
}

void
pci_conf_interrupt(pci_chipset_tag_t pc, int bus, int dev, int pin,
			int swiz, int *iline)
{
	static const int ilinemap[15/*device*/] = {
		-1, -1, -1, -1,		/* device  1 -  4 */
		-1, -1, 28, 25,		/* device  5 -  8 */
		-1, -1, -1, -1,		/* device  9 - 12 */
		-1, -1, -1,		/* device 13 - 15 */
	};

	if (bus == 0) {
		if ((dev < 1) || (dev > 15)) {
			printf("pci_intr_map: bad device %d\n", dev);
			*iline = 0;
			return;
		}
		*iline = ilinemap[dev - 1];
        } else {
		*iline = 19 + ((swiz + dev + 1) & 3);
        }
}
