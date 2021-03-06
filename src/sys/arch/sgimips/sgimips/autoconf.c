/*	$NetBSD: autoconf.c,v 1.23 2004/12/18 00:51:30 sekiya Exp $	*/

/*
 * Copyright (c) 2000 Soren S. Jorvang
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
 *          This product includes software developed for the
 *          NetBSD Project.  See http://www.NetBSD.org/ for
 *          information about NetBSD.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: autoconf.c,v 1.23 2004/12/18 00:51:30 sekiya Exp $");

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/device.h>

#include <machine/cpu.h>
#include <machine/sysconf.h>
#include <machine/machtype.h>
#include <machine/autoconf.h>

#include <dev/scsipi/scsi_all.h>
#include <dev/scsipi/scsipi_all.h>
#include <dev/scsipi/scsiconf.h>

static struct device *booted_controller = NULL;
static int	booted_slot, booted_unit;
static char	*booted_protocol = NULL;

extern struct platform platform;

void
cpu_configure()
{
	int s;

	softintr_init();

	s = splhigh();
	if (config_rootfound("mainbus", "mainbus") == NULL)
		panic("no mainbus found");

	/*
	 * Clear latched bus error registers which may have been
	 * caused by probes for non-existent devices.
	 */
	(*platform.bus_reset)();

	printf("biomask %02x netmask %02x ttymask %02x clockmask %02x\n",
	    biomask >> 8, netmask >> 8, ttymask >> 8, clockmask >> 8);

	_splnone();
}

/*
 * Look at the string 'cp' and decode the boot device.  Boot names
 * can be something like 'bootp(0)netbsd' or
 * 'scsi(0)disk(1)rdisk(0)partition(0)netbsd' or
 * 'dksc(0,1,0)netbsd'
 */
void
makebootdev(char *cp)
{
	if (booted_protocol != NULL)
		return;

	booted_slot = booted_unit = booted_partition = 0;

	if (strncmp(cp, "pci(", 4) == 0) {
		cp += 4;

		while (*cp && *cp != ')')
		    cp++;

		if (*cp != ')')
		    return;

		cp++;
	}

	if (strncmp(cp, "scsi(", 5) == 0) {
		cp += 5;
		if (*cp >= '0' && *cp <= '9')
			booted_slot = *cp++ - '0';
		if (strncmp(cp, ")disk(", 6) == 0) {
			cp += 6;
			if (*cp >= '0' && *cp <= '9')
				booted_unit = *cp++ - '0';
		}
		/* XXX can rdisk() ever be other than 0? */
		if (strncmp(cp, ")rdisk(0)partition(", 19) == 0) {
			cp += 19;
			while (*cp >= '0' && *cp <= '9')
				booted_partition =
					booted_partition * 10 + *cp++ - '0';
		}
		if (*cp != ')')
			return;	/* XXX ? */
		booted_protocol = "SCSI";
		return;
	}
	if (strncmp(cp, "dksc(", 5) == 0) {
		cp += 5;
		if (*cp >= '0' && *cp <= '9')
			booted_slot = *cp++ - '0';
		if (*cp == ',') {
			++cp;
			if (*cp >= '0' || *cp <= '9')
				booted_unit = *cp++ - '0';
			if (*cp == ',') {
				++cp;
				if (*cp >= '0' && *cp <= '9')
					booted_partition = *cp++ - '0';
			}
		}
		if (*cp != ')')
			return;		/* XXX ??? */
		booted_protocol = "SCSI";
		return;
	}
	if (strncmp(cp, "bootp(", 6) == 0) {
		/* XXX controller number?  Needed to
		   handle > 1 network controller */
		booted_protocol = "BOOTP";
		return;
	}
}

void
cpu_rootconf()
{
	printf("boot device: %s\n",
		booted_device ? booted_device->dv_xname : "<unknown>");

	setroot(booted_device, booted_partition);
}

/*
 * Try to determine the boot device.
 */
void
device_register(struct device *dev, void *aux)
{
	static int found, initted, scsiboot, netboot;
	struct device *parent = dev->dv_parent;
	struct cfdata *cf = dev->dv_cfdata;
	const char *name = cf->cf_name;

	if (found)
		return;

	if (!initted && booted_protocol) {
		scsiboot = strcmp(booted_protocol, "SCSI") == 0;
		netboot = (strcmp(booted_protocol, "BOOTP") == 0);
		initted = 1;
	}

	/*
	 * Handle SCSI boot device definitions
	 * wdsc -- IP12/22/24
	 * ahc -- IP32
	 */
	if ( (scsiboot && strcmp(name, "wdsc") == 0) ||
	     (scsiboot && strcmp(name, "ahc") == 0) ) {
		if (dev->dv_unit == booted_slot)
			booted_controller = dev;
		return;
	}

	/*
	 * If we found the boot controller, if check disk/tape/cdrom device
	 * on that controller matches.
	 */
	if (booted_controller && (strcmp(name, "sd") == 0 ||
	    strcmp(name, "st") == 0 ||
	    strcmp(name, "cd") == 0)) {
		struct scsipibus_attach_args *sa = aux;

		if (parent->dv_parent != booted_controller)
			return;
		if (booted_unit != sa->sa_periph->periph_target)
			return;
		booted_device = dev;
		found = 1;
		return;
	}

	/*
	 * Check if netboot device.
	 */
	if (netboot && (strcmp(name, "sq") == 0 ||
	    strcmp(name, "mec") == 0)) {
		/* XXX Check unit number? (Which we don't parse yet) */
		booted_device = dev;
		found = 1;
		return;
	}
}
