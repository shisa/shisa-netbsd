/*	$NetBSD: procfs_machdep.c,v 1.2 2005/01/01 17:11:39 chs Exp $ */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: procfs_machdep.c,v 1.2 2005/01/01 17:11:39 chs Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <miscfs/procfs/procfs.h>

#include <m68k/m68k.h>

/*
 * Linux-style /proc/cpuinfo.
 * Only used when procfs is mounted with -o linux.
 */
int
procfs_getcpuinfstr(char *buf, int *len)
{
	*len = 0;
	const char *cpu, *mmu, *fpu;

	switch (cputype) {
	case CPU_68020:
		cpu = "68020";
		break;
	case CPU_68030:
		cpu = "68030";
		break;
	case CPU_68040:
		cpu = "68040";
		break;
	case CPU_68060:
		cpu = "68060";
		break;
	default:
		cpu = "680x0";
		break;
	}

	switch (mmutype) {
	case MMU_68851:
		mmu = "68851";
		break;
	case MMU_68030:
		mmu = "68030";
		break;
	case MMU_68040:
		mmu = "68040";
		break;
	case MMU_68060:
		mmu = "68060";
		break;
	default:
		mmu = "unknown";
		break;
	}

	switch (fputype) {
	case FPU_NONE:
		fpu = "none(soft float)";
		break;
	case FPU_68881:
		fpu = "68881";
		break;
	case FPU_68882:
		fpu = "68882";
		break;
	case FPU_68040: 
		fpu = "68040";   
		break; 
	case FPU_68060:
		fpu = "68060";
		break;
	default:
		fpu = "none";
		break;
	}

	*len = snprintf(buf, sizeof(buf),
	    /* as seen in Linux 2.4.27 */
	    "CPU:\t\t%s\n"
	    "MMU:\t\t%s\n"
	    "FPU:\t\t%s\n",
	    /*
	     * in Linux m68k /proc/cpuinfo there are also "Clocking",
	     * "BogoMips" and "Calibration".
	     */
	    cpu, mmu, fpu);

	return 0;
}
