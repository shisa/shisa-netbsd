/*	$NetBSD: disksubr_mbr.c,v 1.5 2004/11/03 12:21:04 scw Exp $	*/

/*
 * Copyright (c) 1998 Christopher G. Demetriou.  All rights reserved.
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
 *      This product includes software developed by Christopher G. Demetriou
 *	for the NetBSD Project.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
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

/*
 * Copyright (c) 1982, 1986, 1988 Regents of the University of California.
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
 *	@(#)ufs_disksubr.c	7.16 (Berkeley) 5/4/91
 */

/*
 * From i386 disklabel.c rev 1.29, with cleanups and modifications to
 * make it easier to use on the arm32 and to use as MI code (not quite
 * clean enough, yet).
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: disksubr_mbr.c,v 1.5 2004/11/03 12:21:04 scw Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/disklabel.h>

#include "opt_mbr.h"

#define MBRSIGOFS 0x1fe
static char mbrsig[2] = {0x55, 0xaa};

int fat_types[] = {
	MBR_PTYPE_FAT12, MBR_PTYPE_FAT16S,
	MBR_PTYPE_FAT16B, MBR_PTYPE_FAT32,
	MBR_PTYPE_FAT32L, MBR_PTYPE_FAT16L,
	-1
};

int
mbr_label_read(dev, strat, lp, osdep, msgp, cylp, netbsd_label_offp)
	dev_t dev;
	void (*strat) __P((struct buf *));
	struct disklabel *lp;
	struct cpu_disklabel *osdep;
	char **msgp;
	int *cylp, *netbsd_label_offp;
{
	struct mbr_partition *mbrp;
	struct partition *pp;
	int cyl, mbrpartoff, i, *ip;
	struct buf *bp;
	int rv = 1;

	/* get a buffer and initialize it */
        bp = geteblk((int)lp->d_secsize);
        bp->b_dev = dev;

	/* In case nothing sets them */
	mbrpartoff = 0;
	cyl = LABELSECTOR / lp->d_secpercyl;

	mbrp = osdep->mbrparts;

	/* read master boot record */
	bp->b_blkno = MBR_BBSECTOR;
	bp->b_bcount = lp->d_secsize;
	bp->b_flags |= B_READ;
	bp->b_cylinder = MBR_BBSECTOR / lp->d_secpercyl;
	(*strat)(bp);

	/* if successful, wander through dos partition table */
	if (biowait(bp)) {
		*msgp = "dos partition I/O error";
		goto out;
	} else {
		struct mbr_partition *ourmbrp = NULL;

		/* XXX "there has to be a better check than this." */
		if (bcmp(bp->b_data + MBRSIGOFS, mbrsig, sizeof(mbrsig))) {
			rv = 0;
			goto out;
		}

		/* XXX how do we check veracity/bounds of this? */
		bcopy(bp->b_data + MBR_PART_OFFSET, mbrp,
		      MBR_PART_COUNT * sizeof(*mbrp));

		/* look for NetBSD partition */
		ourmbrp = NULL;
		for (i = 0; !ourmbrp && i < MBR_PART_COUNT; i++) {
			if (mbrp[i].mbrp_type == MBR_PTYPE_NETBSD)
				ourmbrp = &mbrp[i];
		}
#ifdef COMPAT_386BSD_MBRPART
		/* didn't find it -- look for 386BSD partition */
		for (i = 0; !ourmbrp && i < MBR_PART_COUNT; i++) {
			if (mbrp[i].mbrp_type == MBR_PTYPE_386BSD) {
				printf("WARNING: old BSD partition ID!\n");
				ourmbrp = &mbrp[i];
				break;
			}
		}
#endif
		for (i = 0; i < MBR_PART_COUNT; i++, mbrp++) {

			strncpy(lp->d_packname, "fictitious-MBR",
			    sizeof lp->d_packname);

			/* Install in partition e, f, g, or h. */
			pp = &lp->d_partitions['e' - 'a' + i];
			pp->p_offset = mbrp->mbrp_start;
			pp->p_size = mbrp->mbrp_size;
			for (ip = fat_types; *ip != -1; ip++) {
				if (mbrp->mbrp_type == *ip)
					pp->p_fstype = FS_MSDOS;
			}
			if (mbrp->mbrp_type == MBR_PTYPE_LNXEXT2)
				pp->p_fstype = FS_EX2FS;

			/* is this ours? */
			if (mbrp == ourmbrp) {
				/* need sector address for SCSI/IDE,
				 cylinder for ESDI/ST506/RLL */
				mbrpartoff = mbrp->mbrp_start;
				cyl = MBR_PCYL(mbrp->mbrp_scyl, mbrp->mbrp_ssect);

#ifdef __i386__ /* XXX? */
				/* update disklabel with details */
				lp->d_partitions[2].p_size =
				    mbrp->mbrp_size;
				lp->d_partitions[2].p_offset = 
				    mbrp->mbrp_start;
				lp->d_ntracks = mbrp->mbrp_ehd + 1;
				lp->d_nsectors = MBR_PSECT(mbrp->mbrp_esect);
				lp->d_secpercyl =
				    lp->d_ntracks * lp->d_nsectors;
#endif
			}
		}
		lp->d_npartitions = 'e' - 'a' + i;
	}

	*cylp = cyl;
	*netbsd_label_offp = mbrpartoff;
	*msgp = NULL;
out:
        brelse(bp);
	return (rv);
}

int
mbr_label_locate(dev, strat, lp, osdep, cylp, netbsd_label_offp)
	dev_t dev;
	void (*strat) __P((struct buf *));
	struct disklabel *lp;
	struct cpu_disklabel *osdep;
	int *cylp, *netbsd_label_offp;
{
	struct mbr_partition *mbrp;
	int cyl, mbrpartoff, i;
	struct mbr_partition *ourmbrp = NULL;
	struct buf *bp;
	int rv;

	/* get a buffer and initialize it */
        bp = geteblk((int)lp->d_secsize);
        bp->b_dev = dev;

	/* do MBR partitions in the process of getting disklabel? */
	mbrpartoff = 0;
	cyl = LABELSECTOR / lp->d_secpercyl;

	mbrp = osdep->mbrparts;

	/* read master boot record */
	bp->b_blkno = MBR_BBSECTOR;
	bp->b_bcount = lp->d_secsize;
	bp->b_flags |= B_READ;
	bp->b_cylinder = MBR_BBSECTOR / lp->d_secpercyl;
	(*strat)(bp);

	if ((rv = biowait(bp)) != 0) {
		rv = -rv;
		goto out;
	}

	if (bcmp(bp->b_data + MBRSIGOFS, mbrsig, sizeof(mbrsig))) {
		rv = 0;
		goto out;
	}

	/* XXX how do we check veracity/bounds of this? */
	bcopy(bp->b_data + MBR_PART_OFFSET, mbrp, MBR_PART_COUNT * sizeof(*mbrp));

	/* look for NetBSD partition */
	ourmbrp = NULL;
	for (i = 0; !ourmbrp && i < MBR_PART_COUNT; i++) {
		if (mbrp[i].mbrp_type == MBR_PTYPE_NETBSD)
			ourmbrp = &mbrp[i];
	}
#ifdef COMPAT_386BSD_MBRPART
	/* didn't find it -- look for 386BSD partition */
	for (i = 0; !ourmbrp && i < MBR_PART_COUNT; i++) {
		if (mbrp[i].mbrp_type == MBR_PTYPE_386BSD) {
			printf("WARNING: old BSD partition ID!\n");
			ourmbrp = &mbrp[i];
		}
	}
#endif
	if (!ourmbrp) {
		rv = 0;			/* XXX allow easy clobber? */
		goto out;
	}

	/* need sector address for SCSI/IDE, cylinder for ESDI/ST506/RLL */
	mbrpartoff = ourmbrp->mbrp_start;
	cyl = MBR_PCYL(ourmbrp->mbrp_scyl, ourmbrp->mbrp_ssect);

	*cylp = cyl;
	*netbsd_label_offp = mbrpartoff;
	rv = 1;
out:
        brelse(bp);
	return (rv);
}
