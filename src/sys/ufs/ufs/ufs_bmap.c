/*	$NetBSD: ufs_bmap.c,v 1.35 2005/02/26 22:32:20 perry Exp $	*/

/*
 * Copyright (c) 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)ufs_bmap.c	8.8 (Berkeley) 8/11/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: ufs_bmap.c,v 1.35 2005/02/26 22:32:20 perry Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/resourcevar.h>
#include <sys/trace.h>

#include <miscfs/specfs/specdev.h>

#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/ufs_extern.h>
#include <ufs/ufs/ufs_bswap.h>

static boolean_t ufs_issequential __P((const struct ufsmount *,
					daddr_t, daddr_t));

static boolean_t
ufs_issequential(ump, daddr0, daddr1)
	const struct ufsmount *ump;
	daddr_t daddr0;
	daddr_t daddr1;
{

	/* for ufs, blocks in a hole is not 'contiguous'. */
	if (daddr0 == 0)
		return FALSE;

	return (daddr0 + ump->um_seqinc == daddr1);
}

/*
 * Bmap converts a the logical block number of a file to its physical block
 * number on the disk. The conversion is done by using the logical block
 * number to index into the array of block pointers described by the dinode.
 */
int
ufs_bmap(v)
	void *v;
{
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t  a_bn;
		struct vnode **a_vpp;
		daddr_t *a_bnp;
		int *a_runp;
	} */ *ap = v;
	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (ap->a_vpp != NULL)
		*ap->a_vpp = VTOI(ap->a_vp)->i_devvp;
	if (ap->a_bnp == NULL)
		return (0);

	return (ufs_bmaparray(ap->a_vp, ap->a_bn, ap->a_bnp, NULL, NULL,
	    ap->a_runp, ufs_issequential));
}

/*
 * Indirect blocks are now on the vnode for the file.  They are given negative
 * logical block numbers.  Indirect blocks are addressed by the negative
 * address of the first data block to which they point.  Double indirect blocks
 * are addressed by one less than the address of the first indirect block to
 * which they point.  Triple indirect blocks are addressed by one less than
 * the address of the first double indirect block to which they point.
 *
 * ufs_bmaparray does the bmap conversion, and if requested returns the
 * array of logical blocks which must be traversed to get to a block.
 * Each entry contains the offset into that block that gets you to the
 * next block and the disk address of the block (if it is assigned).
 */

int
ufs_bmaparray(vp, bn, bnp, ap, nump, runp, is_sequential)
	struct vnode *vp;
	daddr_t bn;
	daddr_t *bnp;
	struct indir *ap;
	int *nump;
	int *runp;
	ufs_issequential_callback_t is_sequential;
{
	struct inode *ip;
	struct buf *bp;
	struct ufsmount *ump;
	struct mount *mp;
	struct indir a[NIADDR + 1], *xap;
	daddr_t daddr;
	daddr_t metalbn;
	int error, maxrun = 0, num;

	ip = VTOI(vp);
	mp = vp->v_mount;
	ump = ip->i_ump;
#ifdef DIAGNOSTIC
	if ((ap != NULL && nump == NULL) || (ap == NULL && nump != NULL))
		panic("ufs_bmaparray: invalid arguments");
#endif

	if (runp) {
		/*
		 * XXX
		 * If MAXBSIZE is the largest transfer the disks can handle,
		 * we probably want maxrun to be 1 block less so that we
		 * don't create a block larger than the device can handle.
		 */
		*runp = 0;
		maxrun = MAXPHYS / mp->mnt_stat.f_iosize - 1;
	}

	if (bn >= 0 && bn < NDADDR) {
		if (nump != NULL)
			*nump = 0;
		if (ump->um_fstype == UFS1)
			daddr = ufs_rw32(ip->i_ffs1_db[bn],
			    UFS_MPNEEDSWAP(ump));
		else
			daddr = ufs_rw64(ip->i_ffs2_db[bn],
			    UFS_MPNEEDSWAP(ump));
		*bnp = blkptrtodb(ump, daddr);
		/*
		 * Since this is FFS independent code, we are out of
		 * scope for the definitions of BLK_NOCOPY and
		 * BLK_SNAP, but we do know that they will fall in
		 * the range 1..um_seqinc, so we use that test and
		 * return a request for a zeroed out buffer if attempts
		 * are made to read a BLK_NOCOPY or BLK_SNAP block.
		 */
		if ((ip->i_flags & SF_SNAPSHOT) && daddr > 0 &&
		    daddr < ump->um_seqinc) {
			*bnp = -1;
		} else if (*bnp == 0) {
			if (ip->i_flags & SF_SNAPSHOT) {
				*bnp = blkptrtodb(ump, bn * ump->um_seqinc);
			} else {
				*bnp = -1;
			}
		} else if (runp) {
			if (ump->um_fstype == UFS1) {
				for (++bn; bn < NDADDR && *runp < maxrun &&
				    is_sequential(ump,
				        ufs_rw32(ip->i_ffs1_db[bn - 1],
				            UFS_MPNEEDSWAP(ump)),
				        ufs_rw32(ip->i_ffs1_db[bn],
				            UFS_MPNEEDSWAP(ump)));
				    ++bn, ++*runp);
			} else {
				for (++bn; bn < NDADDR && *runp < maxrun &&
				    is_sequential(ump,
				        ufs_rw64(ip->i_ffs2_db[bn - 1],
				            UFS_MPNEEDSWAP(ump)),
				        ufs_rw64(ip->i_ffs2_db[bn],
				            UFS_MPNEEDSWAP(ump)));
				    ++bn, ++*runp);
			}
		}
		return (0);
	}

	xap = ap == NULL ? a : ap;
	if (!nump)
		nump = &num;
	if ((error = ufs_getlbns(vp, bn, xap, nump)) != 0)
		return (error);

	num = *nump;

	/* Get disk address out of indirect block array */
	if (ump->um_fstype == UFS1)
		daddr = ufs_rw32(ip->i_ffs1_ib[xap->in_off],
		    UFS_MPNEEDSWAP(ump));
	else
		daddr = ufs_rw64(ip->i_ffs2_ib[xap->in_off],
		    UFS_MPNEEDSWAP(ump));

	for (bp = NULL, ++xap; --num; ++xap) {
		/*
		 * Exit the loop if there is no disk address assigned yet and
		 * the indirect block isn't in the cache, or if we were
		 * looking for an indirect block and we've found it.
		 */

		metalbn = xap->in_lbn;
		if ((daddr == 0 && !incore(vp, metalbn)) || metalbn == bn)
			break;
		/*
		 * If we get here, we've either got the block in the cache
		 * or we have a disk address for it, go fetch it.
		 */
		if (bp)
			brelse(bp);

		xap->in_exists = 1;
		bp = getblk(vp, metalbn, mp->mnt_stat.f_iosize, 0, 0);
		if (bp == NULL) {

			/*
			 * getblk() above returns NULL only iff we are
			 * pagedaemon.  See the implementation of getblk
			 * for detail.
			 */

			return (ENOMEM);
		}
		if (bp->b_flags & (B_DONE | B_DELWRI)) {
			trace(TR_BREADHIT, pack(vp, size), metalbn);
		}
#ifdef DIAGNOSTIC
		else if (!daddr)
			panic("ufs_bmaparry: indirect block not in cache");
#endif
		else {
			trace(TR_BREADMISS, pack(vp, size), metalbn);
			bp->b_blkno = blkptrtodb(ump, daddr);
			bp->b_flags |= B_READ;
			BIO_SETPRIO(bp, BPRIO_TIMECRITICAL);
			VOP_STRATEGY(vp, bp);
			curproc->p_stats->p_ru.ru_inblock++;	/* XXX */
			if ((error = biowait(bp)) != 0) {
				brelse(bp);
				return (error);
			}
		}
		if (ump->um_fstype == UFS1) {
			daddr = ufs_rw32(((u_int32_t *)bp->b_data)[xap->in_off],
			    UFS_MPNEEDSWAP(ump));
			if (num == 1 && daddr && runp) {
				for (bn = xap->in_off + 1;
				    bn < MNINDIR(ump) && *runp < maxrun &&
				    is_sequential(ump,
				        ufs_rw32(((int32_t *)bp->b_data)[bn-1],
				            UFS_MPNEEDSWAP(ump)),
				        ufs_rw32(((int32_t *)bp->b_data)[bn],
				            UFS_MPNEEDSWAP(ump)));
				    ++bn, ++*runp);
			}
		} else {
			daddr = ufs_rw64(((u_int64_t *)bp->b_data)[xap->in_off],
			    UFS_MPNEEDSWAP(ump));
			if (num == 1 && daddr && runp) {
				for (bn = xap->in_off + 1;
				    bn < MNINDIR(ump) && *runp < maxrun &&
				    is_sequential(ump,
				        ufs_rw64(((int64_t *)bp->b_data)[bn-1],
				            UFS_MPNEEDSWAP(ump)),
				        ufs_rw64(((int64_t *)bp->b_data)[bn],
				            UFS_MPNEEDSWAP(ump)));
				    ++bn, ++*runp);
			}
		}
	}
	if (bp)
		brelse(bp);

	/*
	 * Since this is FFS independent code, we are out of scope for the
	 * definitions of BLK_NOCOPY and BLK_SNAP, but we do know that they
	 * will fall in the range 1..um_seqinc, so we use that test and
	 * return a request for a zeroed out buffer if attempts are made
	 * to read a BLK_NOCOPY or BLK_SNAP block.
	 */
	if ((ip->i_flags & SF_SNAPSHOT) && daddr > 0 &&
	    daddr < ump->um_seqinc) {
		*bnp = -1;
		return (0);
	}
	*bnp = blkptrtodb(ump, daddr);
	if (*bnp == 0) {
		if (ip->i_flags & SF_SNAPSHOT) {
			*bnp = blkptrtodb(ump, bn * ump->um_seqinc);
		} else {
			*bnp = -1;
		}
	}
	return (0);
}

/*
 * Create an array of logical block number/offset pairs which represent the
 * path of indirect blocks required to access a data block.  The first "pair"
 * contains the logical block number of the appropriate single, double or
 * triple indirect block and the offset into the inode indirect block array.
 * Note, the logical block number of the inode single/double/triple indirect
 * block appears twice in the array, once with the offset into the i_ffs1_ib and
 * once with the offset into the page itself.
 */
int
ufs_getlbns(vp, bn, ap, nump)
	struct vnode *vp;
	daddr_t bn;
	struct indir *ap;
	int *nump;
{
	daddr_t metalbn, realbn;
	struct ufsmount *ump;
	int64_t blockcnt;
	int lbc;
	int i, numlevels, off;

	ump = VFSTOUFS(vp->v_mount);
	if (nump)
		*nump = 0;
	numlevels = 0;
	realbn = bn;
	if (bn < 0)
		bn = -bn;
	KASSERT(bn >= NDADDR);

	/*
	 * Determine the number of levels of indirection.  After this loop
	 * is done, blockcnt indicates the number of data blocks possible
	 * at the given level of indirection, and NIADDR - i is the number
	 * of levels of indirection needed to locate the requested block.
	 */

	bn -= NDADDR;
	for (lbc = 0, i = NIADDR;; i--, bn -= blockcnt) {
		if (i == 0)
			return (EFBIG);

		lbc += ump->um_lognindir;
		blockcnt = (int64_t)1 << lbc;

		if (bn < blockcnt)
			break;
	}

	/* Calculate the address of the first meta-block. */
	metalbn = 0;		/* XXX: gcc3 */
	if (realbn >= 0)
		metalbn = -(realbn - bn + NIADDR - i);
	else
		metalbn = -(-realbn - bn + NIADDR - i);

	/*
	 * At each iteration, off is the offset into the bap array which is
	 * an array of disk addresses at the current level of indirection.
	 * The logical block number and the offset in that block are stored
	 * into the argument array.
	 */
	ap->in_lbn = metalbn;
	ap->in_off = off = NIADDR - i;
	ap->in_exists = 0;
	ap++;
	for (++numlevels; i <= NIADDR; i++) {
		/* If searching for a meta-data block, quit when found. */
		if (metalbn == realbn)
			break;

		lbc -= ump->um_lognindir;
		off = (bn >> lbc) & (MNINDIR(ump) - 1);

		++numlevels;
		ap->in_lbn = metalbn;
		ap->in_off = off;
		ap->in_exists = 0;
		++ap;

		metalbn -= -1 + ((int64_t)off << lbc);
	}
	if (nump)
		*nump = numlevels;
	return (0);
}
