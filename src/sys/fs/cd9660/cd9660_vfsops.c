/*	$NetBSD: cd9660_vfsops.c,v 1.22.2.1 2005/08/24 18:43:38 riz Exp $	*/

/*-
 * Copyright (c) 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley
 * by Pace Willisson (pace@blitz.com).  The Rock Ridge Extension
 * Support code is derived from software contributed to Berkeley
 * by Atsushi Murai (amurai@spec.co.jp).
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
 *	@(#)cd9660_vfsops.c	8.18 (Berkeley) 5/22/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: cd9660_vfsops.c,v 1.22.2.1 2005/08/24 18:43:38 riz Exp $");

#if defined(_KERNEL_OPT)
#include "opt_compat_netbsd.h"
#endif

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <miscfs/specfs/specdev.h>
#include <sys/mount.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/disklabel.h>
#include <sys/device.h>
#include <sys/ioctl.h>
#include <sys/cdio.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/pool.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/dirent.h>

#include <fs/cd9660/iso.h>
#include <fs/cd9660/cd9660_extern.h>
#include <fs/cd9660/iso_rrip.h>
#include <fs/cd9660/cd9660_node.h>
#include <fs/cd9660/cd9660_mount.h>

MALLOC_DEFINE(M_ISOFSMNT, "ISOFS mount", "ISOFS mount structure");

extern const struct vnodeopv_desc cd9660_vnodeop_opv_desc;
extern const struct vnodeopv_desc cd9660_specop_opv_desc;
extern const struct vnodeopv_desc cd9660_fifoop_opv_desc;

const struct vnodeopv_desc * const cd9660_vnodeopv_descs[] = {
	&cd9660_vnodeop_opv_desc,
	&cd9660_specop_opv_desc,
	&cd9660_fifoop_opv_desc,
	NULL,
};

struct vfsops cd9660_vfsops = {
	MOUNT_CD9660,
	cd9660_mount,
	cd9660_start,
	cd9660_unmount,
	cd9660_root,
	cd9660_quotactl,
	cd9660_statvfs,
	cd9660_sync,
	cd9660_vget,
	cd9660_fhtovp,
	cd9660_vptofh,
	cd9660_init,
	cd9660_reinit,
	cd9660_done,
	NULL,
	cd9660_mountroot,
	cd9660_check_export,
	(int (*)(struct mount *, struct vnode *, struct timespec *)) eopnotsupp,
	vfs_stdextattrctl,
	cd9660_vnodeopv_descs,
};

static const struct genfs_ops cd9660_genfsops = {
	.gop_size = genfs_size,
};

/*
 * Called by vfs_mountroot when iso is going to be mounted as root.
 *
 * Name is updated by mount(8) after booting.
 */
#define ROOTNAME	"root_device"

static int iso_makemp __P((struct iso_mnt *isomp, struct buf *bp, int *ea_len));
static int iso_mountfs __P((struct vnode *devvp, struct mount *mp,
		struct proc *p, struct iso_args *argp));

int
cd9660_mountroot()
{
	struct mount *mp;
	struct proc *p = curproc;	/* XXX */
	int error;
	struct iso_args args;

	if (root_device->dv_class != DV_DISK)
		return (ENODEV);

	if ((error = vfs_rootmountalloc(MOUNT_CD9660, "root_device", &mp))
			!= 0) {
		vrele(rootvp);
		return (error);
	}

	args.flags = ISOFSMNT_ROOT;
	if ((error = iso_mountfs(rootvp, mp, p, &args)) != 0) {
		mp->mnt_op->vfs_refcount--;
		vfs_unbusy(mp);
		free(mp, M_MOUNT);
		return (error);
	}
	simple_lock(&mountlist_slock);
	CIRCLEQ_INSERT_TAIL(&mountlist, mp, mnt_list);
	simple_unlock(&mountlist_slock);
	(void)cd9660_statvfs(mp, &mp->mnt_stat, p);
	vfs_unbusy(mp);
	return (0);
}

/*
 * VFS Operations.
 *
 * mount system call
 */
int
cd9660_mount(mp, path, data, ndp, p)
	struct mount *mp;
	const char *path;
	void *data;
	struct nameidata *ndp;
	struct proc *p;
{
	struct vnode *devvp;
	struct iso_args args;
	int error;
	struct iso_mnt *imp = NULL;

	if (mp->mnt_flag & MNT_GETARGS) {
		imp = VFSTOISOFS(mp);
		if (imp == NULL)
			return EIO;
		args.fspec = NULL;
		args.flags = imp->im_flags;
		vfs_showexport(mp, &args.export, &imp->im_export);
		return copyout(&args, data, sizeof(args));
	}
	error = copyin(data, &args, sizeof (struct iso_args));
	if (error)
		return (error);

	if ((mp->mnt_flag & MNT_RDONLY) == 0)
		return (EROFS);

	/*
	 * If updating, check whether changing from read-only to
	 * read/write; if there is no device name, that's all we do.
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		imp = VFSTOISOFS(mp);
		if (args.fspec == 0)
			return (vfs_export(mp, &imp->im_export, &args.export));
	}
	/*
	 * Not an update, or updating the name: look up the name
	 * and verify that it refers to a sensible block device.
	 */
	NDINIT(ndp, LOOKUP, FOLLOW, UIO_USERSPACE, args.fspec, p);
	if ((error = namei(ndp)) != 0)
		return (error);
	devvp = ndp->ni_vp;

	if (devvp->v_type != VBLK) {
		vrele(devvp);
		return ENOTBLK;
	}
	if (bdevsw_lookup(devvp->v_rdev) == NULL) {
		vrele(devvp);
		return ENXIO;
	}
	/*
	 * If mount by non-root, then verify that user has necessary
	 * permissions on the device.
	 */
	if (p->p_ucred->cr_uid != 0) {
		vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY);
		error = VOP_ACCESS(devvp, VREAD, p->p_ucred, p);
		VOP_UNLOCK(devvp, 0);
		if (error) {
			vrele(devvp);
			return (error);
		}
	}
	if ((mp->mnt_flag & MNT_UPDATE) == 0) {
		/*
		 * Disallow multiple mounts of the same device.
		 * Disallow mounting of a device that is currently in use
		 * (except for root, which might share swap device for
		 * miniroot).
		 */
		error = vfs_mountedon(devvp);
		if (error)
			goto fail;
		if (vcount(devvp) > 1 && devvp != rootvp) {
			error = EBUSY;
			goto fail;
		}
		error = VOP_OPEN(devvp, FREAD, FSCRED, p);
		if (error)
			goto fail;
		error = iso_mountfs(devvp, mp, p, &args);
		if (error) {
			vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY);
			(void)VOP_CLOSE(devvp, FREAD, NOCRED, p);
			VOP_UNLOCK(devvp, 0);
			goto fail;
		}
	} else {
		vrele(devvp);
		if (devvp != imp->im_devvp)
			return (EINVAL);	/* needs translation */
	}
	imp = VFSTOISOFS(mp);
	return set_statvfs_info(path, UIO_USERSPACE, args.fspec, UIO_USERSPACE,
	    mp, p);

fail:
	vrele(devvp);
	return (error);
}

/*
 * Make a mount point from a volume descriptor
 */
static int
iso_makemp(isomp, bp, ea_len)
	struct iso_mnt *isomp;
	struct buf *bp;
	int *ea_len;
{
	struct iso_primary_descriptor *pri;
	int logical_block_size;
	struct iso_directory_record *rootp;

	pri = (struct iso_primary_descriptor *)bp->b_data;

	logical_block_size = isonum_723 (pri->logical_block_size);

	if (logical_block_size < DEV_BSIZE || logical_block_size > MAXBSIZE
	    || (logical_block_size & (logical_block_size - 1)) != 0)
		return -1;

	rootp = (struct iso_directory_record *)pri->root_directory_record;

	isomp->logical_block_size = logical_block_size;
	isomp->volume_space_size = isonum_733 (pri->volume_space_size);
	memcpy(isomp->root, rootp, sizeof(isomp->root));
	isomp->root_extent = isonum_733 (rootp->extent);
	isomp->root_size = isonum_733 (rootp->size);
	isomp->im_joliet_level = 0;

	isomp->im_bmask = logical_block_size - 1;
	isomp->im_bshift = 0;
	while ((1 << isomp->im_bshift) < isomp->logical_block_size)
		isomp->im_bshift++;

	if (ea_len != NULL)
		*ea_len = isonum_711(rootp->ext_attr_length);

	return 0;
}

/*
 * Common code for mount and mountroot
 */
static int
iso_mountfs(devvp, mp, p, argp)
	struct vnode *devvp;
	struct mount *mp;
	struct proc *p;
	struct iso_args *argp;
{
	struct iso_mnt *isomp = (struct iso_mnt *)0;
	struct buf *bp = NULL, *pribp = NULL, *supbp = NULL;
	dev_t dev = devvp->v_rdev;
	int error = EINVAL;
	int ronly = (mp->mnt_flag & MNT_RDONLY) != 0;
	int iso_bsize;
	int iso_blknum;
	int joliet_level;
	struct iso_volume_descriptor *vdp;
	struct iso_supplementary_descriptor *sup;
	int sess = 0;
	int ext_attr_length;
	struct disklabel label;

	if (!ronly)
		return EROFS;

	/* Flush out any old buffers remaining from a previous use. */
	if ((error = vinvalbuf(devvp, V_SAVE, p->p_ucred, p, 0, 0)) != 0)
		return (error);

	/* This is the "logical sector size".  The standard says this
	 * should be 2048 or the physical sector size on the device,
	 * whichever is greater.  For now, we'll just use a constant.
	 */
	iso_bsize = ISO_DEFAULT_BLOCK_SIZE;

	error = VOP_IOCTL(devvp, DIOCGDINFO, &label, FREAD, FSCRED, p);
	if (!error &&
	    label.d_partitions[DISKPART(dev)].p_fstype == FS_ISO9660) {
		/* XXX more sanity checks? */
		sess = label.d_partitions[DISKPART(dev)].p_cdsession;
	} else {
		/* fallback to old method */
		error = VOP_IOCTL(devvp, CDIOREADMSADDR, &sess, 0, FSCRED, p);
		if (error)
			sess = 0;	/* never mind */
	}
#ifdef ISO_DEBUG
	printf("isofs: session offset (part %d) %d\n", DISKPART(dev), sess);
#endif

	for (iso_blknum = 16; iso_blknum < 100; iso_blknum++) {
		if ((error = bread(devvp, (iso_blknum+sess) * btodb(iso_bsize),
				   iso_bsize, NOCRED, &bp)) != 0)
			goto out;

		vdp = (struct iso_volume_descriptor *)bp->b_data;
		if (memcmp(vdp->id, ISO_STANDARD_ID, sizeof(vdp->id)) != 0) {
			error = EINVAL;
			goto out;
		}

		switch (isonum_711(vdp->type)) {
		case ISO_VD_PRIMARY:
			if (pribp == NULL) {
				pribp = bp;
				bp = NULL;
			}
			break;

		case ISO_VD_SUPPLEMENTARY:
			if (supbp == NULL) {
				supbp = bp;
				bp = NULL;
			}
			break;

		default:
			break;
		}

		if (isonum_711 (vdp->type) == ISO_VD_END) {
			brelse(bp);
			bp = NULL;
			break;
		}

		if (bp != NULL) {
			brelse(bp);
			bp = NULL;
		}
	}

	if (pribp == NULL) {
		error = EINVAL;
		goto out;
	}

	isomp = malloc(sizeof *isomp, M_ISOFSMNT, M_WAITOK);
	memset(isomp, 0, sizeof *isomp);
	if (iso_makemp(isomp, pribp, &ext_attr_length) == -1) {
		error = EINVAL;
		goto out;
	}

	isomp->volume_space_size += sess;

	pribp->b_flags |= B_AGE;
	brelse(pribp);
	pribp = NULL;

	mp->mnt_data = isomp;
	mp->mnt_stat.f_fsidx.__fsid_val[0] = (long)dev;
	mp->mnt_stat.f_fsidx.__fsid_val[1] = makefstype(MOUNT_CD9660);
	mp->mnt_stat.f_fsid = mp->mnt_stat.f_fsidx.__fsid_val[0];
	mp->mnt_stat.f_namemax = MAXNAMLEN;
	mp->mnt_flag |= MNT_LOCAL;
	mp->mnt_dev_bshift = iso_bsize;
	mp->mnt_fs_bshift = isomp->im_bshift;
	isomp->im_mountp = mp;
	isomp->im_dev = dev;
	isomp->im_devvp = devvp;

	devvp->v_specmountpoint = mp;

	/* Check the Rock Ridge Extension support */
	if (!(argp->flags & ISOFSMNT_NORRIP)) {
		struct iso_directory_record *rootp;

		if ((error = bread(isomp->im_devvp,
				   (isomp->root_extent + ext_attr_length) <<
				   (isomp->im_bshift - DEV_BSHIFT),
				   isomp->logical_block_size, NOCRED,
				   &bp)) != 0)
		    goto out;

		rootp = (struct iso_directory_record *)bp->b_data;

		if ((isomp->rr_skip = cd9660_rrip_offset(rootp,isomp)) < 0) {
		    argp->flags  |= ISOFSMNT_NORRIP;
		} else {
		    argp->flags  &= ~ISOFSMNT_GENS;
		}

		/*
		 * The contents are valid,
		 * but they will get reread as part of another vnode, so...
		 */
		bp->b_flags |= B_AGE;
		brelse(bp);
		bp = NULL;
	}
	isomp->im_flags = argp->flags & (ISOFSMNT_NORRIP | ISOFSMNT_GENS |
		 ISOFSMNT_EXTATT | ISOFSMNT_NOJOLIET | ISOFSMNT_RRCASEINS);

	if (isomp->im_flags & ISOFSMNT_GENS)
		isomp->iso_ftype = ISO_FTYPE_9660;
	else if (isomp->im_flags & ISOFSMNT_NORRIP) {
		isomp->iso_ftype = ISO_FTYPE_DEFAULT;
		if (argp->flags & ISOFSMNT_NOCASETRANS)
			isomp->im_flags |= ISOFSMNT_NOCASETRANS;
	} else
		isomp->iso_ftype = ISO_FTYPE_RRIP;

	/* Check the Joliet Extension support */
	if ((argp->flags & ISOFSMNT_NORRIP) != 0 &&
	    (argp->flags & ISOFSMNT_NOJOLIET) == 0 &&
	    supbp != NULL) {
		joliet_level = 0;
		sup = (struct iso_supplementary_descriptor *)supbp->b_data;

		if ((isonum_711(sup->flags) & 1) == 0) {
			if (memcmp(sup->escape, "%/@", 3) == 0)
				joliet_level = 1;
			if (memcmp(sup->escape, "%/C", 3) == 0)
				joliet_level = 2;
			if (memcmp(sup->escape, "%/E", 3) == 0)
				joliet_level = 3;
		}
		if (joliet_level != 0) {
			if (iso_makemp(isomp, supbp, NULL) == -1) {
				error = EINVAL;
				goto out;
			}
			isomp->im_joliet_level = joliet_level;
		}
	}

	if (supbp != NULL) {
		brelse(supbp);
		supbp = NULL;
	}

	return 0;
out:
	if (bp)
		brelse(bp);
	if (pribp)
		brelse(pribp);
	if (supbp)
		brelse(supbp);
	if (isomp) {
		free(isomp, M_ISOFSMNT);
		mp->mnt_data = NULL;
	}
	return error;
}

/*
 * Make a filesystem operational.
 * Nothing to do at the moment.
 */
/* ARGSUSED */
int
cd9660_start(mp, flags, p)
	struct mount *mp;
	int flags;
	struct proc *p;
{
	return 0;
}

/*
 * unmount system call
 */
int
cd9660_unmount(mp, mntflags, p)
	struct mount *mp;
	int mntflags;
	struct proc *p;
{
	struct iso_mnt *isomp;
	int error, flags = 0;

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;
#if 0
	mntflushbuf(mp, 0);
	if (mntinvalbuf(mp))
		return EBUSY;
#endif
	if ((error = vflush(mp, NULLVP, flags)) != 0)
		return (error);

	isomp = VFSTOISOFS(mp);

#ifdef	ISODEVMAP
	if (isomp->iso_ftype == ISO_FTYPE_RRIP)
		iso_dunmap(isomp->im_dev);
#endif

	if (isomp->im_devvp->v_type != VBAD)
		isomp->im_devvp->v_specmountpoint = NULL;

	vn_lock(isomp->im_devvp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_CLOSE(isomp->im_devvp, FREAD, NOCRED, p);
	vput(isomp->im_devvp);
	free(isomp, M_ISOFSMNT);
	mp->mnt_data = NULL;
	mp->mnt_flag &= ~MNT_LOCAL;
	return (error);
}

/*
 * Return root of a filesystem
 */
int
cd9660_root(mp, vpp)
	struct mount *mp;
	struct vnode **vpp;
{
	struct iso_mnt *imp = VFSTOISOFS(mp);
	struct iso_directory_record *dp =
	    (struct iso_directory_record *)imp->root;
	ino_t ino = isodirino(dp, imp);

	/*
	 * With RRIP we must use the `.' entry of the root directory.
	 * Simply tell vget, that it's a relocated directory.
	 */
	return (cd9660_vget_internal(mp, ino, vpp,
				     imp->iso_ftype == ISO_FTYPE_RRIP, dp));
}

/*
 * Do operations associated with quotas, not supported
 */
/* ARGSUSED */
int
cd9660_quotactl(mp, cmd, uid, arg, p)
	struct mount *mp;
	int cmd;
	uid_t uid;
	void *arg;
	struct proc *p;
{

	return (EOPNOTSUPP);
}

/*
 * Get file system statistics.
 */
int
cd9660_statvfs(mp, sbp, p)
	struct mount *mp;
	struct statvfs *sbp;
	struct proc *p;
{
	struct iso_mnt *isomp;

	isomp = VFSTOISOFS(mp);

	sbp->f_bsize = isomp->logical_block_size;
	sbp->f_frsize = sbp->f_bsize;
	sbp->f_iosize = sbp->f_bsize;	/* XXX */
	sbp->f_blocks = isomp->volume_space_size;
	sbp->f_bfree = 0; /* total free blocks */
	sbp->f_bavail = 0; /* blocks free for non superuser */
	sbp->f_bresvd = 0; /* total reserved blocks */
	sbp->f_files =  0; /* total files */
	sbp->f_ffree = 0; /* free file nodes */
	sbp->f_favail = 0; /* free file nodes */
	sbp->f_fresvd = 0; /* reserved file nodes */
	copy_statvfs_info(sbp, mp);
	/* Use the first spare for flags: */
	sbp->f_spare[0] = isomp->im_flags;
	return 0;
}

/* ARGSUSED */
int
cd9660_sync(mp, waitfor, cred, p)
	struct mount *mp;
	int waitfor;
	struct ucred *cred;
	struct proc *p;
{
	return (0);
}

/*
 * File handle to vnode
 *
 * Have to be really careful about stale file handles:
 * - check that the inode number is in range
 * - call iget() to get the locked inode
 * - check for an unallocated inode (i_mode == 0)
 * - check that the generation number matches
 */

struct ifid {
	ushort	ifid_len;
	ushort	ifid_pad;
	int	ifid_ino;
	long	ifid_start;
};

/* ARGSUSED */
int
cd9660_fhtovp(mp, fhp, vpp)
	struct mount *mp;
	struct fid *fhp;
	struct vnode **vpp;
{
	struct ifid *ifhp = (struct ifid *)fhp;
	struct iso_node *ip;
	struct vnode *nvp;
	int error;

#ifdef	ISOFS_DBG
	printf("fhtovp: ino %d, start %ld\n",
	    ifhp->ifid_ino, ifhp->ifid_start);
#endif

	if ((error = VFS_VGET(mp, ifhp->ifid_ino, &nvp)) != 0) {
		*vpp = NULLVP;
		return (error);
	}
	ip = VTOI(nvp);
	if (ip->inode.iso_mode == 0) {
		vput(nvp);
		*vpp = NULLVP;
		return (ESTALE);
	}
	*vpp = nvp;
	return (0);
}

/* ARGSUSED */
int
cd9660_check_export(mp, nam, exflagsp, credanonp)
	struct mount *mp;
	struct mbuf *nam;
	int *exflagsp;
	struct ucred **credanonp;
{
	struct netcred *np;
	struct iso_mnt *imp = VFSTOISOFS(mp);

#ifdef	ISOFS_DBG
	printf("check_export: ino %d, start %ld\n",
	    ifhp->ifid_ino, ifhp->ifid_start);
#endif

	/*
	 * Get the export permission structure for this <mp, client> tuple.
	 */
	np = vfs_export_lookup(mp, &imp->im_export, nam);
	if (np == NULL)
		return (EACCES);

	*exflagsp = np->netc_exflags;
	*credanonp = &np->netc_anon;
	return (0);
}

int
cd9660_vget(mp, ino, vpp)
	struct mount *mp;
	ino_t ino;
	struct vnode **vpp;
{

	/*
	 * XXXX
	 * It would be nice if we didn't always set the `relocated' flag
	 * and force the extra read, but I don't want to think about fixing
	 * that right now.
	 */
	return (cd9660_vget_internal(mp, ino, vpp,
#if 0
				     VFSTOISOFS(mp)->iso_ftype == ISO_FTYPE_RRIP,
#else
				     0,
#endif
				     NULL));
}

int
cd9660_vget_internal(mp, ino, vpp, relocated, isodir)
	struct mount *mp;
	ino_t ino;
	struct vnode **vpp;
	int relocated;
	struct iso_directory_record *isodir;
{
	struct iso_mnt *imp;
	struct iso_node *ip;
#ifdef ISODEVMAP
	struct iso_dnode *dp;
#endif
	struct buf *bp;
	struct vnode *vp, *nvp;
	dev_t dev;
	int error;

	imp = VFSTOISOFS(mp);
	dev = imp->im_dev;
	if ((*vpp = cd9660_ihashget(dev, ino)) != NULLVP)
		return (0);

	/* Allocate a new vnode/iso_node. */
	if ((error = getnewvnode(VT_ISOFS, mp, cd9660_vnodeop_p, &vp)) != 0) {
		*vpp = NULLVP;
		return (error);
	}
	ip = pool_get(&cd9660_node_pool, PR_WAITOK);
	memset(ip, 0, sizeof(struct iso_node));
	vp->v_data = ip;
	ip->i_vnode = vp;
	ip->i_dev = dev;
	ip->i_number = ino;

	/*
	 * Put it onto its hash chain and lock it so that other requests for
	 * this inode will block if they arrive while we are sleeping waiting
	 * for old data structures to be purged or for the contents of the
	 * disk portion of this inode to be read.
	 */
	cd9660_ihashins(ip);

	if (isodir == 0) {
		int lbn, off;

		lbn = lblkno(imp, ino);
		if (lbn >= imp->volume_space_size) {
			vput(vp);
			printf("fhtovp: lbn exceed volume space %d\n", lbn);
			return (ESTALE);
		}

		off = blkoff(imp, ino);
		if (off + ISO_DIRECTORY_RECORD_SIZE > imp->logical_block_size) {
			vput(vp);
			printf("fhtovp: crosses block boundary %d\n",
			    off + ISO_DIRECTORY_RECORD_SIZE);
			return (ESTALE);
		}

		error = bread(imp->im_devvp,
			      lbn << (imp->im_bshift - DEV_BSHIFT),
			      imp->logical_block_size, NOCRED, &bp);
		if (error) {
			vput(vp);
			brelse(bp);
			printf("fhtovp: bread error %d\n",error);
			return (error);
		}
		isodir = (struct iso_directory_record *)(bp->b_data + off);

		if (off + isonum_711(isodir->length) >
		    imp->logical_block_size) {
			vput(vp);
			if (bp != 0)
				brelse(bp);
			printf("fhtovp: directory crosses block boundary %d[off=%d/len=%d]\n",
			    off +isonum_711(isodir->length), off,
			    isonum_711(isodir->length));
			return (ESTALE);
		}

#if 0
		if (isonum_733(isodir->extent) +
		    isonum_711(isodir->ext_attr_length) != ifhp->ifid_start) {
			if (bp != 0)
				brelse(bp);
			printf("fhtovp: file start miss %d vs %d\n",
			    isonum_733(isodir->extent) + isonum_711(isodir->ext_attr_length),
			    ifhp->ifid_start);
			return (ESTALE);
		}
#endif
	} else
		bp = 0;

	ip->i_mnt = imp;
	ip->i_devvp = imp->im_devvp;
	VREF(ip->i_devvp);

	if (relocated) {
		/*
		 * On relocated directories we must
		 * read the `.' entry out of a dir.
		 */
		ip->iso_start = ino >> imp->im_bshift;
		if (bp != 0)
			brelse(bp);
		if ((error = VOP_BLKATOFF(vp, (off_t)0, NULL, &bp)) != 0) {
			vput(vp);
			return (error);
		}
		isodir = (struct iso_directory_record *)bp->b_data;
	}

	ip->iso_extent = isonum_733(isodir->extent);
	ip->i_size = isonum_733(isodir->size);
	ip->iso_start = isonum_711(isodir->ext_attr_length) + ip->iso_extent;

	/*
	 * Setup time stamp, attribute
	 */
	vp->v_type = VNON;
	switch (imp->iso_ftype) {
	default:	/* ISO_FTYPE_9660 */
	    {
		struct buf *bp2;
		int off;
		if ((imp->im_flags & ISOFSMNT_EXTATT)
		    && (off = isonum_711(isodir->ext_attr_length)))
			VOP_BLKATOFF(vp, (off_t)-(off << imp->im_bshift), NULL,
				     &bp2);
		else
			bp2 = NULL;
		cd9660_defattr(isodir, ip, bp2);
		cd9660_deftstamp(isodir, ip, bp2);
		if (bp2)
			brelse(bp2);
		break;
	    }
	case ISO_FTYPE_RRIP:
		cd9660_rrip_analyze(isodir, ip, imp);
		break;
	}

	if (bp != 0)
		brelse(bp);

	/*
	 * Initialize the associated vnode
	 */
	switch (vp->v_type = IFTOVT(ip->inode.iso_mode)) {
	case VFIFO:
		vp->v_op = cd9660_fifoop_p;
		break;
	case VCHR:
	case VBLK:
		/*
		 * if device, look at device number table for translation
		 */
#ifdef	ISODEVMAP
		if ((dp = iso_dmap(dev, ino, 0)) != NULL)
			ip->inode.iso_rdev = dp->d_dev;
#endif
		vp->v_op = cd9660_specop_p;
		if ((nvp = checkalias(vp, ip->inode.iso_rdev, mp)) != NULL) {
			/*
			 * Discard unneeded vnode, but save its iso_node.
			 * Note that the lock is carried over in the iso_node
			 * to the replacement vnode.
			 */
			nvp->v_data = vp->v_data;
			vp->v_data = NULL;
			VOP_UNLOCK(vp, 0);
			vp->v_op = spec_vnodeop_p;
			vrele(vp);
			vgone(vp);
			lockmgr(&nvp->v_lock, LK_EXCLUSIVE, &nvp->v_interlock);
			/*
			 * Reinitialize aliased inode.
			 */
			vp = nvp;
			ip->i_vnode = vp;
		}
		break;
	case VLNK:
	case VNON:
	case VSOCK:
	case VDIR:
	case VBAD:
		break;
	case VREG:
		uvm_vnp_setsize(vp, ip->i_size);
		break;
	}

	if (ip->iso_extent == imp->root_extent)
		vp->v_flag |= VROOT;

	/*
	 * XXX need generation number?
	 */

	genfs_node_init(vp, &cd9660_genfsops);
	*vpp = vp;
	return (0);
}

/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
int
cd9660_vptofh(vp, fhp)
	struct vnode *vp;
	struct fid *fhp;
{
	struct iso_node *ip = VTOI(vp);
	struct ifid *ifhp;

	ifhp = (struct ifid *)fhp;
	ifhp->ifid_len = sizeof(struct ifid);

	ifhp->ifid_ino = ip->i_number;
	ifhp->ifid_start = ip->iso_start;

#ifdef	ISOFS_DBG
	printf("vptofh: ino %d, start %ld\n",
	    ifhp->ifid_ino,ifhp->ifid_start);
#endif
	return 0;
}

SYSCTL_SETUP(sysctl_vfs_cd9660_setup, "sysctl vfs.cd9660 subtree setup")
{

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT, CTLTYPE_NODE, "vfs", NULL,
		       NULL, 0, NULL, 0,
		       CTL_VFS, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT, CTLTYPE_NODE, "cd9660",
		       SYSCTL_DESCR("ISO-9660 file system"),
		       NULL, 0, NULL, 0,
		       CTL_VFS, 14, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "utf8_joliet",
		       SYSCTL_DESCR("Encode Joliet file names to UTF-8"),
		       NULL, 0, &cd9660_utf8_joliet, 0,
		       CTL_VFS, 14, CD9660_UTF8_JOLIET, CTL_EOL);

}
