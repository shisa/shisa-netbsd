/*	$NetBSD: linux32_unistd.c,v 1.1 2006/02/09 19:18:57 manu Exp $ */

/*-
 * Copyright (c) 2006 Emmanuel Dreyfus, all rights reserved.
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
 *	This product includes software developed by Emmanuel Dreyfus
 * 4. The name of the author may not be used to endorse or promote 
 *    products derived from this software without specific prior written 
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE THE AUTHOR AND CONTRIBUTORS ``AS IS'' 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS 
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>

__KERNEL_RCSID(0, "$NetBSD: linux32_unistd.c,v 1.1 2006/02/09 19:18:57 manu Exp $");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/fstypes.h>
#include <sys/signal.h>
#include <sys/dirent.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/sa.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/swap.h>

#include <machine/types.h>

#include <sys/syscallargs.h>

#include <compat/netbsd32/netbsd32.h>
#include <compat/netbsd32/netbsd32_conv.h>
#include <compat/netbsd32/netbsd32_syscallargs.h>

#include <compat/linux/common/linux_types.h>
#include <compat/linux/common/linux_signal.h>
#include <compat/linux/common/linux_machdep.h>
#include <compat/linux/common/linux_misc.h>
#include <compat/linux/common/linux_oldolduname.h>
#include <compat/linux/linux_syscallargs.h>

#include <compat/linux32/common/linux32_types.h>
#include <compat/linux32/common/linux32_signal.h>
#include <compat/linux32/common/linux32_machdep.h>
#include <compat/linux32/common/linux32_sysctl.h>
#include <compat/linux32/common/linux32_socketcall.h>
#include <compat/linux32/linux32_syscallargs.h>

static int linux32_select1(struct lwp *, register_t *, 
    int, fd_set *, fd_set *, fd_set *, struct timeval *);

int
linux32_sys_brk(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_brk_args /* {
		syscallarg(netbsd32_charp) nsize;
	} */ *uap = v;
	struct linux_sys_brk_args ua;

	NETBSD32TOP_UAP(nsize, char);
	return linux_sys_brk(l, &ua, retval);
}

int
linux32_sys_access(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_access_args /* {
		syscallarg(const netbsd32_charp) path;
		syscallarg(int) flags;
	} */ *uap = v;
	struct sys_access_args ua;
	caddr_t sg;

	NETBSD32TOP_UAP(path, const char);
	NETBSD32TO64_UAP(flags);

	sg = stackgap_init(l->l_proc, 0);
	CHECK_ALT_EXIST(l, &sg, SCARG(&ua, path));

	return sys_access(l, &ua, retval);
}

int
linux32_sys_llseek(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_llseek_args /* {
		syscallcarg(int) fd;
                syscallarg(u_int32_t) ohigh;
                syscallarg(u_int32_t) olow;
		syscallarg(netbsd32_caddr_t) res;
		syscallcarg(int) whence;
	} */ *uap = v;
	struct linux_sys_llseek_args ua;

	NETBSD32TO64_UAP(fd);
	NETBSD32TO64_UAP(ohigh);
	NETBSD32TO64_UAP(olow);
	NETBSD32TOP_UAP(res, char);
	NETBSD32TO64_UAP(whence);

	return linux_sys_llseek(l, &ua, retval);
}

int
linux32_sys_readlink(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_readlink_args /* {
		syscallarg(const netbsd32_charp) name;
		syscallarg(netbsd32_charp) buf;
		syscallarg(int) count;
	} */ *uap = v;
	struct linux_sys_readlink_args ua;

	NETBSD32TOP_UAP(name, const char);
	NETBSD32TOP_UAP(buf, char)
	NETBSD32TO64_UAP(count);

	return linux_sys_readlink(l, &ua, retval);
}


int
linux32_sys_select(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_select_args /* {
		syscallarg(int) nfds;
		syscallarg(netbsd32_fd_setp_t) readfds;
		syscallarg(netbsd32_fd_setp_t) writefds;
		syscallarg(netbsd32_fd_setp_t) exceptfds;
		syscallarg(netbsd32_timevalp_t) timeout;
	} */ *uap = v;

	return linux32_select1(l, retval, SCARG(uap, nfds), 
	    NETBSD32PTR64(SCARG(uap, readfds)),
	    NETBSD32PTR64(SCARG(uap, writefds)), 
	    NETBSD32PTR64(SCARG(uap, exceptfds)), 
	    NETBSD32PTR64(SCARG(uap, timeout)));
}

int
linux32_sys_oldselect(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_oldselect_args /* {
		syscallarg(linux32_oldselectp_t) lsp;
	} */ *uap = v;
	struct linux32_oldselect lsp32;
	int error;

	if ((error = copyin(NETBSD32PTR64(SCARG(uap, lsp)), 
	    &lsp32, sizeof(lsp32))) != 0)
		return error;

	return linux32_select1(l, retval, lsp32.nfds, 
	     NETBSD32PTR64(lsp32.readfds), NETBSD32PTR64(lsp32.writefds),
	     NETBSD32PTR64(lsp32.exceptfds), NETBSD32PTR64(lsp32.timeout));
}

static int
linux32_select1(l, retval, nfds, readfds, writefds, exceptfds, timeout)
        struct lwp *l;
        register_t *retval;
        int nfds;
        fd_set *readfds, *writefds, *exceptfds;
        struct timeval *timeout;
{   
	struct timeval tv0, tv1, utv, otv;
	struct netbsd32_timeval utv32;
	int error;

	/*
	 * Store current time for computation of the amount of
	 * time left.
	 */
	if (timeout) {
		if ((error = copyin(timeout, &utv32, sizeof(utv32))))
			return error;

		netbsd32_to_timeval(&utv32, &utv);
		otv = utv;

		if (itimerfix(&utv)) {
			/*
			 * The timeval was invalid.  Convert it to something
			 * valid that will act as it does under Linux.
			 */
			utv.tv_sec += utv.tv_usec / 1000000;
			utv.tv_usec %= 1000000;
			if (utv.tv_usec < 0) {
				utv.tv_sec -= 1;
				utv.tv_usec += 1000000;
			}
			if (utv.tv_sec < 0)
				timerclear(&utv);
		}
		microtime(&tv0);
	} else {
		timerclear(&utv);
	}

	error = selcommon(l, retval, nfds, 
	    readfds, writefds, exceptfds, &utv, NULL);

	if (error) {
		/*
		 * See fs/select.c in the Linux kernel.  Without this,
		 * Maelstrom doesn't work.
		 */
		if (error == ERESTART)
			error = EINTR;
		return error;
	}

	if (timeout) {
		if (*retval) {
			/*
			 * Compute how much time was left of the timeout,
			 * by subtracting the current time and the time
			 * before we started the call, and subtracting
			 * that result from the user-supplied value.
			 */
			microtime(&tv1);
			timersub(&tv1, &tv0, &tv1);
			timersub(&otv, &tv1, &utv);
			if (utv.tv_sec < 0)
				timerclear(&utv);
		} else {
			timerclear(&utv);
		}
		
		netbsd32_from_timeval(&utv, &utv32);

		if ((error = copyout(&utv32, timeout, sizeof(utv32))))
			return error;
	}

	return 0;
}

int
linux32_sys_pipe(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_pipe_args /* {
		syscallarg(netbsd32_intp) fd;
	} */ *uap = v;
	int error;
	int pfds[2];

	if ((error = sys_pipe(l, 0, retval)))
		return error;

	pfds[0] = (int)retval[0];
	pfds[1] = (int)retval[1];

	if ((error = copyout(pfds, NETBSD32PTR64(SCARG(uap, fd)), 
	    2 * sizeof (int))) != 0)
		return error;

	retval[0] = 0;
	retval[1] = 0;

	return 0;
}


int
linux32_sys_unlink(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_unlink_args /* {
		syscallarg(const netbsd32_charp) path;
	} */ *uap = v;
	struct linux_sys_unlink_args ua;

	NETBSD32TOP_UAP(path, const char);
	
	return linux_sys_unlink(l, &ua, retval);
}

int
linux32_sys_chdir(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_chdir_args /* {
		syscallarg(const netbsd32_charp) path;
	} */ *uap = v;
	struct sys_chdir_args ua;
	caddr_t sg = stackgap_init(l->l_proc, 0);

	NETBSD32TOP_UAP(path, const char);

	CHECK_ALT_EXIST(l, &sg, SCARG(&ua, path));
	
	return sys_chdir(l, &ua, retval);
}

int
linux32_sys_link(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_link_args /* {
		syscallarg(const netbsd32_charp) path;
		syscallarg(const netbsd32_charp) link;
	} */ *uap = v;
	struct sys_link_args ua;
	caddr_t sg = stackgap_init(l->l_proc, 0);

	NETBSD32TOP_UAP(path, const char);
	NETBSD32TOP_UAP(link, const char);

	CHECK_ALT_EXIST(l, &sg, SCARG(&ua, path));
	CHECK_ALT_CREAT(l, &sg, SCARG(&ua, link));
	
	return sys_link(l, &ua, retval);
}

int
linux32_sys_creat(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_creat_args /* {
		syscallarg(const netbsd32_charp) path;
		syscallarg(int) mode;
	} */ *uap = v;
	struct sys_open_args ua;
	caddr_t sg = stackgap_init(l->l_proc, 0);

	NETBSD32TOP_UAP(path, const char);
	SCARG(&ua, flags) = O_CREAT | O_TRUNC | O_WRONLY;
	NETBSD32TO64_UAP(mode);

	CHECK_ALT_EXIST(l, &sg, SCARG(&ua, path));

	return sys_open(l, &ua, retval);
}

int
linux32_sys_mknod(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_mknod_args /* {
		syscallarg(const netbsd32_charp) path;
		syscallarg(int) mode;
		syscallarg(int) dev;
	} */ *uap = v;
	struct linux_sys_mknod_args ua;

	NETBSD32TOP_UAP(path, const char);
	NETBSD32TO64_UAP(mode);
	NETBSD32TO64_UAP(dev);

	return linux_sys_mknod(l, &ua, retval);
}

int
linux32_sys_chmod(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_chmod_args /* {
		syscallarg(const netbsd32_charp) path;
		syscallarg(int) mode;
	} */ *uap = v;
	struct sys_chmod_args ua;
	caddr_t sg = stackgap_init(l->l_proc, 0);

	NETBSD32TOP_UAP(path, const char);
	NETBSD32TO64_UAP(mode);

	CHECK_ALT_EXIST(l, &sg, SCARG(&ua, path));

	return sys_chmod(l, &ua, retval);
}

int
linux32_sys_lchown16(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_lchown16_args /* {
		syscallarg(const netbsd32_charp) path;
		syscallarg(int) uid;
		syscallarg(int) gid;
	} */ *uap = v;
        struct sys___posix_lchown_args ua;
        caddr_t sg = stackgap_init(l->l_proc, 0);

	NETBSD32TOP_UAP(path, const char);
        CHECK_ALT_SYMLINK(l, &sg, SCARG(&ua, path));

        if ((linux32_uid_t)SCARG(uap, uid) == (linux32_uid_t)-1)
        	SCARG(&ua, uid) = (uid_t)-1;
	else
        	SCARG(&ua, uid) = SCARG(uap, uid);

        if ((linux32_gid_t)SCARG(uap, gid) == (linux32_gid_t)-1)
        	SCARG(&ua, gid) = (gid_t)-1;
	else
        	SCARG(&ua, gid) = SCARG(uap, gid);
       
        return sys___posix_lchown(l, &ua, retval);
}

int
linux32_sys_break(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
#if 0
	struct linux32_sys_break_args /* {
		syscallarg(const netbsd32_charp) nsize;
	} */ *uap = v;
#endif

	return ENOSYS;
}

int
linux32_sys_rename(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_rename_args /* {
		syscallarg(const netbsd32_charp) from;
		syscallarg(const netbsd32_charp) to;
	} */ *uap = v;
	struct sys_rename_args ua;
	caddr_t sg = stackgap_init(l->l_proc, 0);

	NETBSD32TOP_UAP(from, const char);
	NETBSD32TOP_UAP(to, const char);

	CHECK_ALT_EXIST(l, &sg, SCARG(&ua, from));
	CHECK_ALT_CREAT(l, &sg, SCARG(&ua, to));
	
	return sys___posix_rename(l, &ua, retval);
}

int
linux32_sys_mkdir(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_mkdir_args /* {
		syscallarg(const netbsd32_charp) path;
		syscallarg(int) mode;
	} */ *uap = v;
	struct sys_mkdir_args ua;
	caddr_t sg = stackgap_init(l->l_proc, 0);

	NETBSD32TOP_UAP(path, const char);
	NETBSD32TO64_UAP(mode);

	CHECK_ALT_CREAT(l, &sg, SCARG(&ua, path));
	
	return sys_mkdir(l, &ua, retval);
}

int
linux32_sys_rmdir(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_rmdir_args /* {
		syscallarg(const netbsd32_charp) path;
	} */ *uap = v;
	struct sys_rmdir_args ua;
	caddr_t sg = stackgap_init(l->l_proc, 0);

	NETBSD32TOP_UAP(path, const char);

	CHECK_ALT_EXIST(l, &sg, SCARG(&ua, path));
	
	return sys_rmdir(l, &ua, retval);
}

int
linux32_sys_getgroups16(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_getgroups16_args /* {
		syscallarg(int) gidsetsize;
		syscallarg(linux32_gidp_t) gidset;
	} */ *uap = v;
	struct linux_sys_getgroups16_args ua;

	NETBSD32TO64_UAP(gidsetsize);
	NETBSD32TOP_UAP(gidset, linux32_gid_t);
	
	return linux_sys_getgroups16(l, &ua, retval);
}

int
linux32_sys_setgroups16(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_setgroups16_args /* {
		syscallarg(int) gidsetsize;
		syscallarg(linux32_gidp_t) gidset;
	} */ *uap = v;
	struct linux_sys_setgroups16_args ua;

	NETBSD32TO64_UAP(gidsetsize);
	NETBSD32TOP_UAP(gidset, linux32_gid_t);
	
	return linux_sys_setgroups16(l, &ua, retval);
}

int
linux32_sys_symlink(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_symlink_args /* {
		syscallarg(const netbsd32_charp) path;
		syscallarg(const netbsd32_charp) link;
	} */ *uap = v;
	struct sys_symlink_args ua;
	caddr_t sg = stackgap_init(l->l_proc, 0);

	NETBSD32TOP_UAP(path, const char);
	NETBSD32TOP_UAP(link, const char);

	CHECK_ALT_EXIST(l, &sg, SCARG(&ua, path));
	CHECK_ALT_CREAT(l, &sg, SCARG(&ua, link));
	
	return sys_symlink(l, &ua, retval);
}


int
linux32_sys_swapon(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_swapon_args /* {
		syscallarg(const netbsd32_charp) name;
	} */ *uap = v;
	struct sys_swapctl_args ua;

        SCARG(&ua, cmd) = SWAP_ON;
        SCARG(&ua, arg) = (void *)__UNCONST(NETBSD32PTR64(SCARG(uap, name)));
        SCARG(&ua, misc) = 0;   /* priority */
        return (sys_swapctl(l, &ua, retval));
}

int
linux32_sys_swapoff(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_swapoff_args /* {
		syscallarg(const netbsd32_charp) path;
	} */ *uap = v;
	struct sys_swapctl_args ua;

        SCARG(&ua, cmd) = SWAP_OFF;
        SCARG(&ua, arg) = (void *)__UNCONST(NETBSD32PTR64(SCARG(uap, path)));
        SCARG(&ua, misc) = 0;   /* priority */
        return (sys_swapctl(l, &ua, retval));
}


int
linux32_sys_reboot(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_reboot_args /* {
		syscallarg(int) magic1;
		syscallarg(int) magic2;
		syscallarg(int) cmd;
		syscallarg(netbsd32_voidp) arg;
	} */ *uap = v;
	struct linux_sys_reboot_args ua;

	NETBSD32TO64_UAP(magic1);
	NETBSD32TO64_UAP(magic2);
	NETBSD32TO64_UAP(cmd);
	NETBSD32TOP_UAP(arg, void);
	
	return linux_sys_reboot(l, &ua, retval);
}

int
linux32_sys_truncate(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_truncate_args /* {
		syscallarg(const netbsd32_charp) path;
		syscallarg(netbsd32_charp) buf;
		syscallarg(int) count;
	} */ *uap = v;
	struct compat_43_sys_truncate_args ua;

	NETBSD32TOP_UAP(path, const char);
	NETBSD32TO64_UAP(length);

	return compat_43_sys_truncate(l, &ua, retval);
}

int
linux32_sys_fchown16(l, v, retval)
	struct lwp *l;
	void *v;
	register_t *retval;
{
	struct linux32_sys_fchown16_args /* {
		syscallarg(int) fd;
		syscallarg(int) uid;
		syscallarg(int) gid;
	} */ *uap = v;
        struct sys___posix_fchown_args ua;

	SCARG(&ua, fd) = SCARG(uap, fd);

        if ((linux32_uid_t)SCARG(uap, uid) == (linux32_uid_t)-1)
        	SCARG(&ua, uid) = (uid_t)-1;
	else
        	SCARG(&ua, uid) = SCARG(uap, uid);

        if ((linux32_gid_t)SCARG(uap, gid) == (linux32_gid_t)-1)
        	SCARG(&ua, gid) = (gid_t)-1;
	else
        	SCARG(&ua, gid) = SCARG(uap, gid);
       
        return sys___posix_fchown(l, &ua, retval);
}
