/*	$NetBSD: settimeofday.c,v 1.6 2004/04/27 01:12:44 kleink Exp $ */

/*
 * Copyright (c) 2001 The NetBSD Foundation, Inc.      
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Emmanuel Dreyfus.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "namespace.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/systm.h>

#include <sys/clockctl.h>

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
 
#ifdef __weak_alias
__weak_alias(settimeofday,_settimeofday)
#endif 

int __clockctl_fd = -2;

int
settimeofday(tv, tzp)
	const struct timeval *tv;
	const void *tzp;
{
	struct sys_settimeofday_args args;
	int error;
	quad_t q;
	int rv;

	/*
	 * if __clockctl_fd == -1, then this is not our first time, 
	 * and we know root is the calling user. We use the system call
	 */
	if (__clockctl_fd == -1) {
try_syscall:
		q = __syscall((quad_t)SYS_settimeofday, tv, tzp);
		if (/* LINTED constant */ sizeof (quad_t) == sizeof (register_t)
		    || /* LINTED constant */ BYTE_ORDER == LITTLE_ENDIAN)
			rv = (int)q;
		else
			rv = (int)((u_quad_t)q >> 32); 
	
		/*
		 * If credentials changed from root to an unprivilegied 
		 * user, and we already had __clockctl_fd = -1, then we 
		 * tried the system call as a non root user, it failed 
		 * with EPERM, and we will try clockctl.
		 */
		if (rv != -1 || errno != EPERM)
			return rv;
		__clockctl_fd = -2;
	}

	/*
	 * If __clockctl_fd = -2 then this is our first time here, 
	 * or credentials have changed (the calling process dropped root 
	 * root privilege). Check if root is the calling user. If it is,
	 * we try the system call, if it is not, we try clockctl.
	 */
	if (__clockctl_fd == -2) {
		/* 
		 * Root always uses the syscall
		 */
		if (geteuid() == 0) {
			__clockctl_fd = -1;
			goto try_syscall;
		}

		/*
		 * If this fails, it means that we are not root
		 * and we cannot open clockctl. This is a failure.
		 */
		__clockctl_fd = open(_PATH_CLOCKCTL, O_WRONLY, 0);
		if (__clockctl_fd == -1)
			return -1;
		(void) fcntl(__clockctl_fd, F_SETFD, FD_CLOEXEC);
	}

	/* 
	 * If __clockctl_fd >=0, clockctl has already been open
	 * and used, so we carry on using it.
	 */
	SCARG(&args, tv) = tv;
	SCARG(&args, tzp) = tzp;
	error = ioctl(__clockctl_fd, CLOCKCTL_SETTIMEOFDAY, &args);
	return error;

}
