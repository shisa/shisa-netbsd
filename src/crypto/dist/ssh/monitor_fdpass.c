/*	$NetBSD: monitor_fdpass.c,v 1.4 2005/02/13 05:57:26 christos Exp $	*/
/*
 * Copyright 2001 Niels Provos <provos@citi.umich.edu>
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

#include "includes.h"
RCSID("$OpenBSD: monitor_fdpass.c,v 1.6 2004/08/13 02:51:48 djm Exp $");
__RCSID("$NetBSD: monitor_fdpass.c,v 1.4 2005/02/13 05:57:26 christos Exp $");

#include <sys/uio.h>

#include "log.h"
#include "monitor_fdpass.h"

void
mm_send_fd(int sock, int fd)
{
	struct msghdr msg;
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct iovec vec;
	char ch = '\0';
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = (caddr_t)tmp;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cmsg) = fd;

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	if ((n = sendmsg(sock, &msg, 0)) == -1)
		fatal("%s: sendmsg(%d): %s", __func__, fd,
		    strerror(errno));
	if (n != 1)
		fatal("%s: sendmsg: expected sent 1 got %ld",
		    __func__, (long)n);
}

int
mm_receive_fd(int sock)
{
	struct msghdr msg;
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct iovec vec;
	ssize_t n;
	char ch;
	int fd;

	memset(&msg, 0, sizeof(msg));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = tmp;
	msg.msg_controllen = sizeof(tmp);

	if ((n = recvmsg(sock, &msg, 0)) == -1)
		fatal("%s: recvmsg: %s", __func__, strerror(errno));
	if (n != 1)
		fatal("%s: recvmsg: expected received 1 got %ld",
		    __func__, (long)n);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL)
		fatal("%s: no message header", __func__);
	if (cmsg->cmsg_type != SCM_RIGHTS)
		fatal("%s: expected type %d got %d", __func__,
		    SCM_RIGHTS, cmsg->cmsg_type);
	fd = (*(int *)CMSG_DATA(cmsg));
	return fd;
}
