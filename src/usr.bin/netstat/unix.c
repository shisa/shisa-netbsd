/*	$NetBSD: unix.c,v 1.23 2005/03/04 03:59:07 atatat Exp $	*/

/*-
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 */

#include <sys/cdefs.h>
#ifndef lint
#if 0
static char sccsid[] = "from: @(#)unix.c	8.1 (Berkeley) 6/6/93";
#else
__RCSID("$NetBSD: unix.c,v 1.23 2005/03/04 03:59:07 atatat Exp $");
#endif
#endif /* not lint */

/*
 * Display protocol blocks in the unix domain.
 */
#include <sys/param.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/unpcb.h>
#define _KERNEL
struct uio;
struct proc;
#include <sys/file.h>

#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <kvm.h>
#include "netstat.h"

static	void unixdomainpr __P((struct socket *, caddr_t));

static struct	file *file, *fileNFILE;
static int	nfiles;
extern	kvm_t *kvmd;

void
unixpr(off)
	u_long	off;
{
	struct file *fp;
	struct socket sock, *so = &sock;
	char *filebuf;
	struct protosw *unixsw = (struct protosw *)off;

	filebuf = (char *)kvm_getfiles(kvmd, KERN_FILE, 0, &nfiles);
	if (filebuf == 0) {
		printf("file table read error: %s", kvm_geterr(kvmd));
		return;
	}
	file = (struct file *)(filebuf + sizeof(fp));
	fileNFILE = file + nfiles;
	for (fp = file; fp < fileNFILE; fp++) {
		if (fp->f_count == 0 || fp->f_type != DTYPE_SOCKET)
			continue;
		if (kread((u_long)fp->f_data, (char *)so, sizeof (*so)))
			continue;
		/* kludge */
		if (so->so_proto >= unixsw && so->so_proto <= unixsw + 2)
			if (so->so_pcb)
				unixdomainpr(so, fp->f_data);
	}
}

static	char *socktype[] =
    { "#0", "stream", "dgram", "raw", "rdm", "seqpacket" };

static void
unixdomainpr(so, soaddr)
	struct socket *so;
	caddr_t soaddr;
{
	struct unpcb unp;
	struct sockaddr_un sun;
	static int first = 1;

	if (kread((u_long)so->so_pcb, (char *)&unp, sizeof (unp)))
		return;
	if (unp.unp_addr)
		if (kread((u_long)unp.unp_addr, (char *)&sun, sizeof (sun)))
			unp.unp_addr = 0;
	if (first) {
		printf("Active UNIX domain sockets\n");
		printf(
"%-8.8s %-6.6s %-6.6s %-6.6s %8.8s %8.8s %8.8s %8.8s Addr\n",
		    "Address", "Type", "Recv-Q", "Send-Q",
		    "Inode", "Conn", "Refs", "Nextref");
		first = 0;
	}
	printf("%8lx %-6.6s %6ld %6ld %8lx %8lx %8lx %8lx",
	    (u_long) so->so_pcb, socktype[so->so_type], so->so_rcv.sb_cc, so->so_snd.sb_cc,
	    (u_long) unp.unp_vnode, (u_long) unp.unp_conn,
	    (u_long) unp.unp_refs, (u_long) unp.unp_nextref);
	if (unp.unp_addr)
		printf(" %.*s",
		    (int) (sun.sun_len - (sizeof(sun) - sizeof(sun.sun_path))),
		    sun.sun_path);
	else if (unp.unp_conn &&
	    kread((u_long)unp.unp_conn, (char *)&unp, sizeof (unp)) == 0 &&
	    unp.unp_addr &&
	    kread((u_long)unp.unp_addr, (char *)&sun, sizeof (sun)) == 0 &&
	    sun.sun_path[0] != '\0')
		printf(" -> %.*s",
		    (int) (sun.sun_len - (sizeof(sun) - sizeof(sun.sun_path))),
		    sun.sun_path);
	putchar('\n');
}
