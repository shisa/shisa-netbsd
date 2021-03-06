/*	$NetBSD: fs.c,v 1.2 2007/01/06 18:25:19 pooka Exp $	*/

/*
 * Copyright (c) 2006  Antti Kantee.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the company nor the name of the author may be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD: fs.c,v 1.2 2007/01/06 18:25:19 pooka Exp $");
#endif /* !lint */

#include <err.h>
#include <puffs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "psshfs.h"
#include "sftp_proto.h"

int
psshfs_domount(struct puffs_usermount *pu)
{
	struct statvfs sb;
	struct psshfs_ctx *pctx = pu->pu_privdata;
	struct psshfs_node *root = &pctx->psn_root;
	struct vattr va;
	struct vattr *rva;
	struct psbuf *pb;
	char *rootpath;
	uint32_t count;
	int rv;

	pb = psbuf_make(PSB_OUT);
	psbuf_put_1(pb, SSH_FXP_INIT);
	psbuf_put_4(pb, SFTP_PROTOVERSION);

	while ((rv = psbuf_write(pctx, pb)) != 1)
		if (rv == -1)
			err(1, "write handshake");

	psbuf_destroy(pb);
	pb = psbuf_make(PSB_IN);

	while ((rv = psbuf_read(pctx, pb)) != 1)
		if (rv == -1)
			err(1, "read handshake response");

	if (pb->type != SSH_FXP_VERSION)
		errx(1, "invalid server response");
	pctx->protover = pb->reqid;

	/* might contain some other stuff, but we're not interested */

	/* scope out our rootpath */
	psbuf_recycle(pb, PSB_OUT);
	psbuf_put_1(pb, SSH_FXP_REALPATH);
	psbuf_put_4(pb, NEXTREQ(pctx));
	psbuf_put_str(pb, pctx->mountpath);
	while ((rv = psbuf_write(pctx, pb)) != 1)
		if (rv == -1)
			err(1, "realpath query");

	psbuf_recycle(pb, PSB_IN);

	while ((rv = psbuf_read(pctx, pb)) != 1)
		if (rv == -1)
			err(1, "read realpath query response");
	if (pb->type != SSH_FXP_NAME)
		errx(1, "invalid server realpath response for \"%s\"",
		    pctx->mountpath);

	if (!psbuf_get_4(pb, &count))
		errx(1, "invalid realpath response: count");
	if (!psbuf_get_str(pb, &rootpath, NULL))
		errx(1, "invalid realpath response: rootpath");

	/* stat the rootdir so that we know it's a dir */
	psbuf_recycle(pb, PSB_OUT);
	psbuf_req_str(pb, SSH_FXP_LSTAT, NEXTREQ(pctx), rootpath);
	while ((rv == psbuf_write(pctx, pb)) != 1)
		if (rv == -1)
			errx(1, "lstat");

	psbuf_recycle(pb, PSB_IN);

	while ((rv = psbuf_read(pctx, pb)) != 1)
		if (rv == -1)
			errx(1, "read lstat response");

	rv = psbuf_expect_attrs(pb, &va);
	if (rv)
		errx(1, "couldn't stat rootpath");
	psbuf_destroy(pb);

	if (puffs_mode2vt(va.va_mode) != VDIR)
		errx(1, "remote path (%s) not a directory", rootpath);

	pctx->nextino = 2;

	memset(root, 0, sizeof(struct psshfs_node));
	pu->pu_pn_root = puffs_pn_new(pu, root);
	puffs_setrootpath(pu, rootpath);
	free(rootpath);

	rva = &pu->pu_pn_root->pn_va;
	puffs_setvattr(rva, &va);
	rva->va_fileid = pctx->nextino++;
	rva->va_nlink = 0156; /* XXX */

	puffs_zerostatvfs(&sb);
	if (puffs_start(pu, pu->pu_pn_root, &sb) != 0)
		return errno;

	return 0;
}

int
psshfs_fs_unmount(struct puffs_cc *pcc, int flags, pid_t pid)
{
	struct puffs_usermount *pu = puffs_cc_getusermount(pcc);
	struct psshfs_ctx *pctx = pu->pu_privdata;

	kill(pctx->sshpid, SIGTERM);
	close(pctx->sshfd);
	return 0;
}
