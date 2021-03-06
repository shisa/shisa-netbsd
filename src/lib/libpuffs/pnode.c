/*	$NetBSD: pnode.c,v 1.1 2006/12/29 15:28:11 pooka Exp $	*/

/*
 * Copyright (c) 2006 Antti Kantee.  All Rights Reserved.
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
#if !defined(lint)
__RCSID("$NetBSD: pnode.c,v 1.1 2006/12/29 15:28:11 pooka Exp $");
#endif /* !lint */

#include <sys/types.h>

#include <assert.h>
#include <puffs.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "puffs_priv.h"

/*
 * Well, you're probably wondering why this isn't optimized.
 * The reason is simple: my available time is not optimized for
 * size ... so please be patient ;)
 */
struct puffs_node *
puffs_pn_new(struct puffs_usermount *pu, void *privdata)
{
	struct puffs_node *pn;

	pn = calloc(1, sizeof(struct puffs_node));
	if (pn == NULL)
		return NULL;

	pn->pn_mnt = pu;
	pn->pn_data = privdata;
	puffs_vattr_null(&pn->pn_va);

	LIST_INSERT_HEAD(&pu->pu_pnodelst, pn, pn_entries);

	return pn;
}

void
puffs_pn_put(struct puffs_node *pn)
{

	if (pn == NULL)
		return;

	if (pn->pn_path) {
		free(pn->pn_path);
		pn->pn_path = (void *)0xdeadc0de;
	}

	LIST_REMOVE(pn, pn_entries);
	free(pn);
}
