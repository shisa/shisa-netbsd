/*	$NetBSD: nfs_srvcache.c,v 1.31 2004/05/21 13:53:40 yamt Exp $	*/

/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
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
 *	@(#)nfs_srvcache.c	8.3 (Berkeley) 3/30/95
 */

/*
 * Reference: Chet Juszczak, "Improving the Performance and Correctness
 *		of an NFS Server", in Proc. Winter 1989 USENIX Conference,
 *		pages 53-63. San Diego, February 1989.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: nfs_srvcache.c,v 1.31 2004/05/21 13:53:40 yamt Exp $");

#include "opt_iso.h"

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/pool.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <netinet/in.h>
#ifdef ISO
#include <netiso/iso.h>
#endif
#include <nfs/nfsm_subs.h>
#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsrvcache.h>
#include <nfs/nqnfs.h>
#include <nfs/nfs_var.h>

extern struct nfsstats nfsstats;
extern const int nfsv2_procid[NFS_NPROCS];
long numnfsrvcache, desirednfsrvcache = NFSRVCACHESIZ;
struct pool nfs_reqcache_pool;

#define	NFSRCHASH(xid) \
	(&nfsrvhashtbl[((xid) + ((xid) >> 24)) & nfsrvhash])
LIST_HEAD(nfsrvhash, nfsrvcache) *nfsrvhashtbl;
TAILQ_HEAD(nfsrvlru, nfsrvcache) nfsrvlruhead;
struct simplelock nfsrv_reqcache_lock = SIMPLELOCK_INITIALIZER;
u_long nfsrvhash;

#define	NETFAMILY(rp) \
		(((rp)->rc_flag & RC_INETADDR) ? AF_INET : AF_ISO)

static struct nfsrvcache *nfsrv_lookupcache(struct nfsrv_descript *nd);
static void nfsrv_unlockcache(struct nfsrvcache *rp);

/*
 * Static array that defines which nfs rpc's are nonidempotent
 */
const int nonidempotent[NFS_NPROCS] = {
	FALSE,	/* NULL */
	FALSE,	/* GETATTR */
	TRUE,	/* SETATTR */
	FALSE,	/* LOOKUP */
	FALSE,	/* ACCESS */
	FALSE,	/* READLINK */
	FALSE,	/* READ */
	TRUE,	/* WRITE */
	TRUE,	/* CREATE */
	TRUE,	/* MKDIR */
	TRUE,	/* SYMLINK */
	TRUE,	/* MKNOD */
	TRUE,	/* REMOVE */
	TRUE,	/* RMDIR */
	TRUE,	/* RENAME */
	TRUE,	/* LINK */
	FALSE,	/* READDIR */
	FALSE,	/* READDIRPLUS */
	FALSE,	/* FSSTAT */
	FALSE,	/* FSINFO */
	FALSE,	/* PATHCONF */
	FALSE,	/* COMMIT */
	FALSE,	/* GETLEASE */
	FALSE,	/* VACATED */
	FALSE,	/* EVICTED */
	FALSE,	/* NOOP */
};

/* True iff the rpc reply is an nfs status ONLY! */
static const int nfsv2_repstat[NFS_NPROCS] = {
	FALSE,	/* NULL */
	FALSE,	/* GETATTR */
	FALSE,	/* SETATTR */
	FALSE,	/* NOOP */
	FALSE,	/* LOOKUP */
	FALSE,	/* READLINK */
	FALSE,	/* READ */
	FALSE,	/* Obsolete WRITECACHE */
	FALSE,	/* WRITE */
	FALSE,	/* CREATE */
	TRUE,	/* REMOVE */
	TRUE,	/* RENAME */
	TRUE,	/* LINK */
	TRUE,	/* SYMLINK */
	FALSE,	/* MKDIR */
	TRUE,	/* RMDIR */
	FALSE,	/* READDIR */
	FALSE,	/* STATFS */
};

/*
 * Initialize the server request cache list
 */
void
nfsrv_initcache()
{

	nfsrvhashtbl = hashinit(desirednfsrvcache, HASH_LIST, M_NFSD,
	    M_WAITOK, &nfsrvhash);
	TAILQ_INIT(&nfsrvlruhead);
	pool_init(&nfs_reqcache_pool, sizeof(struct nfsrvcache), 0, 0, 0,
	    "nfsreqcachepl", &pool_allocator_nointr);
}

/*
 * Lookup a cache and lock it
 */
static struct nfsrvcache *
nfsrv_lookupcache(nd)
	struct nfsrv_descript *nd;
{
	struct nfsrvcache *rp;

	LOCK_ASSERT(simple_lock_held(&nfsrv_reqcache_lock));

loop:
	LIST_FOREACH(rp, NFSRCHASH(nd->nd_retxid), rc_hash) {
		if (nd->nd_retxid == rp->rc_xid &&
		    nd->nd_procnum == rp->rc_proc &&
		    netaddr_match(NETFAMILY(rp), &rp->rc_haddr, nd->nd_nam)) {
			if ((rp->rc_flag & RC_LOCKED) != 0) {
				rp->rc_flag |= RC_WANTED;
				(void) ltsleep(rp, PZERO - 1, "nfsrc", 0,
				    &nfsrv_reqcache_lock);
				goto loop;
			}
			rp->rc_flag |= RC_LOCKED;
			break;
		}
	}

	return rp;
}

/*
 * Unlock a cache
 */
static void
nfsrv_unlockcache(rp)
	struct nfsrvcache *rp;
{

	LOCK_ASSERT(simple_lock_held(&nfsrv_reqcache_lock));

	rp->rc_flag &= ~RC_LOCKED;
	if (rp->rc_flag & RC_WANTED) {
		rp->rc_flag &= ~RC_WANTED;
		wakeup(rp);
	}
}

/*
 * Look for the request in the cache
 * If found then
 *    return action and optionally reply
 * else
 *    insert it in the cache
 *
 * The rules are as follows:
 * - if in progress, return DROP request
 * - if completed within DELAY of the current time, return DROP it
 * - if completed a longer time ago return REPLY if the reply was cached or
 *   return DOIT
 * Update/add new request at end of lru list
 */
int
nfsrv_getcache(nd, slp, repp)
	struct nfsrv_descript *nd;
	struct nfssvc_sock *slp;
	struct mbuf **repp;
{
	struct nfsrvcache *rp, *rpdup;
	struct mbuf *mb;
	struct sockaddr_in *saddr;
	caddr_t bpos;
	int ret;

	simple_lock(&nfsrv_reqcache_lock);
	rp = nfsrv_lookupcache(nd);
	if (rp) {
		simple_unlock(&nfsrv_reqcache_lock);
found:
		/* If not at end of LRU chain, move it there */
		if (TAILQ_NEXT(rp, rc_lru)) { /* racy but ok */
			simple_lock(&nfsrv_reqcache_lock);
			TAILQ_REMOVE(&nfsrvlruhead, rp, rc_lru);
			TAILQ_INSERT_TAIL(&nfsrvlruhead, rp, rc_lru);
			simple_unlock(&nfsrv_reqcache_lock);
		}
		if (rp->rc_state == RC_UNUSED)
			panic("nfsrv cache");
		if (rp->rc_state == RC_INPROG) {
			nfsstats.srvcache_inproghits++;
			ret = RC_DROPIT;
		} else if (rp->rc_flag & RC_REPSTATUS) {
			nfsstats.srvcache_nonidemdonehits++;
			nfs_rephead(0, nd, slp, rp->rc_status,
			   0, (u_quad_t *)0, repp, &mb, &bpos);
			ret = RC_REPLY;
		} else if (rp->rc_flag & RC_REPMBUF) {
			nfsstats.srvcache_nonidemdonehits++;
			*repp = m_copym(rp->rc_reply, 0, M_COPYALL,
					M_WAIT);
			ret = RC_REPLY;
		} else {
			nfsstats.srvcache_idemdonehits++;
			rp->rc_state = RC_INPROG;
			ret = RC_DOIT;
		}
		simple_lock(&nfsrv_reqcache_lock);
		nfsrv_unlockcache(rp);
		simple_unlock(&nfsrv_reqcache_lock);
		return ret;
	}
	nfsstats.srvcache_misses++;
	if (numnfsrvcache < desirednfsrvcache) {
		numnfsrvcache++;
		simple_unlock(&nfsrv_reqcache_lock);
		rp = pool_get(&nfs_reqcache_pool, PR_WAITOK);
		memset(rp, 0, sizeof *rp);
		rp->rc_flag = RC_LOCKED;
	} else {
		rp = TAILQ_FIRST(&nfsrvlruhead);
		while ((rp->rc_flag & RC_LOCKED) != 0) {
			rp->rc_flag |= RC_WANTED;
			(void) ltsleep(rp, PZERO-1, "nfsrc", 0,
			    &nfsrv_reqcache_lock);
			rp = TAILQ_FIRST(&nfsrvlruhead);
		}
		rp->rc_flag |= RC_LOCKED;
		LIST_REMOVE(rp, rc_hash);
		TAILQ_REMOVE(&nfsrvlruhead, rp, rc_lru);
		simple_unlock(&nfsrv_reqcache_lock);
		if (rp->rc_flag & RC_REPMBUF)
			m_freem(rp->rc_reply);
		if (rp->rc_flag & RC_NAM)
			(void) m_free(rp->rc_nam);
		rp->rc_flag &= (RC_LOCKED | RC_WANTED);
	}
	rp->rc_state = RC_INPROG;
	rp->rc_xid = nd->nd_retxid;
	saddr = mtod(nd->nd_nam, struct sockaddr_in *);
	switch (saddr->sin_family) {
	case AF_INET:
		rp->rc_flag |= RC_INETADDR;
		rp->rc_inetaddr = saddr->sin_addr.s_addr;
		break;
	case AF_ISO:
	default:
		rp->rc_flag |= RC_NAM;
		rp->rc_nam = m_copym(nd->nd_nam, 0, M_COPYALL, M_WAIT);
		break;
	};
	rp->rc_proc = nd->nd_procnum;
	simple_lock(&nfsrv_reqcache_lock);
	rpdup = nfsrv_lookupcache(nd);
	if (rpdup != NULL) {
		/*
		 * other thread made duplicate cache entry.
		 */
		simple_unlock(&nfsrv_reqcache_lock);
		pool_put(&nfs_reqcache_pool, rp);
		rp = rpdup;
		goto found;
	}
	TAILQ_INSERT_TAIL(&nfsrvlruhead, rp, rc_lru);
	LIST_INSERT_HEAD(NFSRCHASH(nd->nd_retxid), rp, rc_hash);
	nfsrv_unlockcache(rp);
	simple_unlock(&nfsrv_reqcache_lock);
	return RC_DOIT;
}

/*
 * Update a request cache entry after the rpc has been done
 */
void
nfsrv_updatecache(nd, repvalid, repmbuf)
	struct nfsrv_descript *nd;
	int repvalid;
	struct mbuf *repmbuf;
{
	struct nfsrvcache *rp;

	if (!nd->nd_nam2)
		return;
	simple_lock(&nfsrv_reqcache_lock);
	rp = nfsrv_lookupcache(nd);
	simple_unlock(&nfsrv_reqcache_lock);
	if (rp) {
		rp->rc_state = RC_DONE;
		/*
		 * If we have a valid reply update status and save
		 * the reply for non-idempotent rpc's.
		 */
		if (repvalid && nonidempotent[nd->nd_procnum]) {
			if ((nd->nd_flag & ND_NFSV3) == 0 &&
			  nfsv2_repstat[nfsv2_procid[nd->nd_procnum]]) {
				rp->rc_status = nd->nd_repstat;
				rp->rc_flag |= RC_REPSTATUS;
			} else {
				rp->rc_reply = m_copym(repmbuf,
					0, M_COPYALL, M_WAIT);
				rp->rc_flag |= RC_REPMBUF;
			}
		}
		simple_lock(&nfsrv_reqcache_lock);
		nfsrv_unlockcache(rp);
		simple_unlock(&nfsrv_reqcache_lock);
	}
}

/*
 * Clean out the cache. Called when the last nfsd terminates.
 */
void
nfsrv_cleancache()
{
	struct nfsrvcache *rp, *nextrp;

	simple_lock(&nfsrv_reqcache_lock);
	for (rp = TAILQ_FIRST(&nfsrvlruhead); rp != 0; rp = nextrp) {
		nextrp = TAILQ_NEXT(rp, rc_lru);
		LIST_REMOVE(rp, rc_hash);
		TAILQ_REMOVE(&nfsrvlruhead, rp, rc_lru);
		pool_put(&nfs_reqcache_pool, rp);
	}
	numnfsrvcache = 0;
	simple_unlock(&nfsrv_reqcache_lock);
}
