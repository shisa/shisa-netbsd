/*	$NetBSD: server.h,v 1.1.1.1 2004/05/17 23:43:25 christos Exp $	*/

/*
 * Copyright (C) 2004  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 1999-2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* Id: server.h,v 1.58.2.1.10.11 2004/03/08 04:04:21 marka Exp */

#ifndef NAMED_SERVER_H
#define NAMED_SERVER_H 1

#include <isc/log.h>
#include <isc/sockaddr.h>
#include <isc/magic.h>
#include <isc/types.h>
#include <isc/quota.h>

#include <dns/types.h>
#include <dns/acl.h>

#include <named/types.h>

#define NS_EVENTCLASS		ISC_EVENTCLASS(0x4E43)
#define NS_EVENT_RELOAD		(NS_EVENTCLASS + 0)
#define NS_EVENT_CLIENTCONTROL	(NS_EVENTCLASS + 1)

/*
 * Name server state.  Better here than in lots of separate global variables.
 */
struct ns_server {
	unsigned int		magic;
	isc_mem_t *		mctx;

	isc_task_t *		task;

	/* Configurable data. */
	isc_quota_t		xfroutquota;
	isc_quota_t		tcpquota;
	isc_quota_t		recursionquota;
	dns_acl_t		*blackholeacl;
	char *			statsfile;	/* Statistics file name */
	char *			dumpfile;	/* Dump file name */
	char *			recfile;	/* Recursive file name */
	isc_boolean_t		version_set;	/* User has set version */
	char *			version;	/* User-specified version */
	isc_boolean_t		hostname_set;	/* User has set hostname */
	char *			hostname;	/* User-specified hostname */
	/* Use hostname for server id */
	isc_boolean_t		server_usehostname;
	char *			server_id;	/* User-specified server id */

        /*
	 * Current ACL environment.  This defines the
	 * current values of the localhost and localnets
	 * ACLs.
	 */
	dns_aclenv_t		aclenv;

	/* Server data structures. */
	dns_loadmgr_t *		loadmgr;
	dns_zonemgr_t *		zonemgr;
	dns_viewlist_t		viewlist;
	ns_interfacemgr_t *	interfacemgr;
	dns_db_t *		in_roothints;
	dns_tkeyctx_t *		tkeyctx;

	isc_timer_t *		interface_timer;
	isc_timer_t *		heartbeat_timer;
	isc_uint32_t		interface_interval;
	isc_uint32_t		heartbeat_interval;

	isc_mutex_t		reload_event_lock;
	isc_event_t *		reload_event;

	isc_boolean_t		flushonshutdown;
	isc_boolean_t		log_queries;	/* For BIND 8 compatibility */

	isc_uint64_t *		querystats;	/* Query statistics counters */

	ns_controls_t *		controls;	/* Control channels */
	unsigned int		dispatchgen;
	ns_dispatchlist_t	dispatches;
						
};

#define NS_SERVER_MAGIC			ISC_MAGIC('S','V','E','R')
#define NS_SERVER_VALID(s)		ISC_MAGIC_VALID(s, NS_SERVER_MAGIC)

void
ns_server_create(isc_mem_t *mctx, ns_server_t **serverp);
/*
 * Create a server object with default settings.
 * This function either succeeds or causes the program to exit
 * with a fatal error.
 */

void
ns_server_destroy(ns_server_t **serverp);
/*
 * Destroy a server object, freeing its memory.
 */

void
ns_server_reloadwanted(ns_server_t *server);
/*
 * Inform a server that a reload is wanted.  This function
 * may be called asynchronously, from outside the server's task.
 * If a reload is already scheduled or in progress, the call
 * is ignored.
 */

void
ns_server_flushonshutdown(ns_server_t *server, isc_boolean_t flush);
/*
 * Inform the server that the zones should be flushed to disk on shutdown.
 */

isc_result_t
ns_server_reloadcommand(ns_server_t *server, char *args, isc_buffer_t *text);
/*
 * Act on a "reload" command from the command channel.
 */

isc_result_t
ns_server_reconfigcommand(ns_server_t *server, char *args);
/*
 * Act on a "reconfig" command from the command channel.
 */

isc_result_t
ns_server_refreshcommand(ns_server_t *server, char *args, isc_buffer_t *text);
/*
 * Act on a "refresh" command from the command channel.
 */

isc_result_t
ns_server_retransfercommand(ns_server_t *server, char *args);
/*
 * Act on a "retransfer" command from the command channel.
 */

isc_result_t
ns_server_togglequerylog(ns_server_t *server);
/*
 * Toggle logging of queries, as in BIND 8.
 */

/*
 * Dump the current statistics to the statistics file.
 */
isc_result_t
ns_server_dumpstats(ns_server_t *server);

/*
 * Dump the current cache to the dump file.
 */
isc_result_t
ns_server_dumpdb(ns_server_t *server, char *args);

/*
 * Change or increment the server debug level.
 */
isc_result_t
ns_server_setdebuglevel(ns_server_t *server, char *args);

/*
 * Flush the server's cache(s)
 */
isc_result_t
ns_server_flushcache(ns_server_t *server, char *args);

/*
 * Flush a particular name from the server's cache(s)
 */
isc_result_t
ns_server_flushname(ns_server_t *server, char *args);

/*
 * Report the server's status.
 */
isc_result_t
ns_server_status(ns_server_t *server, isc_buffer_t *text);

/*
 * Enable or disable updates for a zone.
 */
isc_result_t
ns_server_freeze(ns_server_t *server, isc_boolean_t freeze, char *args);

/*
 * Dump the current recursive queries.
 */
isc_result_t
ns_server_dumprecursing(ns_server_t *server);

/*
 * Maintain a list of dispatches that require reserved ports.
 */
void
ns_add_reserved_dispatch(ns_server_t *server, isc_sockaddr_t *addr);

#endif /* NAMED_SERVER_H */
