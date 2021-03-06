/*	$NetBSD: deliver_request.c,v 1.1.1.5 2004/05/31 00:24:29 heas Exp $	*/

/*++
/* NAME
/*	deliver_request 3
/* SUMMARY
/*	mail delivery request protocol, server side
/* SYNOPSIS
/*	#include <deliver_request.h>
/*
/*	typedef struct DELIVER_REQUEST {
/* .in +5
/*		VSTREAM	*fp;
/*		int	flags;
/*		char	*queue_name;
/*		char	*queue_id;
/*		long	data_offset;
/*		long	data_size;
/*		char	*nexthop;
/*		char	*encoding;
/*		char	*sender;
/*		char	*errors_to;
/*		char	*return_receipt;
/*		long arrival_time;
/*		RECIPIENT_LIST rcpt_list;
/*		char	*hop_status;
/*		char	*client_name;
/*		char	*client_addr;
/*		char	*client_proto;
/*		char	*client_helo;
/* .in -5
/*	} DELIVER_REQUEST;
/*
/*	DELIVER_REQUEST *deliver_request_read(stream)
/*	VSTREAM *stream;
/*
/*	void	deliver_request_done(stream, request, status)
/*	VSTREAM *stream;
/*	DELIVER_REQUEST *request;
/*	int	status;
/* DESCRIPTION
/*	This module implements the delivery agent side of the `queue manager
/*	to delivery agent' protocol. In this game, the queue manager is
/*	the client, while the delivery agent is the server.
/*
/*	deliver_request_read() reads a client message delivery request,
/*	opens the queue file, and acquires a shared lock.
/*	A null result means that the client sent bad information or that
/*	it went away unexpectedly.
/*
/*	The \fBflags\fR structure member is the bit-wise OR of zero or more
/*	of the following:
/* .IP \fBDEL_REQ_FLAG_SUCCESS\fR
/*	Delete successful recipients from the queue file.
/* .IP \fBDEL_REQ_FLAG_BOUNCE\fR
/*	Delete bounced recipients from the queue file. Currently,
/*	this flag is considered to be "always on".
/* .PP
/*	The \fBDEL_REQ_FLAG_DEFLT\fR constant provides a convenient shorthand
/*	for the most common case: delete successful and bounced recipients.
/*
/*	The \fIhop_status\fR structure member must be updated
/*	by the caller when all delivery to the destination in
/*	\fInexthop\fR should be deferred. The value of the
/*	\fIhop_status\fR member is the reason; it is passed
/*	to myfree().
/*
/*	deliver_request_done() reports the delivery status back to the
/*	client, including the optional \fIhop_status\fR information,
/*	closes the queue file,
/*	and destroys the DELIVER_REQUEST structure. The result is
/*	non-zero when the status could not be reported to the client.
/* DIAGNOSTICS
/*	Warnings: bad data sent by the client. Fatal errors: out of
/*	memory, queue file open errors.
/* SEE ALSO
/*	attr_scan(3) low-level intra-mail input routines
/* LICENSE
/* .ad
/* .fi
/*	The Secure Mailer license must be distributed with this software.
/* AUTHOR(S)
/*	Wietse Venema
/*	IBM T.J. Watson Research
/*	P.O. Box 704
/*	Yorktown Heights, NY 10598, USA
/*--*/

/* System library. */

#include <sys_defs.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* Utility library. */

#include <msg.h>
#include <vstream.h>
#include <vstring.h>
#include <mymalloc.h>
#include <iostuff.h>
#include <myflock.h>

/* Global library. */

#include "mail_queue.h"
#include "mail_proto.h"
#include "mail_open_ok.h"
#include "recipient_list.h"
#include "deliver_request.h"

/* deliver_request_initial - send initial status code */

static int deliver_request_initial(VSTREAM *stream)
{
    int     err;

    /*
     * The master processes runs a finite number of delivery agent processes
     * to handle service requests. Thus, a delivery agent process must send
     * something to inform the queue manager that it is ready to receive a
     * delivery request; otherwise the queue manager could block in write().
     */
    if (msg_verbose)
	msg_info("deliver_request_initial: send initial status");
    attr_print(stream, ATTR_FLAG_NONE,
	       ATTR_TYPE_NUM, MAIL_ATTR_STATUS, 0,
	       ATTR_TYPE_END);
    if ((err = vstream_fflush(stream)) != 0)
	if (msg_verbose)
	    msg_warn("send initial status: %m");
    return (err);
}

/* deliver_request_final - send final delivery request status */

static int deliver_request_final(VSTREAM *stream, char *reason, int status)
{
    int     err;

    /*
     * Send the status and the optional reason.
     */
    if (reason == 0)
	reason = "";
    if (msg_verbose)
	msg_info("deliver_request_final: send: \"%s\" %d", reason, status);
    attr_print(stream, ATTR_FLAG_NONE,
	       ATTR_TYPE_STR, MAIL_ATTR_WHY, reason,
	       ATTR_TYPE_NUM, MAIL_ATTR_STATUS, status,
	       ATTR_TYPE_END);
    if ((err = vstream_fflush(stream)) != 0)
	if (msg_verbose)
	    msg_warn("send final status: %m");

    /*
     * XXX Solaris UNIX-domain streams sockets are brain dead. They lose data
     * when you close them immediately after writing to them. That is not how
     * sockets are supposed to behave! The workaround is to wait until the
     * receiver closes the connection. Calling VSTREAM_GETC() has the benefit
     * of using whatever timeout is specified in the ipc_timeout parameter.
     */
    (void) VSTREAM_GETC(stream);
    return (err);
}

/* deliver_request_get - receive message delivery request */

static int deliver_request_get(VSTREAM *stream, DELIVER_REQUEST *request)
{
    char   *myname = "deliver_request_get";
    const char *path;
    struct stat st;
    static VSTRING *queue_name;
    static VSTRING *queue_id;
    static VSTRING *nexthop;
    static VSTRING *encoding;
    static VSTRING *orig_addr;
    static VSTRING *address;
    static VSTRING *errors_to;
    static VSTRING *return_receipt;
    static VSTRING *client_name;
    static VSTRING *client_addr;
    static VSTRING *client_proto;
    static VSTRING *client_helo;
    long    offset;

    /*
     * Initialize. For some reason I wanted to allow for multiple instances
     * of a deliver_request structure, thus the hoopla with string
     * initialization and copying.
     */
    if (queue_name == 0) {
	queue_name = vstring_alloc(10);
	queue_id = vstring_alloc(10);
	nexthop = vstring_alloc(10);
	encoding = vstring_alloc(10);
	orig_addr = vstring_alloc(10);
	address = vstring_alloc(10);
	errors_to = vstring_alloc(10);
	return_receipt = vstring_alloc(10);
	client_name = vstring_alloc(10);
	client_addr = vstring_alloc(10);
	client_proto = vstring_alloc(10);
	client_helo = vstring_alloc(10);
    }

    /*
     * Extract the queue file name, data offset, and sender address. Abort
     * the conversation when they send bad information.
     */
    if (attr_scan(stream, ATTR_FLAG_STRICT | ATTR_FLAG_MORE,
		  ATTR_TYPE_NUM, MAIL_ATTR_FLAGS, &request->flags,
		  ATTR_TYPE_STR, MAIL_ATTR_QUEUE, queue_name,
		  ATTR_TYPE_STR, MAIL_ATTR_QUEUEID, queue_id,
		  ATTR_TYPE_LONG, MAIL_ATTR_OFFSET, &request->data_offset,
		  ATTR_TYPE_LONG, MAIL_ATTR_SIZE, &request->data_size,
		  ATTR_TYPE_STR, MAIL_ATTR_NEXTHOP, nexthop,
		  ATTR_TYPE_STR, MAIL_ATTR_ENCODING, encoding,
		  ATTR_TYPE_STR, MAIL_ATTR_SENDER, address,
		  ATTR_TYPE_STR, MAIL_ATTR_ERRTO, errors_to,
		  ATTR_TYPE_STR, MAIL_ATTR_RRCPT, return_receipt,
		  ATTR_TYPE_LONG, MAIL_ATTR_TIME, &request->arrival_time,
		  ATTR_TYPE_STR, MAIL_ATTR_CLIENT_NAME, client_name,
		  ATTR_TYPE_STR, MAIL_ATTR_CLIENT_ADDR, client_addr,
		  ATTR_TYPE_STR, MAIL_ATTR_PROTO_NAME, client_proto,
		  ATTR_TYPE_STR, MAIL_ATTR_HELO_NAME, client_helo,
		  ATTR_TYPE_END) != 15) {
	msg_warn("%s: error receiving common attributes", myname);
	return (-1);
    }
    if (mail_open_ok(vstring_str(queue_name),
		     vstring_str(queue_id), &st, &path) == 0)
	return (-1);

    request->queue_name = mystrdup(vstring_str(queue_name));
    request->queue_id = mystrdup(vstring_str(queue_id));
    request->nexthop = mystrdup(vstring_str(nexthop));
    request->encoding = mystrdup(vstring_str(encoding));
    request->sender = mystrdup(vstring_str(address));
    request->errors_to = mystrdup(vstring_str(errors_to));
    request->return_receipt = mystrdup(vstring_str(return_receipt));
    request->client_name = mystrdup(vstring_str(client_name));
    request->client_addr = mystrdup(vstring_str(client_addr));
    request->client_proto = mystrdup(vstring_str(client_proto));
    request->client_helo = mystrdup(vstring_str(client_helo));

    /*
     * Extract the recipient offset and address list. Skip over any
     * attributes from the sender that we do not understand.
     */
    for (;;) {
	if (attr_scan(stream, ATTR_FLAG_MORE | ATTR_FLAG_STRICT,
		      ATTR_TYPE_LONG, MAIL_ATTR_OFFSET, &offset,
		      ATTR_TYPE_END) != 1) {
	    msg_warn("%s: error receiving offset attribute", myname);
	    return (-1);
	}
	if (offset == 0)
	    break;
	if (attr_scan(stream, ATTR_FLAG_MORE | ATTR_FLAG_STRICT,
		      ATTR_TYPE_STR, MAIL_ATTR_ORCPT, orig_addr,
		      ATTR_TYPE_STR, MAIL_ATTR_RECIP, address,
		      ATTR_TYPE_END) != 2) {
	    msg_warn("%s: error receiving recipient attributes", myname);
	    return (-1);
	}
	recipient_list_add(&request->rcpt_list, offset,
			   vstring_str(orig_addr),
			   vstring_str(address));
    }

    /*
     * Open the queue file and set a shared lock, in order to prevent
     * duplicate deliveries when the queue is flushed immediately after queue
     * manager restart.
     * 
     * Opening the queue file can fail for a variety of reasons, such as the
     * system running out of resources. Instead of throwing away mail, we're
     * raising a fatal error which forces the mail system to back off, and
     * retry later.
     */
#define DELIVER_LOCK_MODE (MYFLOCK_OP_SHARED | MYFLOCK_OP_NOWAIT)

    request->fp =
	mail_queue_open(request->queue_name, request->queue_id, O_RDWR, 0);
    if (request->fp == 0) {
	if (errno != ENOENT)
	    msg_fatal("open %s %s: %m", request->queue_name, request->queue_id);
	msg_warn("open %s %s: %m", request->queue_name, request->queue_id);
	return (-1);
    }
    if (msg_verbose)
	msg_info("%s: file %s", myname, VSTREAM_PATH(request->fp));
    if (myflock(vstream_fileno(request->fp), INTERNAL_LOCK, DELIVER_LOCK_MODE) < 0)
	msg_fatal("shared lock %s: %m", VSTREAM_PATH(request->fp));
    close_on_exec(vstream_fileno(request->fp), CLOSE_ON_EXEC);

    return (0);
}

/* deliver_request_alloc - allocate delivery request structure */

static DELIVER_REQUEST *deliver_request_alloc(void)
{
    DELIVER_REQUEST *request;

    request = (DELIVER_REQUEST *) mymalloc(sizeof(*request));
    request->fp = 0;
    request->queue_name = 0;
    request->queue_id = 0;
    request->nexthop = 0;
    request->encoding = 0;
    request->sender = 0;
    request->errors_to = 0;
    request->return_receipt = 0;
    request->data_offset = 0;
    request->data_size = 0;
    recipient_list_init(&request->rcpt_list);
    request->hop_status = 0;
    request->client_name = 0;
    request->client_addr = 0;
    request->client_proto = 0;
    request->client_helo = 0;
    return (request);
}

/* deliver_request_free - clean up delivery request structure */

static void deliver_request_free(DELIVER_REQUEST *request)
{
    if (request->fp)
	vstream_fclose(request->fp);
    if (request->queue_name)
	myfree(request->queue_name);
    if (request->queue_id)
	myfree(request->queue_id);
    if (request->nexthop)
	myfree(request->nexthop);
    if (request->encoding)
	myfree(request->encoding);
    if (request->sender)
	myfree(request->sender);
    if (request->errors_to)
	myfree(request->errors_to);
    if (request->return_receipt)
	myfree(request->return_receipt);
    recipient_list_free(&request->rcpt_list);
    if (request->hop_status)
	myfree(request->hop_status);
    if (request->client_name)
	myfree(request->client_name);
    if (request->client_addr)
	myfree(request->client_addr);
    if (request->client_proto)
	myfree(request->client_proto);
    if (request->client_helo)
	myfree(request->client_helo);
    myfree((char *) request);
}

/* deliver_request_read - create and read delivery request */

DELIVER_REQUEST *deliver_request_read(VSTREAM *stream)
{
    DELIVER_REQUEST *request;

    /*
     * Tell the queue manager that we are ready for this request.
     */
    if (deliver_request_initial(stream) != 0)
	return (0);

    /*
     * Be prepared for the queue manager to change its mind after contacting
     * us. This can happen when a transport or host goes bad.
     */
    (void) read_wait(vstream_fileno(stream), -1);
    if (peekfd(vstream_fileno(stream)) <= 0)
	return (0);

    /*
     * Allocate and read the queue manager's delivery request.
     */
#define XXX_DEFER_STATUS	-1

    request = deliver_request_alloc();
    if (deliver_request_get(stream, request) < 0) {
	deliver_request_done(stream, request, XXX_DEFER_STATUS);
	request = 0;
    }
    return (request);
}

/* deliver_request_done - finish delivery request */

int     deliver_request_done(VSTREAM *stream, DELIVER_REQUEST *request, int status)
{
    int     err;

    err = deliver_request_final(stream, request->hop_status, status);
    deliver_request_free(request);
    return (err);
}
