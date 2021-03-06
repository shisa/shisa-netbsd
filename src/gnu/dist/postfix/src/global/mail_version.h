/*	$NetBSD: mail_version.h,v 1.1.1.17 2004/11/13 05:05:43 heas Exp $	*/

#ifndef _MAIL_VERSION_H_INCLUDED_
#define _MAIL_VERSION_H_INCLUDED_

/*++
/* NAME
/*	mail_version 3h
/* SUMMARY
/*	globally configurable parameters
/* SYNOPSIS
/*	#include <mail_version.h>
/* DESCRIPTION
/* .nf

 /*
  * Version of this program. Official versions are called a.b.c, and
  * snapshots are called a.b-yyyymmdd, where a=major release number,
  * b=minor release number, c=patchlevel, and yyyymmdd is the release date:
  * yyyy=year, mm=month, dd=day.
  * 
  * Patches change the patchlevel and the release date. Snapshots change the
  * release date only.
  */
#define MAIL_RELEASE_DATE	"20040915"
#define MAIL_VERSION_NUMBER	"2.1.5"

#define VAR_MAIL_VERSION	"mail_version"
#ifdef SNAPSHOT
#define DEF_MAIL_VERSION	MAIL_VERSION_NUMBER "-" MAIL_RELEASE_DATE
#else
#define DEF_MAIL_VERSION	MAIL_VERSION_NUMBER
#endif
extern char *var_mail_version;

 /*
  * Release date.
  */
#define VAR_MAIL_RELEASE	"mail_release_date"
#define DEF_MAIL_RELEASE	MAIL_RELEASE_DATE
extern char *var_mail_release;

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

#endif
