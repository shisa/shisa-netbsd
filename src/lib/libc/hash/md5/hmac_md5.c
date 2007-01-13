/*	$NetBSD: hmac_md5.c,v 1.2 2006/06/23 17:15:18 christos Exp $	*/

/*
 * hmac_md5 - using HMAC from RFC 2104
 */

#include "namespace.h"
#include <sys/types.h>
#include <md5.h> /* XXX */

__weak_alias(hmac_md5,_hmac_md5)

#define HMAC_HASH MD5
#define HMAC_FUNC hmac_md5
#define HMAC_KAT  hmac_kat_md5

#define HASH_LENGTH MD5_DIGEST_LENGTH
#define HASH_CTX MD5_CTX
#define HASH_Init MD5Init
#define HASH_Update MD5Update
#define HASH_Final MD5Final

#include "../hmac.c"