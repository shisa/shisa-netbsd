/*	$NetBSD: kmemcpywrap.c,v 1.1.1.1 2004/03/28 08:56:18 martti Exp $	*/

#include "ipf.h"
#include "kmem.h"

int kmemcpywrap(from, to, size)
void *from, *to;
size_t size;
{
	int ret;

	ret = kmemcpy((caddr_t)to, (u_long)from, size);
	return ret;
}

