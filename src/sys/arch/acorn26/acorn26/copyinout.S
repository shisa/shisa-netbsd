/* $NetBSD: copyinout.S,v 1.5 2003/01/17 21:55:23 thorpej Exp $ */

/*-
 * Copyright (c) 2000 Ben Harris
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
/*
 * copyinout.S - copy data between user and kernel space
 */

#include <machine/asm.h>

RCSID("$NetBSD: copyinout.S,v 1.5 2003/01/17 21:55:23 thorpej Exp $")

#include <sys/errno.h>
#include "assym.h"

/* LINTSTUB: Func: int fubyte(void *base) */
ENTRY(fubyte)
	mov	ip, lr			/* data-abort safety */
	adr	r1, Lfusufault
	ldr	r2, Lcurlwp
	ldr	r2, [r2]
	ldr	r2, [r2, #L_ADDR]
	str	r1, [r2, #(U_PCB + PCB_ONFAULT)]
/* XXX Warning: Rn and Rd must be different in LDRT */
	ldrbt	r0, [r0]
	mov	r1, #0
	str	r1, [r2, #(U_PCB + PCB_ONFAULT)]
#ifdef __APCS_26__
	movs	pc, ip
#else
	mov	pc, ip
#endif

/* LINTSTUB: Func: int fuword(void *base) */
ENTRY(fuword)
	mov	ip, lr
	adr	r1, Lfusufault
	ldr	r2, Lcurlwp
	ldr	r2, [r2]
	ldr	r2, [r2, #L_ADDR]
	str	r1, [r2, #(U_PCB + PCB_ONFAULT)]
/* XXX Warning: Rn and Rd must be different in LDRT */
	ldrt	r0, [r0]
	mov	r1, #0
	str	r1, [r2, #(U_PCB + PCB_ONFAULT)]
#ifdef __APCS_26__
	movs	pc, ip
#else
	mov	pc, ip
#endif

/* LINTSTUB: Func: int subyte(void *base, int c) */
ENTRY(subyte)
	mov	ip, lr
	adr	r3, Lfusufault
	ldr	r2, Lcurlwp
	ldr	r2, [r2]
	ldr	r2, [r2, #L_ADDR]
	str	r3, [r2, #(U_PCB + PCB_ONFAULT)]
	strbt	r1, [r0]
	mov	r0, #0
	str	r0, [r2, #(U_PCB + PCB_ONFAULT)]
#ifdef __APCS_26__
	movs	pc, ip
#else
	mov	pc, ip
#endif

/* LINTSTUB: Func: int suword(void *base, long c) */
ENTRY(suword)
	mov	ip, lr
	adr	r3, Lfusufault
	ldr	r2, Lcurlwp
	ldr	r2, [r2]
	ldr	r2, [r2, #L_ADDR]
	str	r3, [r2, #(U_PCB + PCB_ONFAULT)]
	strt	r1, [r0]
	mov	r0, #0
	str	r0, [r2, #(U_PCB + PCB_ONFAULT)]
#ifdef __APCS_26__
	movs	pc, ip
#else
	mov	pc, ip
#endif

Lfusufault:
	mov	r0, #0
	str	r0, [r2, #(U_PCB + PCB_ONFAULT)]
	mvn	r0, #0
#ifdef __APCS_26__
	movs	pc, ip
#else
	mov	pc, ip
#endif

Lcurlwp:
	.word	_C_LABEL(curlwp)
