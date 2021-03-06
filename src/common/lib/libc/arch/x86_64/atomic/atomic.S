/*	$NetBSD: atomic.S,v 1.7 2007/12/10 14:13:12 ad Exp $	*/

/*-
 * Copyright (c) 2007 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe, and by Andrew Doran.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *      
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <machine/asm.h>

#ifdef _KERNEL
#define	LOCK(n)		.Lpatch/**/n:	lock
#define	ALIAS(f, t)	STRONG_ALIAS(f,t)
#define	END(a)		_ALIGN_TEXT; LABEL(a)
#else
#define	LOCK(n)		lock
#define	ALIAS(f, t)	WEAK_ALIAS(f,t)
#define	END(a)		/* nothing */
#endif

	.text

/* 32-bit */

NENTRY(_atomic_add_32)
	LOCK(1)
	addl	%esi, (%rdi)
	ret

NENTRY(_atomic_add_32_nv)
	movl	%esi, %eax
	LOCK(2)
	xaddl	%eax, (%rdi)
	addl	%esi, %eax
	ret

NENTRY(_atomic_and_32)
	LOCK(3)
	andl	%esi, (%rdi)
	ret

NENTRY(_atomic_and_32_nv)
	movl	(%rdi), %eax
1:
	movl	%eax, %ecx
	andl	%esi, %ecx
	LOCK(4)
	cmpxchgl %ecx, (%rdi)
	jnz	1b
	movl	%ecx, %eax
	ret

NENTRY(_atomic_dec_32)
	LOCK(5)
	decl	(%rdi)
	ret

NENTRY(_atomic_dec_32_nv)
	movl	$-1, %eax
	LOCK(6)
	xaddl	%eax, (%rdi)
	decl	%eax
	ret

NENTRY(_atomic_inc_32)
	LOCK(7)
	incl	(%rdi)
	ret

NENTRY(_atomic_inc_32_nv)
	movl	$1, %eax
	LOCK(8)
	xaddl	%eax, (%rdi)
	incl	%eax
	ret

NENTRY(_atomic_or_32)
	LOCK(9)
	orl	%esi, (%rdi)
	ret

NENTRY(_atomic_or_32_nv)
	movl	(%rdi), %eax
1:
	movl	%eax, %ecx
	orl	%esi, %ecx
	LOCK(10)
	cmpxchgl %ecx, (%rdi)
	jnz	1b
	movl	%ecx, %eax
	ret

NENTRY(_atomic_swap_32)
	movl	%esi, %eax
	xchgl	%eax, (%rdi)
	ret

NENTRY(_atomic_cas_32)
	movl	%esi, %eax
	LOCK(12)
	cmpxchgl %edx, (%rdi)
	/* %eax now contains the old value */
	ret

/* 64-bit */

NENTRY(_atomic_add_64)
	LOCK(13)
	addq	%rsi, (%rdi)
	ret

NENTRY(_atomic_add_64_nv)
	movq	%rsi, %rax
	LOCK(14)
	xaddq	%rax, (%rdi)
	addq	%rsi, %rax
	ret

NENTRY(_atomic_and_64)
	LOCK(15)
	andq	%rsi, (%rdi)
	ret

NENTRY(_atomic_and_64_nv)
	movq	(%rdi), %rax
1:
	movq	%rax, %rcx
	andq	%rsi, %rcx
	LOCK(16)
	cmpxchgq %rcx, (%rdi)
	jnz	1b
	movq	%rcx, %rax
	ret

NENTRY(_atomic_dec_64)
	LOCK(17)
	decq	(%rdi)
	ret

NENTRY(_atomic_dec_64_nv)
	movq	$-1, %rax
	LOCK(18)
	xaddq	%rax, (%rdi)
	decq	%rax
	ret

NENTRY(_atomic_inc_64)
	LOCK(19)
	incq	(%rdi)
	ret

NENTRY(_atomic_inc_64_nv)
	movq	$1, %rax
	LOCK(20)
	xaddq	%rax, (%rdi)
	incq	%rax
	ret

NENTRY(_atomic_or_64)
	LOCK(21)
	orq	%rsi, (%rdi)
	ret

NENTRY(_atomic_or_64_nv)
	movq	(%rdi), %rax
1:
	movq	%rax, %rcx
	orq	%rsi, %rcx
	LOCK(22)
	cmpxchgq %rcx, (%rdi)
	jnz	1b
	movq	%rcx, %rax
	ret

NENTRY(_atomic_swap_64)
	movq	%rsi, %rax
	xchgq	%rax, (%rdi)
	ret

NENTRY(_atomic_cas_64)
	movq	%rsi, %rax
	LOCK(24)
	cmpxchgq %rdx, (%rdi)
	/* %eax now contains the old value */
	ret

/* memory barriers */

NENTRY(_membar_consumer)
	LOCK(25)
	addq	$0, -8(%rsp)
	ret
END(membar_consumer_end)

NENTRY(_membar_producer)
	/* A store is enough */
	movq	$0, -8(%rsp)
	ret
END(membar_producer_end)

NENTRY(_membar_enter)
	/* A store is enough */
	movq	$0, -8(%rsp)
	ret
END(membar_enter_end)

NENTRY(_membar_exit)
	/* A store is enough */
	movq	$0, -8(%rsp)
	ret
END(membar_exit_end)

NENTRY(_membar_sync)
	LOCK(26)
	addq	$0, -8(%rsp)
	ret
END(membar_sync_end)

#ifdef _KERNEL
NENTRY(sse2_lfence)
	lfence
	ret
END(sse2_lfence_end)

NENTRY(sse2_mfence)
	mfence
	ret
END(sse2_mfence_end)

atomic_lockpatch:
	.globl	atomic_lockpatch
	.quad	.Lpatch1, .Lpatch2, .Lpatch3, .Lpatch4, .Lpatch5
	.quad	.Lpatch6, .Lpatch7, .Lpatch8, .Lpatch9, .Lpatch10
	.quad	.Lpatch12, .Lpatch13, .Lpatch14, .Lpatch15
	.quad	.Lpatch16, .Lpatch17, .Lpatch18, .Lpatch19, .Lpatch20
	.quad	.Lpatch21, .Lpatch22, .Lpatch24, .Lpatch25
	.quad	.Lpatch26, 0
#endif	/* _KERNEL */

ALIAS(atomic_add_32,_atomic_add_32)
ALIAS(atomic_add_64,_atomic_add_64)
ALIAS(atomic_add_int,_atomic_add_32)
ALIAS(atomic_add_long,_atomic_add_64)
ALIAS(atomic_add_ptr,_atomic_add_64)

ALIAS(atomic_add_32_nv,_atomic_add_32_nv)
ALIAS(atomic_add_64_nv,_atomic_add_64_nv)
ALIAS(atomic_add_int_nv,_atomic_add_32_nv)
ALIAS(atomic_add_long_nv,_atomic_add_64_nv)
ALIAS(atomic_add_ptr_nv,_atomic_add_64_nv)

ALIAS(atomic_and_32,_atomic_and_32)
ALIAS(atomic_and_64,_atomic_and_64)
ALIAS(atomic_and_uint,_atomic_and_32)
ALIAS(atomic_and_ulong,_atomic_and_64)
ALIAS(atomic_and_ptr,_atomic_and_64)

ALIAS(atomic_and_32_nv,_atomic_and_32_nv)
ALIAS(atomic_and_64_nv,_atomic_and_64_nv)
ALIAS(atomic_and_uint_nv,_atomic_and_32_nv)
ALIAS(atomic_and_ulong_nv,_atomic_and_64_nv)
ALIAS(atomic_and_ptr_nv,_atomic_and_64_nv)

ALIAS(atomic_dec_32,_atomic_dec_32)
ALIAS(atomic_dec_64,_atomic_dec_64)
ALIAS(atomic_dec_uint,_atomic_dec_32)
ALIAS(atomic_dec_ulong,_atomic_dec_64)
ALIAS(atomic_dec_ptr,_atomic_dec_64)

ALIAS(atomic_dec_32_nv,_atomic_dec_32_nv)
ALIAS(atomic_dec_64_nv,_atomic_dec_64_nv)
ALIAS(atomic_dec_uint_nv,_atomic_dec_32_nv)
ALIAS(atomic_dec_ulong_nv,_atomic_dec_64_nv)
ALIAS(atomic_dec_ptr_nv,_atomic_dec_64_nv)

ALIAS(atomic_inc_32,_atomic_inc_32)
ALIAS(atomic_inc_64,_atomic_inc_64)
ALIAS(atomic_inc_uint,_atomic_inc_32)
ALIAS(atomic_inc_ulong,_atomic_inc_64)
ALIAS(atomic_inc_ptr,_atomic_inc_64)

ALIAS(atomic_inc_32_nv,_atomic_inc_32_nv)
ALIAS(atomic_inc_64_nv,_atomic_inc_64_nv)
ALIAS(atomic_inc_uint_nv,_atomic_inc_32_nv)
ALIAS(atomic_inc_ulong_nv,_atomic_inc_64_nv)
ALIAS(atomic_inc_ptr_nv,_atomic_inc_64_nv)

ALIAS(atomic_or_32,_atomic_or_32)
ALIAS(atomic_or_uint,_atomic_or_32)
ALIAS(atomic_or_ulong,_atomic_or_64)
ALIAS(atomic_or_ptr,_atomic_or_64)

ALIAS(atomic_or_32_nv,_atomic_or_32_nv)
ALIAS(atomic_or_64_nv,_atomic_or_64_nv)
ALIAS(atomic_or_uint_nv,_atomic_or_32_nv)
ALIAS(atomic_or_ulong_nv,_atomic_or_64_nv)
ALIAS(atomic_or_ptr_nv,_atomic_or_64_nv)

ALIAS(atomic_swap_32,_atomic_swap_32)
ALIAS(atomic_swap_64,_atomic_swap_64)
ALIAS(atomic_swap_uint,_atomic_swap_32)
ALIAS(atomic_swap_ulong,_atomic_swap_64)
ALIAS(atomic_swap_ptr,_atomic_swap_64)

ALIAS(atomic_cas_32,_atomic_cas_32)
ALIAS(atomic_cas_64,_atomic_cas_64)
ALIAS(atomic_cas_uint,_atomic_cas_32)
ALIAS(atomic_cas_ulong,_atomic_cas_64)
ALIAS(atomic_cas_ptr,_atomic_cas_64)

ALIAS(membar_consumer,_membar_consumer)
ALIAS(membar_producer,_membar_producer)
ALIAS(membar_enter,_membar_enter)
ALIAS(membar_exit,_membar_exit)
ALIAS(membar_sync,_membar_sync)

STRONG_ALIAS(_atomic_add_int,_atomic_add_32)
STRONG_ALIAS(_atomic_add_long,_atomic_add_64)
STRONG_ALIAS(_atomic_add_ptr,_atomic_add_64)

STRONG_ALIAS(_atomic_add_int_nv,_atomic_add_32_nv)
STRONG_ALIAS(_atomic_add_long_nv,_atomic_add_64_nv)
STRONG_ALIAS(_atomic_add_ptr_nv,_atomic_add_64_nv)

STRONG_ALIAS(_atomic_and_uint,_atomic_and_32)
STRONG_ALIAS(_atomic_and_ulong,_atomic_and_64)
STRONG_ALIAS(_atomic_and_ptr,_atomic_and_64)

STRONG_ALIAS(_atomic_and_uint_nv,_atomic_and_32_nv)
STRONG_ALIAS(_atomic_and_ulong_nv,_atomic_and_64_nv)
STRONG_ALIAS(_atomic_and_ptr_nv,_atomic_and_64_nv)

STRONG_ALIAS(_atomic_dec_uint,_atomic_dec_32)
STRONG_ALIAS(_atomic_dec_ulong,_atomic_dec_64)
STRONG_ALIAS(_atomic_dec_ptr,_atomic_dec_64)

STRONG_ALIAS(_atomic_dec_uint_nv,_atomic_dec_32_nv)
STRONG_ALIAS(_atomic_dec_ulong_nv,_atomic_dec_64_nv)
STRONG_ALIAS(_atomic_dec_ptr_nv,_atomic_dec_64_nv)

STRONG_ALIAS(_atomic_inc_uint,_atomic_inc_32)
STRONG_ALIAS(_atomic_inc_ulong,_atomic_inc_64)
STRONG_ALIAS(_atomic_inc_ptr,_atomic_inc_64)

STRONG_ALIAS(_atomic_inc_uint_nv,_atomic_inc_32_nv)
STRONG_ALIAS(_atomic_inc_ulong_nv,_atomic_inc_64_nv)
STRONG_ALIAS(_atomic_inc_ptr_nv,_atomic_inc_64_nv)

STRONG_ALIAS(_atomic_or_uint,_atomic_or_32)
STRONG_ALIAS(_atomic_or_ulong,_atomic_or_64)
STRONG_ALIAS(_atomic_or_ptr,_atomic_or_64)

STRONG_ALIAS(_atomic_or_uint_nv,_atomic_or_32_nv)
STRONG_ALIAS(_atomic_or_ulong_nv,_atomic_or_64_nv)
STRONG_ALIAS(_atomic_or_ptr_nv,_atomic_or_64_nv)

STRONG_ALIAS(_atomic_swap_uint,_atomic_swap_32)
STRONG_ALIAS(_atomic_swap_ulong,_atomic_swap_64)
STRONG_ALIAS(_atomic_swap_ptr,_atomic_swap_64)

STRONG_ALIAS(_atomic_cas_uint,_atomic_cas_32)
STRONG_ALIAS(_atomic_cas_ulong,_atomic_cas_64)
STRONG_ALIAS(_atomic_cas_ptr,_atomic_cas_64)
