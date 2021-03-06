/*	$NetBSD: smscvar.h,v 1.1 2007/06/01 14:11:59 blymn Exp $ */

/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Bill Squier.
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
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

#ifndef _DEV_SMSC47B397VAR_H_
#define _DEV_SMSC47B397VAR_H_

/*
 * SMSC LPC47B397-NC "super-io" chip
 */

#define SMSC_ADDR		0
#define SMSC_DATA		1

/* Chip control registers */

#define SMSC_LOGICAL_DEV_SEL	0x07	/* Selector for logical device */
#define SMSC_DEVICE_ID		0X20	/* Device ID register */
#define SMSC_DEVICE_REVISION	0X21	/* Device revision */
#define SMSC_IO_BASE_MSB	0x60
#define SMSC_IO_BASE_LSB	0x61


#define SMSC_LOGICAL_DEVICE	0x08	/* Magic number to select monitoring
					   functions. */
#define SMSC_CONFIG_START	0x55	/* Start configuration mode */
#define SMSC_CONFIG_END		0xAA	/* End configuration mode */

#define SMSC_ID	0x6F	/* Chip Reset/ID */

/* Data registers */
#define SMSC_TEMP1		0x25
#define SMSC_TEMP2		0x26
#define SMSC_TEMP3		0x27
#define SMSC_TEMP4		0x80

/* NOTE: Reading the Fan LSB locks the Fan MSB. The LSB Must be read first. */
#define SMSC_FAN1_LSB		0x28
#define SMSC_FAN1_MSB		0x29
#define SMSC_FAN2_LSB		0x2A
#define SMSC_FAN2_MSB		0x2B
#define SMSC_FAN3_LSB		0x2C
#define SMSC_FAN3_MSB		0x2D
#define SMSC_FAN4_LSB		0x2E
#define SMSC_FAN4_MSB		0x2F

#define SMSC_MAX_SENSORS	0x08	/* 4 temp sensors, 4 fan sensors */

struct smsc_softc {
	struct	device sc_dev;

	bus_space_tag_t	smsc_iot;
	bus_space_handle_t smsc_ioh;

	int	sc_flags;
	struct sysmon_envsys *smsc_sysmon;
	uint8_t numsensors;

	uint8_t regs[SMSC_MAX_SENSORS];
};

#endif /* _DEV_SMSC47B397VAR_H_ */
