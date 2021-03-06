/*	$NetBSD: ffbvar.h,v 1.3.10.2 2005/06/07 18:03:48 tron Exp $	*/
/*	$OpenBSD: creatorvar.h,v 1.6 2002/07/30 19:48:15 jason Exp $	*/

/*
 * Copyright (c) 2002 Jason L. Wright (jason@thought.net),
 *  Federico G. Schwindt (fgsch@openbsd.org)
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Jason L. Wright
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define FFB_CREATOR		0
#define FFB_AFB			1

#define	FFB_CFFLAG_NOACCEL	0x1

struct ffb_softc {
	struct device sc_dv;
	struct fbdevice sc_fb;
	bus_space_tag_t sc_bt;
	bus_space_handle_t sc_pixel_h;
	bus_space_handle_t sc_dac_h;
	bus_space_handle_t sc_fbc_h;
	bus_addr_t sc_addrs[FFB_NREGS];
	bus_size_t sc_sizes[FFB_NREGS];
	int sc_height, sc_width, sc_linebytes, sc_depth;
	int sc_nscreens, sc_nreg;
	int sc_console;
	int sc_node;
	int sc_type;
	u_int sc_dacrev;
	u_int sc_mode;
	int sc_accel;
	int32_t sc_fifo_cache, sc_fg_cache;

	/* virtual console stuff */
	void (*putchar)(void *c, int row, int col, u_int uc, long attr);
	void (*copycols)(void *c, int row, int srccol, int dstcol, int ncols);
	void (*switchcb)(void *, int, int);
	void *switchcbarg;
	struct callout switch_callout;
	LIST_HEAD(, ffb_screen) screens;
	struct ffb_screen *active, *wanted;
	const struct wsscreen_descr *currenttype;
};

struct ffb_screen {
	struct rasops_info ri;
	LIST_ENTRY(ffb_screen) next;
	struct ffb_softc *sc;
	const struct wsscreen_descr *type;
	int active;
	u_int16_t *chars;
	long *attrs;

	int cursoron;
	int cursorcol;
	int cursorrow;
	int cursordrawn;
};

#define	DAC_WRITE(sc,r,v) \
    bus_space_write_4((sc)->sc_bt, (sc)->sc_dac_h, (r), (v))
#define	DAC_READ(sc,r) \
    bus_space_read_4((sc)->sc_bt, (sc)->sc_dac_h, (r))
#define	FBC_WRITE(sc,r,v) \
    bus_space_write_4((sc)->sc_bt, (sc)->sc_fbc_h, (r), (v))
#define	FBC_READ(sc,r) \
    bus_space_read_4((sc)->sc_bt, (sc)->sc_fbc_h, (r))

void	ffb_attach(struct ffb_softc *);
