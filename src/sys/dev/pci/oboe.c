/*	$NetBSD: oboe.c,v 1.18 2005/02/27 00:27:33 perry Exp $	*/

/*	XXXXFVDL THIS DRIVER IS BROKEN FOR NON-i386 -- vtophys() usage	*/

/*-
 * Copyright (c) 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jan Sparud.
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

/*
 * Toshiba OBOE IrDA SIR/FIR driver.
 *
 * Based on information from the Linux driver, thus the magic hex numbers.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: oboe.c,v 1.18 2005/02/27 00:27:33 perry Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/tty.h>
#include <sys/vnode.h>
#include <sys/poll.h>

#include <dev/ir/ir.h>
#include <dev/ir/irdaio.h>
#include <dev/ir/irframevar.h>
#include <dev/ir/sir.h>

#include <dev/pci/pcidevs.h>
#include <dev/pci/pcivar.h>

#include <machine/bus.h>
#include <machine/intr.h>
#include <uvm/uvm_extern.h>

#include <dev/pci/oboereg.h>

int oboe_match(struct device *parent, struct cfdata *match, void *aux);
void oboe_attach(struct device *parent, struct device *self, void *aux);
int oboe_activate(struct device *self, enum devact act);
int oboe_detach(struct device *self, int flags);

int oboe_open(void *h, int flag, int mode, struct proc *p);
int oboe_close(void *h, int flag, int mode, struct proc *p);
int oboe_read(void *h, struct uio *uio, int flag);
int oboe_write(void *h, struct uio *uio, int flag);
int oboe_set_params(void *h, struct irda_params *params);
int oboe_get_speeds(void *h, int *speeds);
int oboe_get_turnarounds(void *h, int *times);
int oboe_poll(void *h, int events, struct proc *p);
int oboe_kqfilter(void *h, struct knote *kn);

#ifdef OBOE_DEBUG
#define DPRINTF(x)	if (oboedebug) printf x
int oboedebug = 1;
#else
#define DPRINTF(x)
#endif

struct oboe_dma;

struct oboe_softc {
	struct device		sc_dev;
	struct device		*sc_child;
	struct pci_attach_args	sc_pa;
	pci_intr_handle_t *	sc_ih;
	unsigned int		sc_revision;	/* PCI Revision ID */
	/* I/O Base device */
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;
	bus_dma_tag_t		sc_dmatag;
	struct selinfo		sc_rsel;
	struct selinfo		sc_wsel;

	int			sc_state;
#define	OBOE_RSLP		0x01	/* waiting for data (read) */
#define	OBOE_WSLP		0x02	/* waiting for data (write) */
#define OBOE_CLOSING		0x04	/* waiting for output to drain */

	int			sc_speeds;
	int			sc_flags;
	int			sc_speed;
	int			sc_ebofs;

	struct oboe_dma		*sc_dmas;
	struct OboeTaskFile	*sc_taskfile;    /* The taskfile   */
	u_char *		sc_xmit_bufs[TX_SLOTS];
	u_char *		sc_recv_bufs[RX_SLOTS];
	void *			sc_xmit_stores[TX_SLOTS];
	void *			sc_recv_stores[RX_SLOTS];
	int			sc_txs; /* Current transmit slot number */
	int			sc_rxs; /* Current receive slot number */
	int			sc_saved; /* number of saved frames */
	int			sc_lens[RX_SLOTS];

	int			sc_txpending;

	/* Statistics */
	int			sc_txpackets;
	int			sc_rxpackets;
	int			sc_txerrors;
	int			sc_rxerrors;
};

static int oboe_intr(void *handle);
static int oboe_reset(struct oboe_softc *);

struct oboe_dma {
	bus_dmamap_t map;
	caddr_t addr;
	bus_dma_segment_t segs[1];
	int nsegs;
	size_t size;
	struct oboe_dma *next;
};

#define DMAADDR(p) ((p)->map->dm_segs[0].ds_addr)
#define KERNADDR(p) ((void *)((p)->addr))

static int oboe_alloc_taskfile(struct oboe_softc *);
static void oboe_init_taskfile(struct oboe_softc *);
static void oboe_startchip(struct oboe_softc *);
static void oboe_stopchip(struct oboe_softc *);
static int oboe_setbaud(struct oboe_softc *, int);

CFATTACH_DECL(oboe, sizeof(struct oboe_softc),
    oboe_match, oboe_attach, oboe_detach, oboe_activate);

struct irframe_methods oboe_methods = {
	oboe_open, oboe_close, oboe_read, oboe_write, oboe_poll,
	oboe_kqfilter, oboe_set_params, oboe_get_speeds, oboe_get_turnarounds
};

int
oboe_match(struct device *parent, struct cfdata *match, void *aux)
{
	struct pci_attach_args *pa = aux;

	if (PCI_VENDOR(pa->pa_id) == PCI_VENDOR_TOSHIBA2 &&
	    (PCI_PRODUCT(pa->pa_id) == PCI_PRODUCT_TOSHIBA2_OBOE ||
	     PCI_PRODUCT(pa->pa_id) == PCI_PRODUCT_TOSHIBA2_DONAUOBOE))
		return (1);
	return 0;
}

void
oboe_attach(struct device *parent, struct device *self, void *aux)
{
	struct oboe_softc *sc = (struct oboe_softc *)self;
	struct pci_attach_args *pa = aux;
	pci_intr_handle_t ih;
	struct ir_attach_args ia;
	const char *intrstring;

	sc->sc_revision = PCI_REVISION(pa->pa_class);
	printf(": Toshiba Fast Infrared Type O, revision %d\n",
	       sc->sc_revision);

	/* Map I/O registers. */
	if (pci_mapreg_map(pa, IO_BAR, PCI_MAPREG_TYPE_IO, 0,
	    &sc->sc_iot, &sc->sc_ioh, NULL, NULL)) {
		printf("%s: can't map I/O space\n", sc->sc_dev.dv_xname);
		return;
	}

	sc->sc_dmatag = pa->pa_dmat;

	ia.ia_type = IR_TYPE_IRFRAME;
	ia.ia_methods = &oboe_methods;
	ia.ia_handle = sc;

	sc->sc_state = 0;
	sc->sc_speed = IRDA_SPEED_9600;

	/* Enable the device */
	pci_conf_write(pa->pa_pc, pa->pa_tag, PCI_COMMAND_STATUS_REG,
	    pci_conf_read(pa->pa_pc, pa->pa_tag, PCI_COMMAND_STATUS_REG) |
	    PCI_COMMAND_MASTER_ENABLE);

	/* Reset the device; bail out upon failure. */
	if (oboe_reset(sc) != 0) {
		printf("%s: can't reset\n", sc->sc_dev.dv_xname);
		return;
	}
	/* Map and establish the interrupt. */
	if (pci_intr_map(pa, &ih)) {
		printf("%s: couldn't map interrupt\n", sc->sc_dev.dv_xname);
		return;
	}
	intrstring = pci_intr_string(pa->pa_pc, ih);
	sc->sc_ih  = pci_intr_establish(pa->pa_pc, ih, IPL_IR, oboe_intr, sc);
	if (sc->sc_ih == NULL) {
		printf("%s: couldn't establish interrupt",
		    sc->sc_dev.dv_xname);
		if (intrstring != NULL)
			printf(" at %s", intrstring);
		printf("\n");
		return;
	}
	printf("%s: interrupting at %s\n", sc->sc_dev.dv_xname, intrstring);

	sc->sc_txs = 0;
	sc->sc_rxs = 0;

	sc->sc_speeds =
		IRDA_SPEED_2400   | IRDA_SPEED_9600    | IRDA_SPEED_19200 |
		IRDA_SPEED_38400  | IRDA_SPEED_57600   | IRDA_SPEED_115200 |
		IRDA_SPEED_576000 | IRDA_SPEED_1152000 | IRDA_SPEED_4000000;

	oboe_alloc_taskfile(sc);

	sc->sc_child = config_found((void *)sc, &ia, ir_print);
}

int
oboe_activate(struct device *self, enum devact act)
{
	struct oboe_softc *sc = (struct oboe_softc *)self;
	int error = 0;

	DPRINTF(("%s: sc=%p\n", __FUNCTION__, sc));

	switch (act) {
	case DVACT_ACTIVATE:
		return (EOPNOTSUPP);
		break;

	case DVACT_DEACTIVATE:
		if (sc->sc_child != NULL)
			error = config_deactivate(sc->sc_child);
		break;
	}
	return (error);
}

int
oboe_detach(struct device *self, int flags)
{
#if 0
	struct oboe_softc *sc = (struct oboe_softc *)self;
#endif
	/* XXX needs reference counting for proper detach. */
	DPRINTF(("%s: sc=%p\n", __FUNCTION__, sc));
	return (0);
}

int
oboe_open(void *h, int flag, int mode, struct proc *p)
{
	struct oboe_softc *sc = h;

	DPRINTF(("%s: sc=%p\n", __FUNCTION__, sc));

	sc->sc_state = 0;
	sc->sc_saved = 0;
	oboe_init_taskfile(sc);
	oboe_startchip(sc);

	return (0);
}

int
oboe_close(void *h, int flag, int mode, struct proc *p)
{
	struct oboe_softc *sc = h;
	int error = 0;
	int s = splir();

	DPRINTF(("%s: sc=%p\n", __FUNCTION__, sc));
	/* Wait for output to drain */

	if (sc->sc_txpending > 0) {
		sc->sc_state |= OBOE_CLOSING;
		error = tsleep(&sc->sc_state, PZERO | PCATCH, "oboecl", hz/10);
	}
	splx(s);

	oboe_stopchip(sc);
	return (error);
}

int
oboe_read(void *h, struct uio *uio, int flag)
{
	struct oboe_softc *sc = h;
	int error = 0;
	int s;
	int slot;

	DPRINTF(("%s: resid=%d, iovcnt=%d, offset=%ld\n",
		 __FUNCTION__, uio->uio_resid, uio->uio_iovcnt,
		 (long)uio->uio_offset));

	s = splir();
	while (sc->sc_saved == 0) {
		if (flag & IO_NDELAY) {
			splx(s);
			return (EWOULDBLOCK);
		}
		sc->sc_state |= OBOE_RSLP;
		DPRINTF(("oboe_read: sleep\n"));
		error = tsleep(&sc->sc_rxs, PZERO | PCATCH, "oboerd", 0);
		DPRINTF(("oboe_read: woke, error=%d\n", error));
		if (error) {
			sc->sc_state &= ~OBOE_RSLP;
			break;
		}
	}

	/* Do just one frame transfer per read */

	if (!error) {
		slot = (sc->sc_rxs - sc->sc_saved + RX_SLOTS) % RX_SLOTS;
		if (uio->uio_resid < sc->sc_lens[slot]) {
			DPRINTF(("oboe_read: uio buffer smaller than frame size"
			    "(%d < %d)\n", uio->uio_resid, sc->sc_lens[slot]));
			error = EINVAL;
		} else {
			DPRINTF(("oboe_read: moving %d bytes from %p\n",
				 sc->sc_lens[slot],
				 sc->sc_recv_stores[slot]));
			error = uiomove(sc->sc_recv_stores[slot],
					sc->sc_lens[slot], uio);
		}
	}
	sc->sc_saved--;
	splx(s);

	return (error);
}

int
oboe_write(void *h, struct uio *uio, int flag)
{
	struct oboe_softc *sc = h;
	int error = 0;
	int n;
	int s = splir();

	DPRINTF(("%s: sc=%p\n", __FUNCTION__, sc));
	while (sc->sc_txpending == TX_SLOTS) {
		if (flag & IO_NDELAY) {
			splx(s);
			return (EWOULDBLOCK);
		}
		sc->sc_state |= OBOE_WSLP;
		DPRINTF(("oboe_write: sleep\n"));
		error = tsleep(&sc->sc_txs, PZERO | PCATCH, "oboewr", 0);
		DPRINTF(("oboe_write: woke up, error=%d\n", error));
		if (error) {
			sc->sc_state &= ~OBOE_WSLP;
			break;
		}
	}
	if (error)
		goto err;
	if (sc->sc_taskfile->xmit[sc->sc_txs].control) {
		DPRINTF(("oboe_write: slot overrun\n"));
	}

	n = irda_sir_frame(sc->sc_xmit_bufs[sc->sc_txs], TX_BUF_SZ, uio,
			   sc->sc_ebofs);
	if (n < 0) {
		error = -n;
		goto err;
	}
	sc->sc_taskfile->xmit[sc->sc_txs].len = n;

	OUTB(sc, 0, OBOE_RST);
	OUTB(sc, 0x1e, OBOE_REG_11);

	sc->sc_taskfile->xmit[sc->sc_txs].control = 0x84;

	/* XXX Need delay here??? */
	delay(1000);

	sc->sc_txpending++;
	OUTB(sc, 0x80, OBOE_RST);
	OUTB(sc, 1, OBOE_REG_9);
	sc->sc_txs++;
	sc->sc_txs %= TX_SLOTS;

 err:
	splx(s);
	return (error);
}

int
oboe_set_params(void *h, struct irda_params *p)
{
	struct oboe_softc *sc = h;
	int error;

	if (p->speed > 0) {
		error = oboe_setbaud(sc, p->speed);
		if (error)
			return (error);
	}
	sc->sc_ebofs = p->ebofs;

	/* XXX ignore ebofs and maxsize for now */
	return (0);
}

int
oboe_get_speeds(void *h, int *speeds)
{
	struct oboe_softc *sc = h;
	*speeds = sc->sc_speeds;
	return (0);
}

int
oboe_get_turnarounds(void *h, int *turnarounds)
{
#if 0
	struct oboe_softc *sc = h;
#endif
	DPRINTF(("%s: sc=%p\n", __FUNCTION__, sc));
	/* XXX Linux driver sets all bits */
	*turnarounds = IRDA_TURNT_10000; /* 10ms */
	return (0);
}

int
oboe_poll(void *h, int events, struct proc *p)
{
	struct oboe_softc *sc = h;
	int revents = 0;
	int s;

	DPRINTF(("%s: sc=%p\n", __FUNCTION__, sc));

	s = splir();
	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLOUT | POLLWRNORM);
	if (events & (POLLIN | POLLRDNORM)) {
		if (sc->sc_saved > 0) {
			DPRINTF(("%s: have data\n", __FUNCTION__));
			revents |= events & (POLLIN | POLLRDNORM);
		} else {
			DPRINTF(("%s: recording select\n", __FUNCTION__));
			selrecord(p, &sc->sc_rsel);
		}
	}
	splx(s);

	return (revents);
}

static void
filt_oboerdetach(struct knote *kn)
{
	struct oboe_softc *sc = kn->kn_hook;
	int s;

	s = splir();
	SLIST_REMOVE(&sc->sc_rsel.sel_klist, kn, knote, kn_selnext);
	splx(s);
}

static int
filt_oboeread(struct knote *kn, long hint)
{
	struct oboe_softc *sc = kn->kn_hook;

	kn->kn_data = sc->sc_saved;
	return (kn->kn_data > 0);
}

static void
filt_oboewdetach(struct knote *kn)
{
	struct oboe_softc *sc = kn->kn_hook;
	int s;

	s = splir();
	SLIST_REMOVE(&sc->sc_wsel.sel_klist, kn, knote, kn_selnext);
	splx(s);
}

static const struct filterops oboeread_filtops =
	{ 1, NULL, filt_oboerdetach, filt_oboeread };
static const struct filterops oboewrite_filtops =
	{ 1, NULL, filt_oboewdetach, filt_seltrue };

int
oboe_kqfilter(void *h, struct knote *kn)
{
	struct oboe_softc *sc = h;
	struct klist *klist;
	int s;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		klist = &sc->sc_rsel.sel_klist;
		kn->kn_fop = &oboeread_filtops;
		break;
	case EVFILT_WRITE:
		klist = &sc->sc_wsel.sel_klist;
		kn->kn_fop = &oboewrite_filtops;
		break;
	default:
		return (1);
	}

	kn->kn_hook = sc;

	s = splir();
	SLIST_INSERT_HEAD(klist, kn, kn_selnext);
	splx(s);

	return (0);
}

static int
oboe_reset(struct oboe_softc *sc)
{
#if 0
	OUTB(sc, 0x00, OBOE_RST);
	OUTB(sc, 0x80, OBOE_RST);
#endif
	return 0;
}

static int
oboe_intr(void *p)
{
	struct oboe_softc *sc = p;
	uint8_t irqstat	= INB(sc, OBOE_ISR);

	if (!(irqstat & 0xf8))
		return (0); /* Not for me? */

	DPRINTF(("oboe_intr stat=0x%x\n", irqstat));

	OUTB(sc, irqstat, OBOE_ISR);

	if (irqstat & OBOE_ISR_RXDONE) {
		while (sc->sc_taskfile->recv[sc->sc_rxs].control == 0) {
			int len = sc->sc_taskfile->recv[sc->sc_rxs].len;
			if (sc->sc_saved == RX_SLOTS) {
				DPRINTF(("oboe_intr: all buffers filled\n"));
				return 0;
			}

			if (len > 2)
				len -= 2; /* JSP: skip check sum? */

			DPRINTF(("oboe_intr: moving %d bytes to %p\n", len,
				 sc->sc_recv_stores[sc->sc_rxs]));
			memcpy(sc->sc_recv_stores[sc->sc_rxs],
			       sc->sc_recv_bufs[sc->sc_rxs],
			       len);
			sc->sc_lens[sc->sc_rxs] = len;
			sc->sc_saved++;
#if 0
			(void)b_to_q(sc->sc_recv_bufs[sc->sc_rxs],
				     len, &sc->sc_q);
#endif
			sc->sc_taskfile->recv[sc->sc_rxs].control = 0x83;
			sc->sc_taskfile->recv[sc->sc_rxs].len = 0x0;
			sc->sc_rxs = (sc->sc_rxs + 1) % RX_SLOTS;
			DPRINTF(("oboe_intr new rxs=%d\n", sc->sc_rxs));
		}
		DPRINTF(("oboe_intr no more frames available\n"));
		if (sc->sc_state & OBOE_RSLP) {
			DPRINTF(("oboe_intr changing state to ~OBOE_RSLP\n"));
			sc->sc_state &= ~OBOE_RSLP;
			DPRINTF(("oboe_intr: waking up reader\n"));
			wakeup(&sc->sc_rxs);
		}
		selnotify(&sc->sc_rsel, 0);
		DPRINTF(("oboe_intr returning\n"));
	}
	if (irqstat & OBOE_ISR_TXDONE) {
	        DPRINTF(("oboe_intr: write done\n"));
		sc->sc_txpending--;
		sc->sc_txpackets++;

		if ((sc->sc_state & OBOE_CLOSING) && sc->sc_txpending == 0) {
			wakeup(&sc->sc_state);
			return 1;
		}

		if (sc->sc_state & OBOE_WSLP) {
			DPRINTF(("oboe_intr changing state to ~OBOE_WSLP\n"));
			sc->sc_state &= ~OBOE_WSLP;
			DPRINTF(("oboe_intr: waking up writer\n"));
			wakeup(&sc->sc_txs);
		}
		selnotify(&sc->sc_wsel, 0);
	}
	return (1);
}

/* XXX vtophys must go! */
static void
oboe_init_taskfile(struct oboe_softc *sc)
{
	int i;
	int s = splir();

	for (i = 0; i < TX_SLOTS; ++i) {
		sc->sc_taskfile->xmit[i].len = 0;
		sc->sc_taskfile->xmit[i].control = 0x00;
		sc->sc_taskfile->xmit[i].buffer =
			vtophys((u_int)sc->sc_xmit_bufs[i]); /* u_int? */
	}

	for (i = 0; i < RX_SLOTS; ++i) {
		sc->sc_taskfile->recv[i].len = 0;
		sc->sc_taskfile->recv[i].control = 0x83;
		sc->sc_taskfile->recv[i].buffer =
			vtophys((u_int)sc->sc_recv_bufs[i]); /* u_int? */
	}

	sc->sc_txpending = 0;

	splx(s);
}

static int
oboe_alloc_taskfile(struct oboe_softc *sc)
{
	int i;
	/* XXX */
	uint32_t addr = (uint32_t)malloc(OBOE_TASK_BUF_LEN, M_DEVBUF, M_WAITOK);
	if (addr == 0) {
		goto bad;
	}
	addr &= ~(sizeof (struct OboeTaskFile) - 1);
	addr += sizeof (struct OboeTaskFile);
	sc->sc_taskfile = (struct OboeTaskFile *) addr;

	for (i = 0; i < TX_SLOTS; ++i) {
		sc->sc_xmit_bufs[i] =
			malloc(TX_BUF_SZ, M_DEVBUF, M_WAITOK);
		sc->sc_xmit_stores[i] =
			malloc(TX_BUF_SZ, M_DEVBUF, M_WAITOK);
		if (sc->sc_xmit_bufs[i] == NULL ||
		    sc->sc_xmit_stores[i] == NULL) {
			goto bad;
		}
	}
	for (i = 0; i < RX_SLOTS; ++i) {
		sc->sc_recv_bufs[i] =
			malloc(RX_BUF_SZ, M_DEVBUF, M_WAITOK);
		sc->sc_recv_stores[i] =
			malloc(RX_BUF_SZ, M_DEVBUF, M_WAITOK);
		if (sc->sc_recv_bufs[i] == NULL ||
		    sc->sc_recv_stores[i] == NULL) {
			goto bad;
		}
	}

	return 0;
bad:
	printf("oboe: malloc for buffers failed()\n");
	return 1;
}

static void
oboe_startchip (struct oboe_softc *sc)
{
	uint32_t physaddr;

	OUTB(sc, 0, OBOE_LOCK);
	OUTB(sc, 0, OBOE_RST);
	OUTB(sc, OBOE_NTR_VAL, OBOE_NTR);
	OUTB(sc, 0xf0, OBOE_REG_D);
	OUTB(sc, 0xff, OBOE_ISR);
	OUTB(sc, 0x0f, OBOE_REG_1A);
	OUTB(sc, 0xff, OBOE_REG_1B);

	physaddr = vtophys((u_int)sc->sc_taskfile); /* u_int? */

	OUTB(sc, (physaddr >> 0x0a) & 0xff, OBOE_TFP0);
	OUTB(sc, (physaddr >> 0x12) & 0xff, OBOE_TFP1);
	OUTB(sc, (physaddr >> 0x1a) & 0x3f, OBOE_TFP2);

	OUTB(sc, 0x0e, OBOE_REG_11);
	OUTB(sc, 0x80, OBOE_RST);

	(void)oboe_setbaud(sc, 9600);

	sc->sc_rxs = INB(sc, OBOE_RCVT);
	if (sc->sc_rxs < 0 || sc->sc_rxs >= RX_SLOTS)
		sc->sc_rxs = 0;
	sc->sc_txs = INB(sc, OBOE_XMTT) - OBOE_XMTT_OFFSET;
	if (sc->sc_txs < 0 || sc->sc_txs >= TX_SLOTS)
		sc->sc_txs = 0;
}

static void
oboe_stopchip (struct oboe_softc *sc)
{
	OUTB(sc, 0x0e, OBOE_REG_11);
	OUTB(sc, 0x00, OBOE_RST);
	OUTB(sc, 0x3f, OBOE_TFP2);     /* Write the taskfile address */
	OUTB(sc, 0xff, OBOE_TFP1);
	OUTB(sc, 0xff, OBOE_TFP0);
	OUTB(sc, 0x0f, OBOE_REG_1B);
	OUTB(sc, 0xff, OBOE_REG_1A);
	OUTB(sc, 0x00, OBOE_ISR); /* XXX: should i do this to disable ints? */
	OUTB(sc, 0x80, OBOE_RST);
	OUTB(sc, 0x0e, OBOE_LOCK);
}

#define SPEEDCASE(speed, type, divisor) \
case speed: \
OUTB(sc, OBOE_PMDL_##type, OBOE_PMDL); \
OUTB(sc, OBOE_SMDL_##type, OBOE_SMDL); \
OUTB(sc, divisor, OBOE_UDIV); \
break

static int
oboe_setbaud(struct oboe_softc *sc, int baud)
{
	int s;

	DPRINTF(("oboe: setting baud to %d\n", baud));

	s = splir();

	switch (baud) {
	SPEEDCASE(   2400, SIR, 0xbf);
	SPEEDCASE(   9600, SIR, 0x2f);
	SPEEDCASE(  19200, SIR, 0x17);
	SPEEDCASE(  38400, SIR, 0x0b);
	SPEEDCASE(  57600, SIR, 0x07);
	SPEEDCASE( 115200, SIR, 0x03);
	SPEEDCASE(1152000, MIR, 0x01);
	SPEEDCASE(4000000, FIR, 0x00);
	default:
		DPRINTF(("oboe: cannot set speed to %d\n", baud));
		splx(s);
		return (EINVAL);
	}

	OUTB(sc, 0x00, OBOE_RST);
	OUTB(sc, 0x80, OBOE_RST);
	OUTB(sc, 0x01, OBOE_REG_9);

	sc->sc_speed = baud;

	splx(s);

	return (0);
}
