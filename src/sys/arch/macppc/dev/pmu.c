/*	$NetBSD: pmu.c,v 1.2 2007/01/18 00:43:00 macallan Exp $ */

/*-
 * Copyright (c) 2006 Michael Lorenz
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
 * 3. Neither the name of The NetBSD Foundation nor the names of its
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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: pmu.c,v 1.2 2007/01/18 00:43:00 macallan Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/proc.h>
#include <sys/kthread.h>

#include <machine/bus.h>
#include <machine/autoconf.h>
#include <dev/clock_subr.h>
#include <dev/i2c/i2cvar.h>

#include <macppc/dev/viareg.h>
#include <macppc/dev/pmuvar.h>

#include <dev/ofw/openfirm.h>
#include <dev/adb/adbvar.h>
#include "opt_pmu.h"
#include "nadb.h"

#ifdef PMU_DEBUG
#define DPRINTF printf
#else
#define DPRINTF while (0) printf
#endif

#define PMU_NOTREADY	0x1	/* has not been initialized yet */
#define PMU_IDLE	0x2	/* the bus is currently idle */
#define PMU_OUT		0x3	/* sending out a command */
#define PMU_IN		0x4	/* receiving data */

static void pmu_attach(struct device *, struct device *, void *);
static int pmu_match(struct device *, struct cfdata *, void *);
static void pmu_autopoll(void *, int);

static int pmu_intr(void *);

struct pmu_softc {
	struct device sc_dev;
	void *sc_ih;
	struct todr_chip_handle sc_todr;
	struct adb_bus_accessops sc_adbops;
	struct i2c_controller sc_i2c;
	struct lock sc_buslock;
	bus_space_tag_t sc_memt;
	bus_space_handle_t sc_memh;
	uint32_t sc_flags;
#define PMU_HAS_BACKLIGHT_CONTROL	1
	int sc_node;
	int sc_iic_done;
	int sc_error;
	int sc_autopoll;
	int sc_pending_eject;
	int sc_brightness, sc_brightness_wanted;
	int sc_volume, sc_volume_wanted;
	/* deferred processing */
	struct proc *sc_thread;
	/* signalling the event thread */
	int sc_event;
	/* ADB */
	void (*sc_adb_handler)(void *, int, uint8_t *);
	void *sc_adb_cookie;
};

CFATTACH_DECL(pmu, sizeof(struct pmu_softc),
    pmu_match, pmu_attach, NULL, NULL);

static inline void pmu_write_reg(struct pmu_softc *, int, uint8_t);
static inline uint8_t pmu_read_reg(struct pmu_softc *, int);
static void pmu_in(struct pmu_softc *);
static void pmu_out(struct pmu_softc *);
static void pmu_ack_off(struct pmu_softc *);
static void pmu_ack_on(struct pmu_softc *);
static int pmu_intr_state(struct pmu_softc *);

static void pmu_init(struct pmu_softc *);
static void pmu_create_thread(void *);
static void pmu_thread(void *);
static void pmu_eject_card(struct pmu_softc *, int);
static void pmu_update_brightness(struct pmu_softc *);

/*
 * send a message to Cuda.
 */
/* cookie, flags, length, data */
static int pmu_send(struct pmu_softc *, int, int, uint8_t *, uint8_t *);
#if notyet
static void pmu_poll(void *);
#endif
static void pmu_adb_poll(void *);
#if notyet
static int pmu_error_handler(void *, int, uint8_t *);

static int pmu_todr_handler(void *, int, uint8_t *);
#endif
static int pmu_todr_set(todr_chip_handle_t, volatile struct timeval *);
static int pmu_todr_get(todr_chip_handle_t, volatile struct timeval *);

static int pmu_adb_handler(void *, int, uint8_t *);
static void pmu_final(struct device *);

static struct pmu_softc *pmu0 = NULL;

/* ADB bus attachment stuff */
static 	int pmu_adb_send(void *, int, int, int, uint8_t *);
static	int pmu_adb_set_handler(void *, void (*)(void *, int, uint8_t *), void *);

/* i2c stuff */
#if 0
static int pmu_i2c_acquire_bus(void *, int);
static void pmu_i2c_release_bus(void *, int);
static int pmu_i2c_exec(void *, i2c_op_t, i2c_addr_t, const void *, size_t,
		    void *, size_t, int);
#endif

/* these values shows that number of data returned after 'send' cmd is sent */
static signed char pm_send_cmd_type[] = {
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x01, 0x01,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00,   -1,   -1,   -1,   -1,   -1, 0x00,
	  -1, 0x00, 0x02, 0x01, 0x01,   -1,   -1,   -1,
	0x00,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x04, 0x14,   -1, 0x03,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x02, 0x02,   -1,   -1,   -1,   -1,
	0x01, 0x01,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00,   -1,   -1, 0x01,   -1,   -1,   -1,
	0x01, 0x00, 0x02, 0x02,   -1, 0x01, 0x03, 0x01,
	0x00, 0x01, 0x00, 0x00, 0x00,   -1,   -1,   -1,
	0x02,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   -1,   -1,
	0x01, 0x01, 0x01,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00,   -1,   -1,   -1,   -1, 0x04, 0x04,
	0x04,   -1, 0x00,   -1,   -1,   -1,   -1,   -1,
	0x00,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x01, 0x02,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00,   -1,   -1,   -1,   -1,   -1,   -1,
	0x02, 0x02, 0x02, 0x04,   -1, 0x00,   -1,   -1,
	0x01, 0x01, 0x03, 0x02,   -1,   -1,   -1,   -1,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x01, 0x01,   -1,   -1, 0x00, 0x00,   -1,   -1,
	  -1, 0x04, 0x00,   -1,   -1,   -1,   -1,   -1,
	0x03,   -1, 0x00,   -1, 0x00,   -1,   -1, 0x00,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1
};

/* these values shows that number of data returned after 'receive' cmd is sent */
static signed char pm_receive_cmd_type[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x02,   -1,   -1,   -1,   -1,   -1, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x05, 0x15,   -1, 0x02,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x02,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x03, 0x03,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x04, 0x03, 0x09,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  -1,   -1,   -1,   -1,   -1,   -1, 0x01, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x06,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x02,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x02,   -1,   -1, 0x02,   -1,   -1,   -1,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	  -1,   -1, 0x02,   -1,   -1,   -1,   -1, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
};

static int
pmu_match(struct device *parent, struct cfdata *cf, void *aux)
{
	struct confargs *ca = aux;

	if (ca->ca_nreg < 8)
		return 0;

	if (ca->ca_nintr < 4)
		return 0;

	if (strcmp(ca->ca_name, "via-pmu") == 0) {
		return 10;
	}
	
	return 0;
}

static void
pmu_attach(struct device *parent, struct device *dev, void *aux)
{
	struct confargs *ca = aux;
	struct pmu_softc *sc = (struct pmu_softc *)dev;
#if notyet
	struct i2cbus_attach_args iba;
#endif
	int irq = ca->ca_intr[0];
	int node, extint_node;
	uint8_t cmd[2] = {2, 0};
	uint8_t resp[8];
	char name[32];

	extint_node = getnodebyname(OF_parent(ca->ca_node), "extint-gpio1");
	if (extint_node)
		OF_getprop(extint_node, "interrupts", &irq, 4);

	printf(" irq %d: ", irq);

	sc->sc_node = ca->ca_node;
	sc->sc_memt = ca->ca_tag;

	sc->sc_error = 0;
	sc->sc_autopoll = 0;
	sc->sc_pending_eject = 0;
	sc->sc_brightness = sc->sc_brightness_wanted = 0x80;
	sc->sc_volume = sc->sc_volume_wanted = 0x80;
	sc->sc_flags = 0;

	if (bus_space_map(sc->sc_memt, ca->ca_reg[0] + ca->ca_baseaddr,
	    ca->ca_reg[1], 0, &sc->sc_memh) != 0) {

		printf("%s: unable to map registers\n", dev->dv_xname);
		return;
	}
	sc->sc_ih = intr_establish(irq, IST_LEVEL, IPL_HIGH, pmu_intr, sc);

	pmu_init(sc);

	if (pmu0 == NULL)
		pmu0 = sc;

	pmu_send(sc, PMU_SYSTEM_READY, 1, cmd, resp);

	/* check what kind of PMU we're talking to */
	if (pmu_send(sc, PMU_GET_VERSION, 0, cmd, resp) > 1)
		printf(" rev. %d", resp[1]);
	printf("\n");

	config_interrupts(dev, pmu_final);

	node = OF_child(ca->ca_node);
	while (node != 0) {

		if (OF_getprop(node, "name", name, 32) == 0)
			continue;
		if (strncmp(name, "adb", 4) == 0) {

			printf("%s: initializing ADB\n", sc->sc_dev.dv_xname);
			sc->sc_adbops.cookie = sc;
			sc->sc_adbops.send = pmu_adb_send;
			sc->sc_adbops.poll = pmu_adb_poll;
			sc->sc_adbops.autopoll = pmu_autopoll;
			sc->sc_adbops.set_handler = pmu_adb_set_handler;
#if NNADB > 0
			config_found_ia(dev, "adb_bus", &sc->sc_adbops,
			    nadb_print);
#endif
			goto next;
		}
		if (strncmp(name, "rtc", 4) == 0) {

			printf("%s: initializing RTC\n", sc->sc_dev.dv_xname);
			sc->sc_todr.todr_gettime = pmu_todr_get;
			sc->sc_todr.todr_settime = pmu_todr_set;
			sc->sc_todr.cookie = sc;
			todr_attach(&sc->sc_todr);
			goto next;
		}
		printf("%s: %s not configured\n", sc->sc_dev.dv_xname, name);
next:
		node = OF_peer(node);
	}

	if (OF_finddevice("/bandit/ohare") != -1) {
		printf("%s: enabling ohare backlight control\n",
		    device_xname(dev));
		sc->sc_flags |= PMU_HAS_BACKLIGHT_CONTROL;
	}

#if notyet
	iba.iba_tag = &sc->sc_i2c;
	sc->sc_i2c.ic_cookie = sc;
	sc->sc_i2c.ic_acquire_bus = pmu_i2c_acquire_bus;
	sc->sc_i2c.ic_release_bus = pmu_i2c_release_bus;
	sc->sc_i2c.ic_send_start = NULL;
	sc->sc_i2c.ic_send_stop = NULL;
	sc->sc_i2c.ic_initiate_xfer = NULL;
	sc->sc_i2c.ic_read_byte = NULL;
	sc->sc_i2c.ic_write_byte = NULL;
	sc->sc_i2c.ic_exec = pmu_i2c_exec;
	config_found_ia(&sc->sc_dev, "i2cbus", &iba, iicbus_print);
#endif
	kthread_create(pmu_create_thread, sc);
}

static void
pmu_init(struct pmu_softc *sc)
{
	uint8_t pmu_imask, resp[16];

	pmu_imask =
	    PMU_INT_PCEJECT | PMU_INT_SNDBRT | PMU_INT_ADB/* | PMU_INT_TICK*/;
	pmu_imask |= PMU_INT_BATTERY;
	pmu_imask |= PMU_INT_ENVIRONMENT;
	pmu_send(sc, PMU_SET_IMASK, 1, &pmu_imask, resp);

	pmu_write_reg(sc, vIER, 0x90);	/* enable VIA interrupts */
}

static void
pmu_final(struct device *dev)
{
	//struct pmu_softc *sc = (struct pmu_softc *)dev;

//	pmu_write_reg(sc, vIER, 0x90);	/* enable VIA interrupts */
}

static inline void
pmu_write_reg(struct pmu_softc *sc, int offset, uint8_t value)
{

	bus_space_write_1(sc->sc_memt, sc->sc_memh, offset, value);
}

static inline uint8_t
pmu_read_reg(struct pmu_softc *sc, int offset)
{

	return bus_space_read_1(sc->sc_memt, sc->sc_memh, offset);
}

static inline int
pmu_send_byte(struct pmu_softc *sc, uint8_t data)
{

	pmu_out(sc);
	pmu_write_reg(sc, vSR, data);
	pmu_ack_off(sc);
	/* wait for intr to come up */
	/* XXX should add a timeout and bail if it expires */
	do {} while (pmu_intr_state(sc) == 0);
	pmu_ack_on(sc);
	do {} while (pmu_intr_state(sc));
	pmu_ack_on(sc);
	DPRINTF(" %02x>", data);
	return 0;
}

static inline int
pmu_read_byte(struct pmu_softc *sc, uint8_t *data)
{
	volatile uint8_t scratch;
	pmu_in(sc);
	scratch = pmu_read_reg(sc, vSR);
	pmu_ack_off(sc);
	/* wait for intr to come up */
	do {} while (pmu_intr_state(sc) == 0);
	pmu_ack_on(sc);
	do {} while (pmu_intr_state(sc));
	*data = pmu_read_reg(sc, vSR);
	DPRINTF(" <%02x", *data);
	return 0;
}

static int
pmu_send(struct pmu_softc *sc, int cmd, int length, uint8_t *in_msg,
    uint8_t *out_msg)
{
	int i, rcv_len = -1, s;
	uint8_t out_len, intreg;

	DPRINTF("pmu_send: ");

	s = splhigh();
	intreg = pmu_read_reg(sc, vIER);
	intreg &= 0x10;
	pmu_write_reg(sc, vIER, intreg);

	/* wait idle */
	do {} while (pmu_intr_state(sc));
	sc->sc_error = 0;

	/* send command */
	pmu_send_byte(sc, cmd);

	/* send length if necessary */
	if (pm_send_cmd_type[cmd] < 0) {
		pmu_send_byte(sc, length);
	}

	for (i = 0; i < length; i++) {
		pmu_send_byte(sc, in_msg[i]);
		DPRINTF(" next ");
	}
	DPRINTF("done sending\n");

	/* see if there's data to read */
	rcv_len = pm_receive_cmd_type[cmd];
	if (rcv_len == 0) 
		goto done;

	/* read command */
	if (rcv_len == 1) {
		pmu_read_byte(sc, out_msg);
		goto done;
	} else
		out_msg[0] = cmd;
	if (rcv_len < 0) {
		pmu_read_byte(sc, &out_len);
		rcv_len = out_len + 1;
	}
	for (i = 1; i < rcv_len; i++)
		pmu_read_byte(sc, &out_msg[i]);

done:
	DPRINTF("\n");
	pmu_write_reg(sc, vIER, (intreg == 0) ? 0 : 0x90);
	splx(s);

	return rcv_len;
}

#if notyet
static void
pmu_poll(void *cookie)
{
	struct pmu_softc *sc = cookie;

	while ((pmu_read_reg(sc, vIFR) & vSR_INT) == vSR_INT) {
		pmu_intr(sc);
	}
}
#endif

static void
pmu_adb_poll(void *cookie)
{
	struct pmu_softc *sc = cookie;

	pmu_intr(sc);
}

static void
pmu_in(struct pmu_softc *sc)
{
	uint8_t reg;

	reg = pmu_read_reg(sc, vACR);
	reg &= ~vSR_OUT;
	reg |= 0x0c;
	pmu_write_reg(sc, vACR, reg);
}

static void
pmu_out(struct pmu_softc *sc)
{
	uint8_t reg;

	reg = pmu_read_reg(sc, vACR);
	reg |= vSR_OUT;
	reg |= 0x0c;
	pmu_write_reg(sc, vACR, reg);
}

static void
pmu_ack_off(struct pmu_softc *sc)
{
	uint8_t reg;

	reg = pmu_read_reg(sc, vBufB);
	reg &= ~vPB4;
	pmu_write_reg(sc, vBufB, reg);
}

static void
pmu_ack_on(struct pmu_softc *sc)
{
	uint8_t reg;

	reg = pmu_read_reg(sc, vBufB);
	reg |= vPB4;
	pmu_write_reg(sc, vBufB, reg);
}

static int
pmu_intr_state(struct pmu_softc *sc)
{
	return ((pmu_read_reg(sc, vBufB) & vPB3) == 0);
}

static int
pmu_intr(void *arg)
{
	struct pmu_softc *sc = arg;
	unsigned int s, len, i;
	uint8_t resp[16];

	s = splhigh();		/* can't be too careful - might be called */
				/* from a routine, NOT an interrupt */

	DPRINTF(":");

	pmu_write_reg(sc, vIFR, 0x90);	/* Clear 'em */
	len = pmu_send(sc, PMU_INT_ACK, 0, NULL, resp);
	if ((len < 1) || (resp[1] == 0))
		goto done;
#ifdef PMU_DEBUG
	{
		DPRINTF("intr: %02x", resp[0]);
		for (i = 1; i < len; i++)
			DPRINTF(" %02x", resp[i]);
		DPRINTF("\n");
	}
#endif
	if (resp[1] & PMU_INT_ADB) {
		pmu_adb_handler(sc, len - 1, &resp[1]);
		goto done;
	}
	if (resp[1] & PMU_INT_SNDBRT) {
		/* deal with the brightness / volume control buttons */
		DPRINTF("brightness: %d volume %d\n", resp[2], resp[3]);
		sc->sc_brightness_wanted = resp[2];
		sc->sc_volume_wanted = resp[3];
		wakeup(&sc->sc_event);
		goto done;
	}
	if (resp[1] & PMU_INT_PCEJECT) {
		/* deal with PCMCIA eject buttons */
		DPRINTF("card eject %d\n", resp[3]);
		sc->sc_pending_eject |= (resp[3] & 3);
		wakeup(&sc->sc_event);
		goto done;
	}
	if (resp[1] & PMU_INT_BATTERY) {
		/* deal with battery messages */
		printf("battery:");
		for (i = 2; i < len; i++)
			printf(" %02x", resp[i]);
		printf("\n");
		goto done;
	}
	if (resp[1] & PMU_INT_ENVIRONMENT) {
#ifdef PMU_VERBOSE
		/* deal with environment messages */
		printf("environment:");
		for (i = 2; i < len; i++)
			printf(" %02x", resp[i]);
		printf("\n");
#endif
		goto done;
	}
	if (resp[1] & PMU_INT_TICK) {
		/* don't bother */
		goto done;
	}

	/* unknown interrupt code?! */
#ifdef PMU_DEBUG
	printf("pmu intr: %02x:", resp[1]);
	for (i = 2; i < len; i++)
		printf(" %02x", resp[i]);
	printf("\n");
#endif
done:
	splx(s);
	return 1;
}

#if 0
static int
pmu_error_handler(void *cookie, int len, uint8_t *data)
{
	struct pmu_softc *sc = cookie;

	/* 
	 * something went wrong
	 * byte 3 seems to be the failed command
	 */
	sc->sc_error = 1;
	wakeup(&sc->sc_todev);
	return 0;
}
#endif
#define DIFF19041970 2082844800

static int
pmu_todr_get(todr_chip_handle_t tch, volatile struct timeval *tvp)
{
	struct pmu_softc *sc = tch->cookie;
	uint32_t sec;
	uint8_t resp[16];

	DPRINTF("pmu_todr_get\n");
	pmu_send(sc, PMU_READ_RTC, 0, NULL, resp);

	memcpy(&sec, &resp[1], 4);
	tvp->tv_sec = sec - DIFF19041970;
	DPRINTF("tod: %ld\n", tvp->tv_sec);
	tvp->tv_usec = 0;
	return 0;
}

static int
pmu_todr_set(todr_chip_handle_t tch, volatile struct timeval *tvp)
{
	struct pmu_softc *sc = tch->cookie;
	uint32_t sec;
	uint8_t resp[16];

	sec = tvp->tv_sec + DIFF19041970;
	if (pmu_send(sc, PMU_SET_RTC, 4, (uint8_t *)&sec, resp) >= 0)
		return 0;
	return -1;		
}

void
pmu_poweroff()
{
	struct pmu_softc *sc;
	uint8_t cmd[] = {'M', 'A', 'T', 'T'};
	uint8_t resp[16];

	if (pmu0 == NULL)
		return;
	sc = pmu0;
	if (pmu_send(sc, PMU_POWER_OFF, 4, cmd, resp) >= 0)
		while (1);
}

void
pmu_restart()
{
	struct pmu_softc *sc;
	uint8_t resp[16];

	if (pmu0 == NULL)
		return;
	sc = pmu0;
	if (pmu_send(sc, PMU_RESET_CPU, 0, NULL, resp) >= 0)
		while (1);
}

static void
pmu_autopoll(void *cookie, int flag)
{
	struct pmu_softc *sc = cookie;
	/* magical incantation to re-enable autopolling */
	uint8_t cmd[] = {0, 0x86, (flag >> 8) & 0xff, flag & 0xff};
	uint8_t resp[16];

	if (sc->sc_autopoll == flag)
		return;

	if (flag) {
		pmu_send(sc, PMU_ADB_CMD, 4, cmd, resp);
	} else {
		pmu_send(sc, PMU_ADB_POLL_OFF, 0, NULL, resp);
	}
	sc->sc_autopoll = flag & 0xffff;
}

static int
pmu_adb_handler(void *cookie, int len, uint8_t *data)
{
	struct pmu_softc *sc = cookie;
	uint8_t resp[16];

	if (sc->sc_adb_handler != NULL) {
		sc->sc_adb_handler(sc->sc_adb_cookie, len, data);
		/*
		 * the PMU will turn off autopolling after each LISTEN so we
		 * need to re-enable it here whenever we receive an ACK for a
		 * LISTEN command
		 */
		if ((data[1] & 0x0c) == 0x08) {
			uint8_t cmd[] = {0, 0x86, (sc->sc_autopoll >> 8) & 0xff,
			    sc->sc_autopoll & 0xff};
			pmu_send(sc, PMU_ADB_CMD, 4, cmd, resp);
		}
		return 0;
	}
	return -1;
}

static int
pmu_adb_send(void *cookie, int poll, int command, int len, uint8_t *data)
{
	struct pmu_softc *sc = cookie;
	int i, replen;
	uint8_t packet[16], resp[16];

	/* construct an ADB command packet and send it */
	packet[0] = command;
	packet[1] = 0;
	packet[2] = len;
	for (i = 0; i < len; i++)
		packet[i + 3] = data[i];
	replen = pmu_send(sc, PMU_ADB_CMD, len + 3, packet, resp);

	return 0;
}

static int
pmu_adb_set_handler(void *cookie, void (*handler)(void *, int, uint8_t *),
    void *hcookie)
{
	struct pmu_softc *sc = cookie;

	/* register a callback for incoming ADB messages */
	sc->sc_adb_handler = handler;
	sc->sc_adb_cookie = hcookie;
	return 0;
}
#if 0
static int
pmu_i2c_acquire_bus(void *cookie, int flags)
{
	/* nothing yet */
	return 0;
}

static void
pmu_i2c_release_bus(void *cookie, int flags)
{
	/* nothing here either */
}

static int
pmu_i2c_exec(void *cookie, i2c_op_t op, i2c_addr_t addr, const void *_send,
    size_t send_len, void *_recv, size_t recv_len, int flags)
{
#if 0
	struct pmu_softc *sc = cookie;
	const uint8_t *send = _send;
	uint8_t *recv = _recv;
	uint8_t command[16] = {PMU_POWERMGR, PMGR_IIC};

	DPRINTF("pmu_i2c_exec(%02x)\n", addr);
	command[2] = addr;

	memcpy(&command[3], send, min((int)send_len, 12));

	sc->sc_iic_done = 0;
	pmu_send(sc, sc->sc_polling, send_len + 3, command);

	while ((sc->sc_iic_done == 0) && (sc->sc_error == 0)) {
		if (sc->sc_polling) {
			pmu_poll(sc);
		} else
			tsleep(&sc->sc_todev, 0, "i2c", 1000);
	}

	if (sc->sc_error) {
		sc->sc_error = 0;
		return -1;
	}

	/* see if we're supposed to do a read */
	if (recv_len > 0) {
		sc->sc_iic_done = 0;
		command[2] |= 1;
		command[3] = 0;

		/*
		 * XXX we need to do something to limit the size of the answer
		 * - apparently the chip keeps sending until we tell it to stop
		 */
		pmu_send(sc, sc->sc_polling, 3, command);
		while ((sc->sc_iic_done == 0) && (sc->sc_error == 0)) {
			if (sc->sc_polling) {
				pmu_poll(sc);
			} else
				tsleep(&sc->sc_todev, 0, "i2c", 1000);
		}

		if (sc->sc_error) {
			printf("error trying to read\n");
			sc->sc_error = 0;
			return -1;
		}
	}

	if ((sc->sc_iic_done > 3) && (recv_len > 0)) {
		/* we got an answer */
		recv[0] = sc->sc_iic_val;
		printf("ret: %02x\n", sc->sc_iic_val);
		return 1;
	}
#endif
	return 0;
}
#endif

static void
pmu_eject_card(struct pmu_softc *sc, int socket)
{
	int s;
	uint8_t buf[] = {socket | 4};
	uint8_t res[4];

	s = splhigh();
	sc->sc_pending_eject &= ~socket;
	splx(s);
	pmu_send(sc, PMU_EJECT_PCMCIA, 1, buf, res);
}

static void
pmu_update_brightness(struct pmu_softc *sc)
{
	int val;
	uint8_t cmd[2], resp[16];

	if (sc->sc_brightness == sc->sc_brightness_wanted)
		return;

	if ((sc->sc_flags & PMU_HAS_BACKLIGHT_CONTROL) == 0) {

		printf("%s: this PMU doesn't support backlight control\n",
			sc->sc_dev.dv_xname);
		sc->sc_brightness = sc->sc_brightness_wanted;	
		return;
	}

	if (sc->sc_brightness_wanted == 0) {
		
		/* turn backlight off completely */
		cmd[0] = PMU_POW_OFF | PMU_POW_BACKLIGHT;
		pmu_send(sc, PMU_POWER_CTRL, 1, cmd, resp);
		sc->sc_brightness = sc->sc_brightness_wanted;
		
		/* don't bother with brightness */
		return;
	}

	/* turn backlight on if needed */
	if (sc->sc_brightness == 0) {
		cmd[0] = PMU_POW_ON | PMU_POW_BACKLIGHT;
		pmu_send(sc, PMU_POWER_CTRL, 1, cmd, resp);
	}

	DPRINTF("pmu_update_brightness: %d -> %d\n", sc->sc_brightness,
	    sc->sc_brightness_wanted);

	val = 0x7f - (sc->sc_brightness_wanted >> 1);
	if (val < 0x08)
		val = 0x08;
	if (val > 0x78)
		val = 0x78;
	cmd[0] = val;
	pmu_send(sc, PMU_SET_BRIGHTNESS, 1, cmd, resp);

	sc->sc_brightness = sc->sc_brightness_wanted;
}

static void
pmu_create_thread(void *cookie)
{
	struct pmu_softc *sc = cookie;
	
	if (kthread_create1(pmu_thread, sc, &sc->sc_thread, "%s",
	    "pmu") != 0) {
		printf("pmu: unable to create event kthread");
	}
}

static void
pmu_thread(void *cookie)
{
	struct pmu_softc *sc = cookie;
	//time_t time_bat = time_second;
	int ticks = hz, i;
	
	while (1) {
		tsleep(&sc->sc_event, PWAIT, "pmu_wait", ticks);
		if (sc->sc_pending_eject != 0) {
			DPRINTF("eject %d\n", sc->sc_pending_eject);
			for (i = 1; i < 3; i++) {
				if (i & sc->sc_pending_eject)
					pmu_eject_card(sc, i);
			}
		}
#if NLWPM > 0
		lwpm_poll();
#endif
		/* see if we need to update brightness */
		if (sc->sc_brightness_wanted != sc->sc_brightness) {
			pmu_update_brightness(sc);
		}

		/* see if we need to update audio volume */
		if (sc->sc_volume_wanted != sc->sc_volume) {
			//set_volume(sc->sc_volume_wanted);
			sc->sc_volume = sc->sc_volume_wanted;
		}
	}
}
