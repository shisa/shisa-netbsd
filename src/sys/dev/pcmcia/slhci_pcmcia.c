/*	$NetBSD: slhci_isa.c,v 1.4 2002/10/02 03:10:50 thorpej Exp $	*/

/*
 * Copyright (c) 2001 Kiyoshi Ikehara. All rights reserved.
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
 *      This product includes software developed by Kiyoshi Ikehara.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * PCMCIA-USB host board
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: slhci_isa.c,v 1.4 2002/10/02 03:10:50 thorpej Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>

#include <machine/bus.h>
#include <machine/cpu.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>

#include <dev/ic/sl811hsreg.h>
#include <dev/ic/sl811hsvar.h>

#include <dev/pcmcia/pcmciadevs.h>
#include <dev/pcmcia/pcmciareg.h>
#include <dev/pcmcia/pcmciavar.h>


struct slhci_pcmcia_softc {
	struct slhci_softc sc;
	struct pcmcia_function *sc_pf;		/* our PCMCIA function */
	void *sc_ih;
	int sc_attached;
};

static int  slhci_pcmcia_match(struct device *, struct cfdata *, void *);
static void slhci_pcmcia_attach(struct device *, struct device *, void *);
static int slhci_pcmcia_detach(struct device *, int);

static int slhci_pcmcia_validate_config(struct pcmcia_config_entry *cfe);
static int slhci_pcmcia_enable(struct slhci_softc *);
static void slhci_pcmcia_disable(struct slhci_softc *);


CFATTACH_DECL(slhci_pcmcia, sizeof(struct slhci_pcmcia_softc),
    slhci_pcmcia_match, slhci_pcmcia_attach, slhci_pcmcia_detach, NULL);

const struct pcmcia_product slhci_pcmcia_products[] = {
        { PCMCIA_VENDOR_RATOC, PCMCIA_PRODUCT_RATOC_REX_CFU1,
	  PCMCIA_CIS_RATOC_REX_CFU1 },
};
static const size_t slhci_pcmcia_nproducts =
    sizeof(slhci_pcmcia_products) / sizeof(slhci_pcmcia_products[0]);


/* ARGSUSED */
static int
slhci_pcmcia_match(struct device *parent, struct cfdata *cf, void *aux)
{
	struct pcmcia_attach_args *pa = aux;

	if (pa->pf->function == PCMCIA_FUNCTION_DISK)
		return (1);
	if (pcmcia_product_lookup(pa, slhci_pcmcia_products,
	    slhci_pcmcia_nproducts, sizeof(slhci_pcmcia_products[0]), NULL))
		return (2);
	return (0);
}

static int
slhci_pcmcia_validate_config(struct pcmcia_config_entry *cfe)
{

	if (cfe->iftype != PCMCIA_IFTYPE_IO || cfe->num_iospace != 1)
		return (EINVAL);
	cfe->num_memspace = 0;
	return (0);
}

/* ARGSUSED */
static void
slhci_pcmcia_attach(struct device *parent, struct device *self, void *aux)
{
	struct slhci_pcmcia_softc *psc = (struct slhci_pcmcia_softc *)self;
	struct slhci_softc *sc = &psc->sc;
	struct pcmcia_attach_args *pa = aux;
	struct pcmcia_config_entry *cfe;
	int error;

	psc->sc_pf = pa->pf;

	error = pcmcia_function_configure(pa->pf, slhci_pcmcia_validate_config);
	if (error) {
		aprint_error("%s: configure failed, error=%d\n", self->dv_xname,
		    error);
		return;
	}

	cfe = pa->pf->cfe;
	sc->sc_iot = cfe->iospace[0].handle.iot;
	sc->sc_ioh = cfe->iospace[0].handle.ioh;
	sc->sc_enable_power = NULL;
	sc->sc_enable_intr  = NULL;
	sc->sc_arg = psc;

	error = slhci_pcmcia_enable(sc);
	if (error)
		goto fail;

	printf("\n");

	if (slhci_attach(sc, self))
		goto fail;

	psc->sc_attached = 1;
	return;

fail:
	slhci_pcmcia_disable(sc);
	pcmcia_function_unconfigure(pa->pf);
}

static int
slhci_pcmcia_detach(struct device *self, int flags)
{
	struct slhci_pcmcia_softc *psc = (struct slhci_pcmcia_softc *)self;
	int error;

	if (!psc->sc_attached)
		return (0);

	slhci_pcmcia_disable(&psc->sc);
	if ((error = slhci_detach(&psc->sc, flags)) != 0)
		return (error);

	pcmcia_function_unconfigure(psc->sc_pf);
	return (0);
}

static int
slhci_pcmcia_enable(struct slhci_softc *sc)
{
	struct slhci_pcmcia_softc *psc = (struct slhci_pcmcia_softc *)sc;
	struct pcmcia_function *pf = psc->sc_pf;
	int error;

	/* establish the interrupt. */
	psc->sc_ih = pcmcia_intr_establish(pf, IPL_USB, slhci_intr, sc);
	if (psc->sc_ih == NULL) {
		printf("%s: couldn't establish interrupt\n",
		    sc->sc_bus.bdev.dv_xname);
		return (1);
	}

	if ((error = pcmcia_function_enable(pf)) != 0) {
		pcmcia_intr_disestablish(pf, psc->sc_ih);
		psc->sc_ih = 0;
		return (error);
	}

	return (0);
}

static void
slhci_pcmcia_disable(struct slhci_softc *sc)
{
	struct slhci_pcmcia_softc *psc = (struct slhci_pcmcia_softc *)sc;

	pcmcia_function_disable(psc->sc_pf);
	pcmcia_intr_disestablish(psc->sc_pf, psc->sc_ih);
	psc->sc_ih = 0;
}
