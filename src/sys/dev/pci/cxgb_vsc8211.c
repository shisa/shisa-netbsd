/**************************************************************************

Copyright (c) 2007, Chelsio Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Neither the name of the Chelsio Corporation nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

***************************************************************************/

#include <sys/cdefs.h>
#ifdef __FreeBSD__
__FBSDID("$FreeBSD: src/sys/dev/cxgb/common/cxgb_vsc8211.c,v 1.2 2007/05/28 22:57:26 kmacy Exp $");
#endif

#ifdef CONFIG_DEFINED
#include <cxgb_include.h>
#else
#ifdef __FreeBSD__
#include <dev/cxgb/cxgb_include.h>
#endif
#ifdef __NetBSD__
#include <dev/pci/cxgb_include.h>
#endif
#endif

/* VSC8211 PHY specific registers. */
enum {
	VSC8211_INTR_ENABLE   = 25,
	VSC8211_INTR_STATUS   = 26,
	VSC8211_AUX_CTRL_STAT = 28,
};

enum {
	VSC_INTR_RX_ERR     = 1 << 0,
	VSC_INTR_MS_ERR     = 1 << 1,  /* master/slave resolution error */
	VSC_INTR_CABLE      = 1 << 2,  /* cable impairment */
	VSC_INTR_FALSE_CARR = 1 << 3,  /* false carrier */
	VSC_INTR_MEDIA_CHG  = 1 << 4,  /* AMS media change */
	VSC_INTR_RX_FIFO    = 1 << 5,  /* Rx FIFO over/underflow */
	VSC_INTR_TX_FIFO    = 1 << 6,  /* Tx FIFO over/underflow */
	VSC_INTR_DESCRAMBL  = 1 << 7,  /* descrambler lock-lost */
	VSC_INTR_SYMBOL_ERR = 1 << 8,  /* symbol error */
	VSC_INTR_NEG_DONE   = 1 << 10, /* autoneg done */
	VSC_INTR_NEG_ERR    = 1 << 11, /* autoneg error */
	VSC_INTR_LINK_CHG   = 1 << 13, /* link change */
	VSC_INTR_ENABLE     = 1 << 15, /* interrupt enable */
};

#define CFG_CHG_INTR_MASK (VSC_INTR_LINK_CHG | VSC_INTR_NEG_ERR | \
	 		   VSC_INTR_NEG_DONE)
#define INTR_MASK (CFG_CHG_INTR_MASK | VSC_INTR_TX_FIFO | VSC_INTR_RX_FIFO | \
		   VSC_INTR_ENABLE)

/* PHY specific auxiliary control & status register fields */
#define S_ACSR_ACTIPHY_TMR    0
#define M_ACSR_ACTIPHY_TMR    0x3
#define V_ACSR_ACTIPHY_TMR(x) ((x) << S_ACSR_ACTIPHY_TMR)

#define S_ACSR_SPEED    3
#define M_ACSR_SPEED    0x3
#define G_ACSR_SPEED(x) (((x) >> S_ACSR_SPEED) & M_ACSR_SPEED)

#define S_ACSR_DUPLEX 5
#define F_ACSR_DUPLEX (1 << S_ACSR_DUPLEX)

#define S_ACSR_ACTIPHY 6
#define F_ACSR_ACTIPHY (1 << S_ACSR_ACTIPHY)

/*
 * Reset the PHY.  This PHY completes reset immediately so we never wait.
 */
static int vsc8211_reset(struct cphy *cphy, int wait)
{
	return t3_phy_reset(cphy, 0, 0);
}

static int vsc8211_intr_enable(struct cphy *cphy)
{
	return mdio_write(cphy, 0, VSC8211_INTR_ENABLE, INTR_MASK);
}

static int vsc8211_intr_disable(struct cphy *cphy)
{
	return mdio_write(cphy, 0, VSC8211_INTR_ENABLE, 0);
}

static int vsc8211_intr_clear(struct cphy *cphy)
{
	u32 val;

	/* Clear PHY interrupts by reading the register. */
	return mdio_read(cphy, 0, VSC8211_INTR_STATUS, &val);
}

static int vsc8211_autoneg_enable(struct cphy *cphy)
{
	return t3_mdio_change_bits(cphy, 0, MII_BMCR, BMCR_PDOWN | BMCR_ISOLATE,
				   BMCR_ANENABLE | BMCR_ANRESTART);
}

static int vsc8211_autoneg_restart(struct cphy *cphy)
{
	return t3_mdio_change_bits(cphy, 0, MII_BMCR, BMCR_PDOWN | BMCR_ISOLATE,
				   BMCR_ANRESTART);
}

static int vsc8211_get_link_status(struct cphy *cphy, int *link_ok,
				     int *speed, int *duplex, int *fc)
{
	unsigned int bmcr, status, lpa, adv;
	int err, sp = -1, dplx = -1, pause = 0;

	err = mdio_read(cphy, 0, MII_BMCR, &bmcr);
	if (!err)
		err = mdio_read(cphy, 0, MII_BMSR, &status);
	if (err)
		return err;

	if (link_ok) {
		/*
		 * BMSR_LSTATUS is latch-low, so if it is 0 we need to read it
		 * once more to get the current link state.
		 */
		if (!(status & BMSR_LSTATUS))
			err = mdio_read(cphy, 0, MII_BMSR, &status);
		if (err)
			return err;
		*link_ok = (status & BMSR_LSTATUS) != 0;
	}
	if (!(bmcr & BMCR_ANENABLE)) {
		dplx = (bmcr & BMCR_FULLDPLX) ? DUPLEX_FULL : DUPLEX_HALF;
		if (bmcr & BMCR_SPEED1000)
			sp = SPEED_1000;
		else if (bmcr & BMCR_SPEED100)
			sp = SPEED_100;
		else
			sp = SPEED_10;
	} else if (status & BMSR_ANEGCOMPLETE) {
		err = mdio_read(cphy, 0, VSC8211_AUX_CTRL_STAT, &status);
		if (err)
			return err;

		dplx = (status & F_ACSR_DUPLEX) ? DUPLEX_FULL : DUPLEX_HALF;
		sp = G_ACSR_SPEED(status);
		if (sp == 0)
			sp = SPEED_10;
		else if (sp == 1)
			sp = SPEED_100;
		else
			sp = SPEED_1000;

		if (fc && dplx == DUPLEX_FULL) {
			err = mdio_read(cphy, 0, MII_LPA, &lpa);
			if (!err)
				err = mdio_read(cphy, 0, MII_ADVERTISE, &adv);
			if (err)
				return err;

			if (lpa & adv & ADVERTISE_PAUSE_CAP)
				pause = PAUSE_RX | PAUSE_TX;
			else if ((lpa & ADVERTISE_PAUSE_CAP) &&
				 (lpa & ADVERTISE_PAUSE_ASYM) &&
				 (adv & ADVERTISE_PAUSE_ASYM))
				pause = PAUSE_TX;
			else if ((lpa & ADVERTISE_PAUSE_ASYM) &&
				 (adv & ADVERTISE_PAUSE_CAP))
				pause = PAUSE_RX;
		}
	}
	if (speed)
		*speed = sp;
	if (duplex)
		*duplex = dplx;
	if (fc)
		*fc = pause;
	return 0;
}

static int vsc8211_power_down(struct cphy *cphy, int enable)
{
	return t3_mdio_change_bits(cphy, 0, MII_BMCR, BMCR_PDOWN,
				   enable ? BMCR_PDOWN : 0);
}

static int vsc8211_intr_handler(struct cphy *cphy)
{
	unsigned int cause;
	int err, cphy_cause = 0;

	err = mdio_read(cphy, 0, VSC8211_INTR_STATUS, &cause);
	if (err)
		return err;

	cause &= INTR_MASK;
	if (cause & CFG_CHG_INTR_MASK)
		cphy_cause |= cphy_cause_link_change;
	if (cause & (VSC_INTR_RX_FIFO | VSC_INTR_TX_FIFO))
		cphy_cause |= cphy_cause_fifo_error;
	return cphy_cause;
}

#ifdef C99_NOT_SUPPORTED
static struct cphy_ops vsc8211_ops = {
	NULL,
	vsc8211_reset,
	vsc8211_intr_enable,
	vsc8211_intr_disable,
	vsc8211_intr_clear,
	vsc8211_intr_handler,
	vsc8211_autoneg_enable,
	vsc8211_autoneg_restart,
	t3_phy_advertise,
	NULL,
	t3_set_phy_speed_duplex,
	vsc8211_get_link_status,
	vsc8211_power_down,
};
#else
static struct cphy_ops vsc8211_ops = {
	.reset             = vsc8211_reset,
	.intr_enable       = vsc8211_intr_enable,
	.intr_disable      = vsc8211_intr_disable,
	.intr_clear        = vsc8211_intr_clear,
	.intr_handler      = vsc8211_intr_handler,
	.autoneg_enable    = vsc8211_autoneg_enable,
	.autoneg_restart   = vsc8211_autoneg_restart,
	.advertise         = t3_phy_advertise,
	.set_speed_duplex  = t3_set_phy_speed_duplex,
	.get_link_status   = vsc8211_get_link_status,
	.power_down        = vsc8211_power_down,
};
#endif

void t3_vsc8211_phy_prep(struct cphy *phy, adapter_t *adapter, int phy_addr,
			 const struct mdio_ops *mdio_ops)
{
	cphy_init(phy, adapter, phy_addr, &vsc8211_ops, mdio_ops);
}
