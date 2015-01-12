#ifndef ATTACKS_H
#define ATTACKS_H

// Utility functions
int attack_confradio(struct ath_softc_tgt *sc);
struct ath_tx_buf * attack_build_packet(struct ath_softc_tgt *sc, uint8_t *data,
			a_int32_t len, char waitack, unsigned char destmac[6]);

// Attack implementations
int attack_reactivejam(struct ath_softc_tgt *sc, unsigned char source[6],
		       unsigned int msecs);

#endif // ATTACKS_H

