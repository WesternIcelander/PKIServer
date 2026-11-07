package io.siggi.pkiserver.store;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.time.Instant;

/**
 * A CRL accepted for a signing certificate.
 *
 * @param number     the CRL Number (also the file name)
 * @param crl        the parsed CRL
 * @param der        its DER encoding
 * @param sha256     SHA-256 of {@code der}, lowercase hex
 * @param state      current, pending or superseded
 * @param thisUpdate the CRL's thisUpdate
 * @param nextUpdate the CRL's nextUpdate, or null if it has none
 * @param receivedAt when the server accepted it
 */
public record StoredCrl(BigInteger number, X509CRL crl, byte[] der, String sha256, CrlState state,
                        Instant thisUpdate, Instant nextUpdate, Instant receivedAt) {
    public StoredCrl withState(CrlState newState) {
        return new StoredCrl(number, crl, der, sha256, newState, thisUpdate, nextUpdate, receivedAt);
    }
}
