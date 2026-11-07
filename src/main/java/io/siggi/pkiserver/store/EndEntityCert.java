package io.siggi.pkiserver.store;

import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * An end-entity certificate published under its issuer.
 *
 * @param issuerSlug slug of the issuing signing certificate
 * @param serial     serial number, formatted as by {@code X509Util.formatSerial}
 * @param cert       the certificate
 * @param der        its DER encoding
 * @param sha256     SHA-256 of {@code der}, lowercase hex
 * @param uploadedAt when the server accepted it
 */
public record EndEntityCert(String issuerSlug, String serial, X509Certificate cert, byte[] der, String sha256,
                            Instant uploadedAt) {
}
