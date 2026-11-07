package io.siggi.pkiserver.store;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

/**
 * A signing (CA) certificate on the server.
 *
 * @param slug       URL name, also the directory name under {@code ca/}
 * @param cert       the certificate
 * @param der        its DER encoding (the bytes stored in {@code cert.der})
 * @param role       root (self-signed) or intermediate
 * @param spkiSha256 SHA-256 of the SubjectPublicKeyInfo, lowercase hex
 * @param sha256     SHA-256 of the DER certificate, lowercase hex
 */
public record SigningCert(String slug, X509Certificate cert, byte[] der, CaRole role, String spkiSha256,
                          String sha256) {
    public X500Principal subject() {
        return cert.getSubjectX500Principal();
    }
}
