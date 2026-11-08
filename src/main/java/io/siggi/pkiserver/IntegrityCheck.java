package io.siggi.pkiserver;

import io.siggi.pkiserver.store.CaRole;
import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.EndEntityCert;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoreException;
import io.siggi.pkiserver.store.StoredCrl;
import io.siggi.pkiserver.x509.X509Util;

import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Startup integrity check: re-verifies everything the {@link Store} loaded and withholds what
 * no longer validates, so it is neither served nor used to validate anything else.
 * <p>
 * The store has already re-parsed every DER file and rebuilt the metadata from it. This adds
 * the checks that need the other stored objects:
 * <ul>
 *   <li>a root is self-signed and {@code CA:TRUE} (as {@code add-root} requires);</li>
 *   <li>an intermediate is {@code CA:TRUE}, has {@code keyCertSign} (if it has a Key Usage)
 *       and passes PKIX through installed, themselves valid signing certificates up to an
 *       installed root (see {@link ChainValidator#verifyStored}); withholding one
 *       intermediate can break the path of another, so this repeats until nothing changes;</li>
 *   <li>a CRL is signed by its CA's key, the CA has {@code cRLSign} (if it has a Key Usage),
 *       it is a full CRL and has a {@code nextUpdate} after its {@code thisUpdate};</li>
 *   <li>an end-entity certificate is not a CA and passes PKIX through the CA it is stored
 *       under.</li>
 * </ul>
 * Time and revocation are not checked: stored objects stay published when they expire or are
 * revoked. Withheld objects stay on disk untouched (and their slugs, CRL Numbers and serials
 * stay taken), so fixing the cause and restarting brings them back. Slugs are never
 * re-derived.
 */
final class IntegrityCheck {
    private static final Logger log = Logging.get(IntegrityCheck.class);

    private final Store store;
    private final ChainValidator validator;
    private final List<String> withheld = new ArrayList<>();

    IntegrityCheck(Store store) {
        this.store = store;
        this.validator = new ChainValidator(store);
    }

    /**
     * Runs the check, logging each withheld object.
     *
     * @return descriptions of the withheld objects (empty if everything validated)
     */
    List<String> run() {
        checkSigningCerts();
        for (SigningCert sc : store.signingCerts()) {
            checkCrls(sc);
            checkEndEntities(sc);
        }
        if (withheld.isEmpty()) {
            log.info("Integrity check passed");
        } else {
            log.warning("Integrity check: " + withheld.size() + " stored object(s) failed and are not served");
        }
        return List.copyOf(withheld);
    }

    private void checkSigningCerts() {
        boolean changed = true;
        while (changed) {
            changed = false;
            for (SigningCert sc : store.signingCerts()) {
                String problem = signingCertProblem(sc);
                if (problem == null) continue;
                try {
                    store.withholdSigningCert(sc.slug());
                } catch (StoreException e) {
                    continue; // already gone
                }
                withhold("signing certificate \"" + sc.slug() + "\" (" + sc.subject().getName()
                        + ") and its CRLs and certificates", problem);
                changed = true;
            }
        }
    }

    private String signingCertProblem(SigningCert sc) {
        X509Certificate cert = sc.cert();
        if (sc.role() == CaRole.ROOT) return AdminCli.rootProblem(cert);
        if (cert.getBasicConstraints() < 0) return "not a CA certificate (basicConstraints CA:TRUE is missing)";
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5])) {
            return "Key Usage does not include keyCertSign";
        }
        try {
            validator.verifyStored(cert, null);
            return null;
        } catch (ChainValidator.ValidationException e) {
            return e.getMessage();
        }
    }

    private void checkCrls(SigningCert sc) {
        for (StoredCrl crl : store.crls(sc.slug())) {
            String problem = crlProblem(sc, crl.crl());
            if (problem == null) continue;
            try {
                store.withholdCrl(sc.slug(), crl.number());
            } catch (StoreException e) {
                continue;
            }
            withhold("CRL #" + crl.number() + " (" + crl.state().id() + ") of \"" + sc.slug() + "\"", problem);
            if (crl.state() == CrlState.CURRENT) {
                log.warning("\"" + sc.slug() + "\" has no current CRL until a new one takes effect");
            }
        }
    }

    private static String crlProblem(SigningCert sc, X509CRL crl) {
        try {
            crl.verify(sc.cert().getPublicKey());
        } catch (GeneralSecurityException | RuntimeException e) {
            return "signature does not verify with the key of the signing certificate";
        }
        boolean[] keyUsage = sc.cert().getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= 6 || !keyUsage[6])) {
            return "the Key Usage of the signing certificate does not include cRLSign";
        }
        if (X509Util.isDeltaCrl(crl)) return "it is a delta CRL";
        if (crl.getNextUpdate() == null) return "it has no nextUpdate";
        if (!crl.getThisUpdate().before(crl.getNextUpdate())) return "thisUpdate is not before nextUpdate";
        return null;
    }

    private void checkEndEntities(SigningCert sc) {
        for (EndEntityCert ee : store.endEntityCerts(sc.slug())) {
            String problem = endEntityProblem(sc, ee.cert());
            if (problem == null) continue;
            try {
                store.withholdEndEntityCert(sc.slug(), ee.serial());
            } catch (StoreException e) {
                continue;
            }
            withhold("certificate " + ee.serial() + " (" + ee.cert().getSubjectX500Principal().getName()
                    + ") under \"" + sc.slug() + "\"", problem);
        }
    }

    private String endEntityProblem(SigningCert sc, X509Certificate cert) {
        if (cert.getBasicConstraints() >= 0) return "it is a CA certificate, not an end-entity certificate";
        try {
            validator.verifyStored(cert, sc.slug());
            return null;
        } catch (ChainValidator.ValidationException e) {
            return e.getMessage();
        }
    }

    private void withhold(String what, String problem) {
        String message = what + ": " + problem;
        withheld.add(message);
        log.warning("Not serving " + message);
    }
}
