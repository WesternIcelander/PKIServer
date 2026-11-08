package io.siggi.pkiserver;

import io.siggi.pkiserver.store.CaRole;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoredCrl;
import io.siggi.pkiserver.x509.X509Util;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Validates certificates against the signing certificates installed on the server.
 * <p>
 * The only trust anchors are the installed roots; the JDK trust store is never used. Paths
 * are built only through installed intermediates (whatever else a client sends is ignored),
 * validated with the JDK's PKIX {@link CertPathValidator}, and then checked for revocation
 * against our own current CRLs (PKIX revocation checking is off: the server never fetches
 * anything).
 * <p>
 * Certificates that aren't valid yet are accepted: the path is validated at the later of now
 * and the target's {@code notBefore}, so a CA renewed ahead of time can be published early.
 * An expired target is rejected.
 */
final class ChainValidator {
    /** Longest chain considered (target + intermediates + root), against loops and blowups. */
    static final int MAX_PATH_LENGTH = 8;

    private final Store store;

    ChainValidator(Store store) {
        this.store = store;
    }

    /** Why a certificate didn't validate. */
    static final class ValidationException extends Exception {
        ValidationException(String message) {
            super(message);
        }
    }

    /**
     * Validates {@code target} at {@code now}.
     *
     * @return the issuing signing certificates, the direct issuer first and the root last
     * @throws ValidationException with a human-readable reason if no valid path exists
     */
    List<SigningCert> validate(X509Certificate target, Instant now) throws ValidationException {
        if (target.getNotAfter().toInstant().isBefore(now)) {
            throw new ValidationException("certificate expired on " + target.getNotAfter().toInstant());
        }
        List<SigningCert> roots = new ArrayList<>();
        for (SigningCert sc : store.signingCerts()) {
            if (sc.role() == CaRole.ROOT) roots.add(sc);
        }
        if (roots.isEmpty()) {
            throw new ValidationException("no root is installed on this server");
        }
        List<List<SigningCert>> candidates = new ArrayList<>();
        findPaths(target, new ArrayList<>(), candidates);
        if (candidates.isEmpty()) {
            throw new ValidationException(noPathReason(target));
        }
        Instant at = target.getNotBefore().toInstant().isAfter(now) ? target.getNotBefore().toInstant() : now;
        String firstProblem = null;
        for (List<SigningCert> path : candidates) {
            String problem = pkixProblem(target, path, roots, at);
            if (problem == null) problem = revocationProblem(target, path);
            if (problem == null) return List.copyOf(path);
            if (firstProblem == null) firstProblem = problem;
        }
        throw new ValidationException(firstProblem);
    }

    /**
     * Depth-first search for every chain of installed signing certificates from the issuer of
     * {@code cert} up to an installed root, following subject DN and signature.
     */
    private void findPaths(X509Certificate cert, List<SigningCert> above, List<List<SigningCert>> out) {
        if (above.size() + 1 >= MAX_PATH_LENGTH) return;
        for (SigningCert issuer : store.signingCertsBySubject(cert.getIssuerX500Principal())) {
            if (!signedBy(cert, issuer.cert())) continue;
            boolean loop = false;
            for (SigningCert sc : above) {
                if (sc.sha256().equals(issuer.sha256())) loop = true;
            }
            if (loop) continue;
            above.add(issuer);
            if (issuer.role() == CaRole.ROOT) {
                out.add(new ArrayList<>(above));
            } else {
                findPaths(issuer.cert(), above, out);
            }
            above.remove(above.size() - 1);
        }
    }

    private static boolean signedBy(X509Certificate cert, X509Certificate issuer) {
        try {
            cert.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** Why no path of installed certificates leads from {@code target} to a root. */
    private String noPathReason(X509Certificate target) {
        String issuerName = target.getIssuerX500Principal().getName();
        List<SigningCert> issuers = store.signingCertsBySubject(target.getIssuerX500Principal());
        if (issuers.isEmpty()) {
            return "issuer " + issuerName + " is not installed on this server";
        }
        for (SigningCert issuer : issuers) {
            if (signedBy(target, issuer.cert())) {
                return "issuer " + issuerName + " (\"" + issuer.slug() + "\") does not chain to an installed root";
            }
        }
        return "signature does not verify with the key of any installed certificate named " + issuerName;
    }

    /** Runs PKIX validation of {@code target} through {@code path}; null if it passes. */
    private static String pkixProblem(X509Certificate target, List<SigningCert> path, List<SigningCert> roots,
                                      Instant at) {
        List<X509Certificate> certs = new ArrayList<>();
        certs.add(target);
        for (int i = 0; i < path.size() - 1; i++) certs.add(path.get(i).cert()); // root is the anchor
        Set<TrustAnchor> anchors = new HashSet<>();
        for (SigningCert root : roots) anchors.add(new TrustAnchor(root.cert(), null));
        try {
            CertPath certPath = CertificateFactory.getInstance("X.509").generateCertPath(certs);
            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false); // checked against our own CRLs instead
            params.setDate(Date.from(at));
            CertPathValidator.getInstance("PKIX").validate(certPath, params);
            return null;
        } catch (CertPathValidatorException e) {
            int index = e.getIndex();
            String where = index >= 0 && index < certs.size()
                    ? " at " + certs.get(index).getSubjectX500Principal().getName() : "";
            String cause = e.getCause() != null && e.getCause().getMessage() != null
                    && !e.getCause().getMessage().equals(e.getMessage()) ? ": " + e.getCause().getMessage() : "";
            return "certificate path validation failed" + where + ": " + e.getMessage() + cause;
        } catch (CertificateException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            return "certificate path validation failed: " + e.getMessage();
        }
    }

    /**
     * Checks every certificate on the path below the root against its issuer's current CRL on
     * this server; null if none is revoked. A CA without a current CRL revokes nothing.
     */
    private String revocationProblem(X509Certificate target, List<SigningCert> path) {
        X509Certificate cert = target;
        for (SigningCert issuer : path) {
            StoredCrl crl = store.currentCrl(issuer.slug());
            if (crl != null) {
                X509CRLEntry entry = crl.crl().getRevokedCertificate(cert);
                if (entry != null) {
                    return cert.getSubjectX500Principal().getName() + " (serial "
                            + X509Util.formatSerial(cert.getSerialNumber()) + ") is revoked by CRL #"
                            + crl.number() + " of \"" + issuer.slug() + "\" since "
                            + entry.getRevocationDate().toInstant();
                }
            }
            cert = issuer.cert();
        }
        return null;
    }
}
