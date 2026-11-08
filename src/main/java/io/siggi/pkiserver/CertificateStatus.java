package io.siggi.pkiserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.siggi.pkiserver.store.EndEntityCert;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoredCrl;
import io.siggi.pkiserver.x509.X509Util;

import java.math.BigInteger;
import java.security.cert.CRLReason;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

/**
 * Status of a published end-entity certificate: whether it's revoked (by its issuer's current
 * CRL, or because a signing certificate above it is revoked by its own issuer's current CRL),
 * expired, not yet valid, or valid.
 * <p>
 * Revocation is read from the current CRLs on this server only. Since a current CRL never drops
 * an entry (CRL rule 5), a certificate once shown as revoked stays revoked.
 *
 * @param ee         the certificate
 * @param now        when this was computed
 * @param status     the overall status
 * @param revocation why it's revoked, or null if it isn't
 */
record CertificateStatus(EndEntityCert ee, Instant now, Status status, Revocation revocation) {

    /** The API path prefix: {@code GET /api/certificate/<slug>/<serial>}. */
    static final String API_PREFIX = CertificateUpload.PATH + "/";

    enum Status {
        VALID("valid"), REVOKED("revoked"), EXPIRED("expired"), NOT_YET_VALID("not-yet-valid");

        final String id;

        Status(String id) {
            this.id = id;
        }
    }

    /**
     * A revocation found in a current CRL.
     *
     * @param revokedSlug    null if the end-entity certificate itself is revoked, otherwise the
     *                       slug of the revoked signing certificate above it
     * @param serial         serial of the revoked certificate, formatted
     * @param crlSlug        the signing certificate whose CRL lists it
     * @param crlNumber      that CRL's number
     * @param revocationDate the revocation date in the CRL entry
     * @param reason         the CRL entry's reason code, or null if it has none
     */
    record Revocation(String revokedSlug, String serial, String crlSlug, BigInteger crlNumber,
                      Instant revocationDate, CRLReason reason) {
    }

    /** The status of {@code ee} at {@code now}. */
    static CertificateStatus of(Store store, ChainBuilder chains, EndEntityCert ee, Instant now) {
        Revocation revocation = revocation(store, chains, ee);
        X509Certificate cert = ee.cert();
        Status status;
        if (revocation != null) {
            status = Status.REVOKED;
        } else if (now.isAfter(cert.getNotAfter().toInstant())) {
            status = Status.EXPIRED;
        } else if (now.isBefore(cert.getNotBefore().toInstant())) {
            status = Status.NOT_YET_VALID;
        } else {
            status = Status.VALID;
        }
        return new CertificateStatus(ee, now, status, revocation);
    }

    /**
     * The first revocation found walking up from {@code ee}: the certificate itself in its
     * issuer's current CRL, then each signing certificate in the next one up's. If no path to a
     * root exists any more, only the issuer's CRL is checked.
     */
    private static Revocation revocation(Store store, ChainBuilder chains, EndEntityCert ee) {
        List<SigningCert> path = chains.path(ee.issuerSlug());
        if (path == null) {
            SigningCert issuer = store.signingCert(ee.issuerSlug());
            if (issuer == null) return null;
            path = List.of(issuer);
        }
        X509Certificate cert = ee.cert();
        String certSlug = null;
        for (SigningCert issuer : path) {
            StoredCrl crl = store.currentCrl(issuer.slug());
            if (crl != null) {
                X509CRLEntry entry = crl.crl().getRevokedCertificate(cert);
                if (entry != null) {
                    return new Revocation(certSlug, X509Util.formatSerial(cert.getSerialNumber()),
                            issuer.slug(), crl.number(), entry.getRevocationDate().toInstant(),
                            entry.getRevocationReason());
                }
            }
            cert = issuer.cert();
            certSlug = issuer.slug();
        }
        return null;
    }

    /** The reason as a lowercase RFC 5280 style name, e.g. {@code keyCompromise}, or null. */
    static String reasonName(CRLReason reason) {
        if (reason == null) return null;
        String[] words = reason.name().toLowerCase(Locale.ROOT).split("_");
        StringBuilder sb = new StringBuilder(words[0]);
        for (int i = 1; i < words.length; i++) {
            if (words[i].isEmpty()) continue;
            sb.append(Character.toUpperCase(words[i].charAt(0))).append(words[i].substring(1));
        }
        String name = sb.toString();
        // The JDK spells it CA_COMPROMISE and AA_COMPROMISE; RFC 5280 says cACompromise/aACompromise.
        return switch (reason) {
            case CA_COMPROMISE -> "cACompromise";
            case AA_COMPROMISE -> "aACompromise";
            default -> name;
        };
    }

    JsonObject toJson() {
        X509Certificate cert = ee.cert();
        JsonObject j = new JsonObject();
        j.addProperty("issuer", ee.issuerSlug());
        j.addProperty("serial", ee.serial());
        j.addProperty("subject", cert.getSubjectX500Principal().getName());
        JsonArray sans = new JsonArray();
        for (String san : Store.subjectAltNames(cert)) sans.add(san);
        j.add("subjectAltNames", sans);
        j.addProperty("notBefore", cert.getNotBefore().toInstant().toString());
        j.addProperty("notAfter", cert.getNotAfter().toInstant().toString());
        j.addProperty("sha256", ee.sha256());
        j.addProperty("uploadedAt", ee.uploadedAt() == null ? null : ee.uploadedAt().toString());
        j.addProperty("now", now.toString());
        j.addProperty("status", status.id);
        j.addProperty("revoked", revocation != null);
        if (revocation == null) {
            j.add("revocation", null);
        } else {
            JsonObject r = new JsonObject();
            // Null if this certificate itself is revoked, else the slug of the revoked CA above it.
            r.addProperty("revokedCa", revocation.revokedSlug());
            r.addProperty("revokedSerial", revocation.serial());
            r.addProperty("revocationDate", revocation.revocationDate().toString());
            r.addProperty("reason", reasonName(revocation.reason()));
            r.addProperty("crlIssuer", revocation.crlSlug());
            r.addProperty("crlNumber", revocation.crlNumber().toString());
            j.add("revocation", r);
        }
        String base = "/" + ee.issuerSlug() + "/" + ee.serial() + "/";
        JsonObject urls = new JsonObject();
        urls.addProperty("certificate", base + "certificate.pem");
        urls.addProperty("chain", base + "chain.pem");
        urls.addProperty("fullchain", base + "fullchain.pem");
        urls.addProperty("der", base + "certificate.der");
        j.add("urls", urls);
        return j;
    }

    /** {@code GET /api/certificate/<slug>/<serial>}: the certificate's status as JSON. */
    static Api.GetHandler apiHandler(Store store, Clock clock) {
        ChainBuilder chains = new ChainBuilder(store);
        return (request, rest) -> {
            String[] parts = rest.split("/", -1);
            if (parts.length != 2) {
                Api.error(request, 404, "Not Found", "use /api/certificate/<name>/<serial>", false);
                return;
            }
            String problem = RequestPaths.slugProblem(parts[0]);
            if (problem == null) problem = RequestPaths.serialProblem(parts[1]);
            if (problem != null) {
                Api.error(request, 400, "Bad Request", problem, false);
                return;
            }
            EndEntityCert ee = store.signingCert(parts[0]) == null ? null : store.endEntityCert(parts[0], parts[1]);
            if (ee == null) {
                Api.error(request, 404, "Not Found",
                        "no certificate with serial " + parts[1] + " published under " + parts[0], false);
                return;
            }
            Api.json(request, 200, "OK", of(store, chains, ee, clock.instant()).toJson());
        };
    }
}
