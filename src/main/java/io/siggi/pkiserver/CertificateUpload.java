package io.siggi.pkiserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.siggi.http.HTTPRequest;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoreException;
import io.siggi.pkiserver.x509.InvalidX509Exception;
import io.siggi.pkiserver.x509.X509Util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * {@code POST /api/certificate}: uploads of signing (CA) and end-entity certificates.
 * <p>
 * The body is one DER certificate or PEM with one or more. Each {@code CA:TRUE} certificate
 * is published under the slug derived from its subject CN if it chains to an installed root
 * through installed intermediates ({@link ChainValidator}), has {@code keyCertSign} (when it
 * has a Key Usage extension), isn't expired, and its slug is free. Re-uploading a certificate
 * that is already installed is a no-op.
 * <p>
 * Every other certificate is an end-entity certificate. It is published under the slug of its
 * issuing signing certificate, by serial, if it chains to an installed root through installed
 * intermediates (certificates in the body are only used for this once they are installed
 * themselves), isn't revoked by a current CRL on the path and isn't expired. Re-uploading the
 * identical certificate is a no-op; a different certificate with the same issuer and serial
 * is a {@code 409} conflict.
 * <p>
 * The certificates of one body are processed together: one whose issuer is installed by an
 * earlier certificate of the same body is retried, so a chain can be uploaded in any order.
 * <p>
 * The response is JSON with one result per certificate. Its status is {@code 200} if all were
 * accepted, otherwise {@code 409} if every rejection was a slug conflict, else {@code 400}.
 */
final class CertificateUpload implements Api.UploadHandler {
    private static final Logger log = Logging.get(CertificateUpload.class);

    static final String PATH = Api.PREFIX + "/certificate";

    private final Store store;
    private final ChainValidator validator;
    private final Clock clock;

    CertificateUpload(Store store, Clock clock) {
        this.store = store;
        this.validator = new ChainValidator(store);
        this.clock = clock;
    }

    /** Result of processing one certificate. */
    private record Outcome(String result, int status, String slug, String error, boolean retryable,
                           boolean endEntity) {
        static Outcome installed(String slug) {
            return new Outcome("installed", 200, slug, null, false, false);
        }

        static Outcome unchanged(String slug) {
            return new Outcome("unchanged", 200, slug, null, false, false);
        }

        static Outcome published(String slug) {
            return new Outcome("published", 200, slug, null, false, true);
        }

        static Outcome unchangedEndEntity(String slug) {
            return new Outcome("unchanged", 200, slug, null, false, true);
        }

        static Outcome rejected(int status, String slug, String error) {
            return new Outcome("rejected", status, slug, error, false, false);
        }

        static Outcome retryable(String error) {
            return new Outcome("rejected", 400, null, error, true, false);
        }

        boolean accepted() {
            return status == 200;
        }
    }

    @Override
    public void handle(HTTPRequest request, byte[] body) throws Exception {
        List<X509Certificate> certs;
        try {
            certs = X509Util.parseCertificates(body);
        } catch (InvalidX509Exception e) {
            Api.error(request, 400, "Bad Request", "could not parse certificate: " + e.getMessage(), false);
            return;
        }

        Outcome[] outcomes = new Outcome[certs.size()];
        boolean progress = true;
        while (progress) {
            progress = false;
            for (int i = 0; i < certs.size(); i++) {
                if (outcomes[i] != null && !outcomes[i].retryable()) continue;
                outcomes[i] = process(certs.get(i));
                if (outcomes[i].result().equals("installed")) progress = true;
            }
        }

        JsonArray results = new JsonArray();
        boolean allAccepted = true;
        boolean onlyConflicts = true;
        for (int i = 0; i < certs.size(); i++) {
            Outcome o = outcomes[i];
            results.add(toJson(certs.get(i), o));
            if (!o.accepted()) {
                allAccepted = false;
                if (o.status() != 409) onlyConflicts = false;
            }
        }
        JsonObject json = new JsonObject();
        json.add("certificates", results);
        if (allAccepted) {
            Api.json(request, 200, "OK", json);
        } else if (onlyConflicts) {
            json.addProperty("error", firstError(outcomes));
            Api.json(request, 409, "Conflict", json);
        } else {
            json.addProperty("error", firstError(outcomes));
            Api.json(request, 400, "Bad Request", json);
        }
    }

    private static String firstError(Outcome[] outcomes) {
        for (Outcome o : outcomes) {
            if (o.error() != null) return o.error();
        }
        return null;
    }

    private Outcome process(X509Certificate cert) throws IOException {
        if (cert.getBasicConstraints() < 0) return processEndEntity(cert);
        String sha256 = X509Util.sha256Hex(X509Util.der(cert));
        for (SigningCert sc : store.signingCerts()) {
            if (sc.sha256().equals(sha256)) return Outcome.unchanged(sc.slug());
        }
        if (isSelfSigned(cert)) {
            return Outcome.rejected(400, null,
                    "root certificates can't be uploaded; the server admin installs roots with the admin CLI");
        }
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5])) {
            return Outcome.rejected(400, null, "Key Usage does not include keyCertSign");
        }
        try {
            validator.validate(cert, clock.instant());
        } catch (ChainValidator.ValidationException e) {
            return Outcome.retryable(e.getMessage());
        }

        String cn = X509Util.commonName(cert.getSubjectX500Principal());
        String slug = X509Util.slugFor(cert);
        if (slug.isEmpty()) {
            return Outcome.rejected(400, null, cn == null
                    ? "the subject has no CN to derive a slug from"
                    : "the CN \"" + cn + "\" has no URL-safe characters to derive a slug from");
        }
        String slugProblem = Slugs.problem(slug);
        if (slugProblem != null) return Outcome.rejected(400, slug, slugProblem);
        SigningCert taken = store.signingCert(slug);
        if (taken != null) {
            return Outcome.rejected(409, slug, "slug \"" + slug + "\" is already taken by a different certificate ("
                    + taken.subject().getName() + ", serial " + X509Util.formatSerial(taken.cert().getSerialNumber())
                    + "); a renewed or cross-signed CA needs a different CN");
        }
        try {
            store.addSigningCert(slug, cert);
        } catch (StoreException e) {
            return Outcome.rejected(409, slug, e.getMessage());
        }
        log.info("Published uploaded signing certificate " + cert.getSubjectX500Principal().getName()
                + " as \"" + slug + "\"");
        return Outcome.installed(slug);
    }

    private Outcome processEndEntity(X509Certificate cert) throws IOException {
        List<SigningCert> path;
        try {
            path = validator.validate(cert, clock.instant());
        } catch (ChainValidator.ValidationException e) {
            return Outcome.retryable(e.getMessage());
        }
        String slug = path.get(0).slug();
        String serial = X509Util.formatSerial(cert.getSerialNumber());
        boolean added;
        try {
            added = store.addEndEntityCert(slug, cert, clock.instant());
        } catch (StoreException e) {
            String message = store.endEntityCert(slug, serial) != null
                    ? "a different certificate with issuer " + cert.getIssuerX500Principal().getName()
                    + " and serial " + serial + " is already published under \"" + slug
                    + "\"; serial numbers must be unique per issuer"
                    : e.getMessage();
            return Outcome.rejected(409, slug, message);
        }
        if (!added) return Outcome.unchangedEndEntity(slug);
        log.info("Published end-entity certificate " + cert.getSubjectX500Principal().getName()
                + " under \"" + slug + "\" as " + serial);
        return Outcome.published(slug);
    }

    private static boolean isSelfSigned(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) return false;
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    private static JsonObject toJson(X509Certificate cert, Outcome o) {
        JsonObject j = new JsonObject();
        j.addProperty("subject", cert.getSubjectX500Principal().getName());
        j.addProperty("serial", X509Util.formatSerial(cert.getSerialNumber()));
        j.addProperty("result", o.result());
        if (o.slug() != null) j.addProperty("slug", o.slug());
        if (o.error() != null) j.addProperty("error", o.error());
        if (o.accepted()) {
            Instant notBefore = cert.getNotBefore().toInstant();
            j.addProperty("notBefore", notBefore.toString());
            j.addProperty("notAfter", cert.getNotAfter().toInstant().toString());
            JsonObject urls = new JsonObject();
            if (o.endEntity()) {
                String base = "/" + o.slug() + "/" + X509Util.formatSerial(cert.getSerialNumber()) + "/";
                urls.addProperty("certificate", base + "certificate.pem");
                urls.addProperty("chain", base + "chain.pem");
                urls.addProperty("fullchain", base + "fullchain.pem");
            } else {
                urls.addProperty("der", "/" + o.slug() + ".der");
                urls.addProperty("crt", "/" + o.slug() + ".crt");
                urls.addProperty("pem", "/" + o.slug() + ".pem");
            }
            j.add("urls", urls);
        }
        return j;
    }
}
