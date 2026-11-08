package io.siggi.pkiserver;

import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPResponse;
import io.siggi.pkiserver.store.CaRole;
import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.EndEntityCert;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoredCrl;
import io.siggi.pkiserver.x509.X509Util;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Serves the public, read-only files: signing certificates at {@code /<slug>.der}
 * (alias {@code .crt}) and {@code /<slug>.pem}, their current CRLs at {@code /<slug>.crl} and
 * {@code /<slug>.crl.pem}, end-entity certificates at
 * {@code /<slug>/<serial>/{certificate,chain,fullchain}.pem} and {@code certificate.der}, and the
 * index page at {@code /}.
 * <p>
 * A current CRL that is past its {@code nextUpdate} is still served (better than a 404), with
 * {@code max-age=0}; the index page flags it as stale and the {@link CrlScheduler} logs it.
 */
final class PublicFiles {
    static final String PKIX_CERT = "application/pkix-cert";
    static final String PKIX_CRL = "application/pkix-crl";
    static final String PEM = "application/x-pem-file";
    static final String HTML = "text/html; charset=utf-8";
    /** Signing certificates don't change under a slug, but can be removed: cache for an hour. */
    static final long CERT_MAX_AGE_SECONDS = 3600;
    /**
     * Cap on a CRL's max-age, so a newly uploaded CRL (e.g. an emergency revocation) propagates
     * quickly. The max-age also never extends past the CRL's nextUpdate, nor past the moment a
     * pending CRL takes over.
     */
    static final long CRL_MAX_AGE_SECONDS = 3600;

    private static final DateTimeFormatter HTTP_DATE = DateTimeFormatter.RFC_1123_DATE_TIME.withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DISPLAY_DATE =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.ROOT).withZone(ZoneOffset.UTC);

    private final Store store;
    private final Duration coverageWarning;
    private final ChainBuilder chains;

    PublicFiles(Store store, Duration coverageWarning) {
        this.store = store;
        this.coverageWarning = coverageWarning;
        this.chains = new ChainBuilder(store);
    }

    /**
     * Handles {@code request} if its path is one of ours.
     *
     * @return false if the path isn't a public file (the caller sends a 404)
     */
    boolean handle(HTTPRequest request) throws Exception {
        String path = request.url;
        if (path.equals("/") || path.equals("/index.html")) {
            if (!allowGet(request)) return true;
            serveIndex(request);
            return true;
        }
        if (!path.startsWith("/")) return false;
        if (path.indexOf('/', 1) >= 0) return handleEndEntity(request, path);
        String name = path.substring(1);
        // Longest suffix first: "/tls2.crl.pem" is tls2's CRL, unless there is no "tls2" but
        // there is a (hand-installed) "tls2.crl", in which case it's that one's certificate.
        for (Format format : Format.values()) {
            if (!name.endsWith(format.suffix)) continue;
            String slug = name.substring(0, name.length() - format.suffix.length());
            if (!Store.isStorableSlug(slug)) continue;
            SigningCert cert = store.signingCert(slug);
            if (cert == null) continue;
            if (format.crl) {
                StoredCrl crl = store.currentCrl(slug);
                if (crl == null) return false;
                if (!allowGet(request)) return true;
                serveCrl(request, slug, crl, format);
            } else {
                if (!allowGet(request)) return true;
                serveCert(request, cert, format);
            }
            return true;
        }
        return false;
    }

    /** The files published for an end-entity certificate, by name. */
    private enum EeFile {
        CERTIFICATE_PEM("certificate.pem"), CERTIFICATE_DER("certificate.der"),
        CHAIN_PEM("chain.pem"), FULLCHAIN_PEM("fullchain.pem");

        final String name;

        EeFile(String name) {
            this.name = name;
        }

        static EeFile of(String name) {
            for (EeFile f : values()) if (f.name.equals(name)) return f;
            return null;
        }
    }

    /**
     * {@code /<slug>/<serial>/<file>}. For one of our file names, a malformed slug or serial is a
     * 400; any other path, or an unknown slug/serial/file, is a 404.
     */
    private boolean handleEndEntity(HTTPRequest request, String path) throws Exception {
        String[] parts = path.substring(1).split("/", -1);
        if (parts.length != 3) return false;
        String slug = parts[0];
        String serial = parts[1];
        EeFile file = EeFile.of(parts[2]);
        if (file == null) return false;
        String problem = RequestPaths.slugProblem(slug);
        if (problem == null) problem = RequestPaths.serialProblem(serial);
        if (problem != null) {
            Api.error(request, 400, "Bad Request", problem, !isGetOrHead(request));
            return true;
        }
        EndEntityCert ee = store.endEntityCert(slug, serial);
        if (ee == null || store.signingCert(slug) == null) return false;
        byte[] body;
        String contentType = PEM;
        String etag;
        Instant lastModified = ee.uploadedAt();
        switch (file) {
            case CERTIFICATE_DER -> {
                body = ee.der();
                contentType = PKIX_CERT;
                etag = "\"" + ee.sha256() + "\"";
            }
            case CERTIFICATE_PEM -> {
                body = X509Util.pem(ee.cert()).getBytes(StandardCharsets.US_ASCII);
                etag = "\"" + ee.sha256() + "-pem\"";
            }
            default -> {
                List<SigningCert> chain = chains.chain(slug);
                // No path of installed certificates to a root (e.g. one was removed): not published.
                if (chain == null) return false;
                List<X509Certificate> certs = new ArrayList<>();
                if (file == EeFile.FULLCHAIN_PEM) certs.add(ee.cert());
                for (SigningCert sc : chain) {
                    certs.add(sc.cert());
                    Instant modified = store.signingCertModified(sc.slug());
                    if (modified != null && (lastModified == null || modified.isAfter(lastModified))) {
                        lastModified = modified;
                    }
                }
                body = X509Util.pem(certs).getBytes(StandardCharsets.US_ASCII);
                // Built at serve time, so the ETag covers exactly what's sent.
                etag = "\"" + X509Util.sha256Hex(body) + "\"";
            }
        }
        if (!allowGet(request)) return true;
        request.response.setHeader("Cache-Control", "public, max-age=" + CERT_MAX_AGE_SECONDS);
        if (lastModified != null && lastModified.isAfter(Instant.now())) lastModified = Instant.now();
        send(request, contentType, body, etag, lastModified);
        return true;
    }

    /** Lowercase hex, no leading zeros, as produced by {@code X509Util.formatSerial}. */
    static boolean isFormattedSerial(String serial) {
        if (serial.isEmpty()) return false;
        if (serial.length() > 1 && serial.charAt(0) == '0') return false;
        for (int i = 0; i < serial.length(); i++) {
            char c = serial.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    /** URL suffixes, longest first. */
    private enum Format {
        CRL_PEM(".crl.pem", true, true), CRL(".crl", true, false),
        DER(".der", false, false), CRT(".crt", false, false), PEM(".pem", false, true);

        final String suffix;
        final boolean crl;
        final boolean pem;

        Format(String suffix, boolean crl, boolean pem) {
            this.suffix = suffix;
            this.crl = crl;
            this.pem = pem;
        }
    }

    private void serveCert(HTTPRequest request, SigningCert cert, Format format) throws Exception {
        byte[] body;
        String contentType;
        if (format.pem) {
            body = X509Util.pem(cert.cert()).getBytes(StandardCharsets.US_ASCII);
            contentType = PEM;
        } else {
            body = cert.der();
            contentType = PKIX_CERT;
        }
        // The ETag identifies the certificate; PEM and DER are different representations.
        String etag = "\"" + cert.sha256() + (format.pem ? "-pem" : "") + "\"";
        Instant lastModified = store.signingCertModified(cert.slug());
        HTTPResponse response = request.response;
        response.setHeader("Cache-Control", "public, max-age=" + CERT_MAX_AGE_SECONDS);
        send(request, contentType, body, etag, lastModified);
    }

    private void serveCrl(HTTPRequest request, String slug, StoredCrl crl, Format format) throws Exception {
        byte[] body;
        String contentType;
        if (format.pem) {
            body = X509Util.pem(crl.crl()).getBytes(StandardCharsets.US_ASCII);
            contentType = PEM;
        } else {
            body = crl.der();
            contentType = PKIX_CRL;
        }
        String etag = "\"" + crl.sha256() + (format.pem ? "-pem" : "") + "\"";
        Instant now = Instant.now();
        Instant nextPending = null;
        for (StoredCrl c : store.crls(slug)) {
            if (c.state() == CrlState.PENDING && (nextPending == null || c.thisUpdate().isBefore(nextPending))) {
                nextPending = c.thisUpdate();
            }
        }
        long maxAge = crlMaxAge(now, crl.nextUpdate(), nextPending);
        request.response.setHeader("Cache-Control", "public, max-age=" + maxAge);
        send(request, contentType, body, etag, crlPublished(crl, now));
    }

    /**
     * Seconds a CRL may be cached: at most {@link #CRL_MAX_AGE_SECONDS}, never past its
     * {@code nextUpdate} nor past the moment the next pending CRL takes effect, and 0 once stale.
     */
    static long crlMaxAge(Instant now, Instant nextUpdate, Instant nextPendingThisUpdate) {
        long maxAge = CRL_MAX_AGE_SECONDS;
        if (nextUpdate != null) maxAge = Math.min(maxAge, secondsUntil(now, nextUpdate));
        if (nextPendingThisUpdate != null) maxAge = Math.min(maxAge, secondsUntil(now, nextPendingThisUpdate));
        return maxAge;
    }

    private static long secondsUntil(Instant now, Instant then) {
        if (!then.isAfter(now)) return 0;
        // Round down, so the cache entry expires at or before the deadline.
        return Math.max(0, then.getEpochSecond() - now.getEpochSecond() - (now.getNano() > 0 ? 1 : 0));
    }

    /**
     * When the CRL started being served at its URL: when it was received, or for a pre-signed
     * CRL, its thisUpdate (when it got promoted). Never in the future.
     */
    static Instant crlPublished(StoredCrl crl, Instant now) {
        Instant t = crl.receivedAt();
        if (crl.thisUpdate() != null && (t == null || crl.thisUpdate().isAfter(t))) t = crl.thisUpdate();
        if (t == null || t.isAfter(now)) t = now;
        return t;
    }

    private void serveIndex(HTTPRequest request) throws Exception {
        byte[] body = indexHtml(Instant.now()).getBytes(StandardCharsets.UTF_8);
        String etag = "\"" + X509Util.sha256Hex(body) + "\"";
        request.response.setHeader("Cache-Control", "no-cache");
        send(request, HTML, body, etag, null);
    }

    /** Sends {@code body}, or a 304 if the client's conditional headers say it has it. */
    private static void send(HTTPRequest request, String contentType, byte[] body, String etag, Instant lastModified)
            throws Exception {
        HTTPResponse response = request.response;
        response.setHeader("ETag", etag);
        if (lastModified != null) {
            lastModified = lastModified.truncatedTo(ChronoUnit.SECONDS);
            response.setHeader("Last-Modified", HTTP_DATE.format(lastModified));
        }
        if (notModified(request, etag, lastModified)) {
            response.setHeader("304 Not Modified");
            response.sendHeaders();
            return;
        }
        response.setHeader("200 OK");
        response.setContentType(contentType);
        response.contentLength(body.length);
        response.write(body);
    }

    static boolean notModified(HTTPRequest request, String etag, Instant lastModified) {
        String ifNoneMatch = request.getHeader("If-None-Match");
        if (ifNoneMatch != null) {
            // If-None-Match takes precedence over If-Modified-Since (RFC 9110 13.2.2).
            for (String tag : ifNoneMatch.split(",")) {
                tag = tag.trim();
                if (tag.startsWith("W/")) tag = tag.substring(2);
                if (tag.equals("*") || tag.equals(etag)) return true;
            }
            return false;
        }
        String ifModifiedSince = request.getHeader("If-Modified-Since");
        if (ifModifiedSince != null && lastModified != null) {
            try {
                Instant since = Instant.from(HTTP_DATE.parse(ifModifiedSince.trim()));
                return !lastModified.isAfter(since);
            } catch (DateTimeParseException e) {
                return false;
            }
        }
        return false;
    }

    static boolean isGetOrHead(HTTPRequest request) {
        return request.method.equals("GET") || request.method.equals("HEAD");
    }

    /** Only GET and HEAD (and OPTIONS); anything else gets a 405. */
    private static boolean allowGet(HTTPRequest request) throws Exception {
        if (isGetOrHead(request)) return true;
        HTTPResponse response = request.response;
        response.setHeader("Allow", "GET, HEAD, OPTIONS");
        if (request.method.equals("OPTIONS")) {
            response.setHeader("204 No Content");
            response.contentLength(0);
            response.sendHeaders();
        } else {
            // The body (if any) isn't read: close the connection after answering.
            Api.error(request, 405, "Method Not Allowed", "use GET", true);
        }
        return false;
    }

    // ------------------------------------------------------------------ index page

    String indexHtml(Instant now) {
        List<SigningCert> certs = store.signingCerts();
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
                .append("<title>PKI</title>\n<style>\n")
                .append("body{font-family:system-ui,sans-serif;margin:2em;color:#222}")
                .append("table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:.4em .6em;")
                .append("text-align:left;vertical-align:top}th{background:#f4f4f4}")
                .append(".warn{color:#a40000;font-weight:bold}.muted{color:#777}code{font-size:.9em}\n")
                .append("</style>\n</head>\n<body>\n<h1>Signing certificates</h1>\n");
        if (certs.isEmpty()) {
            sb.append("<p class=\"muted\">No signing certificates are installed.</p>\n");
        } else {
            sb.append("<table>\n<tr><th>Name</th><th>Subject</th><th>Role</th><th>Issuer</th><th>Validity</th>")
                    .append("<th>Download</th><th>Current CRL</th><th>Pending CRLs</th>")
                    .append("<th>Highest CRL number</th><th>CRL coverage until</th></tr>\n");
            for (SigningCert cert : certs) {
                appendRow(sb, cert, now);
            }
            sb.append("</table>\n");
        }
        sb.append("<p class=\"muted\">Generated ").append(DISPLAY_DATE.format(now)).append("</p>\n")
                .append("</body>\n</html>\n");
        return sb.toString();
    }

    private void appendRow(StringBuilder sb, SigningCert cert, Instant now) {
        String slug = cert.slug();
        Instant notBefore = cert.cert().getNotBefore().toInstant();
        Instant notAfter = cert.cert().getNotAfter().toInstant();
        sb.append("<tr id=\"").append(esc(slug)).append("\">");
        sb.append("<td><code>").append(esc(slug)).append("</code></td>");
        sb.append("<td>").append(esc(cert.subject().getName())).append("</td>");
        sb.append("<td>").append(cert.role().id()).append("</td>");
        sb.append("<td>").append(esc(issuerName(cert))).append("</td>");
        sb.append("<td>").append(DISPLAY_DATE.format(notBefore)).append(" &ndash;<br>")
                .append(DISPLAY_DATE.format(notAfter));
        if (now.isBefore(notBefore)) sb.append("<br><span class=\"muted\">not yet valid</span>");
        if (now.isAfter(notAfter)) sb.append("<br><span class=\"warn\">expired</span>");
        sb.append("</td>");
        String href = esc(urlPart(slug));
        sb.append("<td><a href=\"").append(href).append(".der\">DER</a> &middot; <a href=\"")
                .append(href).append(".pem\">PEM</a></td>");

        CrlCoverage coverage = CrlCoverage.of(store, slug, now, coverageWarning);
        StoredCrl current = coverage.current();
        sb.append("<td>");
        if (current == null) {
            sb.append("<span class=\"muted\">none</span>");
        } else {
            sb.append("<a href=\"").append(href).append(".crl\">#").append(current.number()).append("</a>")
                    .append(" (<a href=\"").append(href).append(".crl.pem\">PEM</a>), next update ");
            sb.append(current.nextUpdate() == null ? "none" : DISPLAY_DATE.format(current.nextUpdate()));
            if (coverage.stale()) {
                sb.append(" <span class=\"warn\">stale</span>");
            }
        }
        sb.append("</td><td>");
        if (coverage.pending().isEmpty()) {
            sb.append("<span class=\"muted\">none</span>");
        } else {
            boolean first = true;
            for (StoredCrl crl : coverage.pending()) {
                if (!first) sb.append("<br>");
                first = false;
                sb.append("#").append(crl.number()).append(": ").append(DISPLAY_DATE.format(crl.thisUpdate()))
                        .append(" &ndash; ")
                        .append(crl.nextUpdate() == null ? "none" : DISPLAY_DATE.format(crl.nextUpdate()));
            }
        }
        sb.append("</td><td>");
        if (coverage.highestNumber() == null) {
            sb.append("<span class=\"muted\">none</span>");
        } else {
            sb.append("#").append(coverage.highestNumber())
                    .append("<br><span class=\"muted\">next: #").append(coverage.nextNumber()).append("</span>");
        }
        sb.append("</td><td>");
        if (coverage.coverageUntil() == null) {
            sb.append("<span class=\"muted\">&ndash;</span>");
        } else {
            sb.append(DISPLAY_DATE.format(coverage.coverageUntil()));
            if (coverage.warning()) {
                Duration remaining = coverage.remaining();
                sb.append("<br><span class=\"warn\">");
                if (remaining.isNegative() || remaining.isZero()) {
                    sb.append("coverage has run out");
                } else {
                    long days = remaining.toDays();
                    sb.append("coverage runs out in ")
                            .append(days > 0 ? days + (days == 1 ? " day" : " days")
                                    : remaining.toHours() + (remaining.toHours() == 1 ? " hour" : " hours"));
                }
                sb.append("</span>");
            }
        }
        sb.append("</td></tr>\n");
    }

    /** The issuer's slug if it's on the server, otherwise its DN. */
    private String issuerName(SigningCert cert) {
        if (cert.role() == CaRole.ROOT) return "(self-signed)";
        for (SigningCert candidate : store.signingCertsBySubject(cert.cert().getIssuerX500Principal())) {
            try {
                cert.cert().verify(candidate.cert().getPublicKey());
                return candidate.slug();
            } catch (Exception ignored) {
            }
        }
        return cert.cert().getIssuerX500Principal().getName();
    }

    /** Slugs contain only unreserved characters, but be safe in case of hand-made directories. */
    private static String urlPart(String slug) {
        return "/" + URLEncoder.encode(slug, StandardCharsets.UTF_8).replace("+", "%20");
    }

    static String esc(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }
}
