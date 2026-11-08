package io.siggi.pkiserver;

import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPResponse;
import io.siggi.pkiserver.store.CaRole;
import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoredCrl;
import io.siggi.pkiserver.x509.X509Util;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;

/**
 * Serves the public, read-only files: signing certificates at {@code /<slug>.der}
 * (alias {@code .crt}) and {@code /<slug>.pem}, their current CRLs at {@code /<slug>.crl} and
 * {@code /<slug>.crl.pem}, and the index page at {@code /}.
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

    PublicFiles(Store store) {
        this.store = store;
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
        if (!path.startsWith("/") || path.indexOf('/', 1) >= 0) return false;
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

    /** Only GET and HEAD; anything else gets a 405. */
    private static boolean allowGet(HTTPRequest request) throws Exception {
        if (request.method.equals("GET") || request.method.equals("HEAD")) return true;
        HTTPResponse response = request.response;
        if (request.method.equals("OPTIONS")) {
            response.setHeader("204 No Content");
        } else {
            response.setHeader("405 Method Not Allowed");
        }
        response.setHeader("Allow", "GET, HEAD, OPTIONS");
        response.contentLength(0);
        response.sendHeaders();
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
                    .append("<th>Download</th><th>CRL</th><th>CRL coverage until</th></tr>\n");
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

        List<StoredCrl> crls = store.crls(slug);
        StoredCrl current = null;
        int pending = 0;
        Instant coverage = null;
        for (StoredCrl crl : crls) {
            if (crl.state() == CrlState.CURRENT) current = crl;
            if (crl.state() == CrlState.PENDING) pending++;
            if ((crl.state() == CrlState.CURRENT || crl.state() == CrlState.PENDING) && crl.nextUpdate() != null
                    && (coverage == null || crl.nextUpdate().isAfter(coverage))) {
                coverage = crl.nextUpdate();
            }
        }
        sb.append("<td>");
        if (current == null) {
            sb.append("<span class=\"muted\">none</span>");
        } else {
            sb.append("<a href=\"").append(href).append(".crl\">#").append(current.number()).append("</a>")
                    .append(" (<a href=\"").append(href).append(".crl.pem\">PEM</a>), next update ");
            sb.append(current.nextUpdate() == null ? "none" : DISPLAY_DATE.format(current.nextUpdate()));
            if (current.nextUpdate() != null && now.isAfter(current.nextUpdate())) {
                sb.append(" <span class=\"warn\">stale</span>");
            }
        }
        if (pending > 0) {
            sb.append("<br>").append(pending).append(" pending");
        }
        sb.append("</td><td>");
        if (coverage == null) {
            sb.append("<span class=\"muted\">&ndash;</span>");
        } else {
            sb.append(DISPLAY_DATE.format(coverage));
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
