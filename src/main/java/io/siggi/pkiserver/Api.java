package io.siggi.pkiserver;

import com.google.gson.JsonObject;
import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPResponse;
import io.siggi.http.iphelper.IP;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * The {@code /api/*} endpoints, behind the HTTPS-only gate.
 * <p>
 * Uploads are unauthenticated, so they must only arrive over HTTPS. TLS is terminated by a
 * reverse proxy, so a request is let through only when the TCP connection comes from one of
 * the configured trusted proxies <em>and</em> that proxy says the client used HTTPS
 * ({@code X-Forwarded-Proto: https}). Everything else gets {@code 403} without its body being
 * read. With no trusted proxy configured, the API is disabled.
 * <p>
 * After the gate, uploads (POST) are rate limited per client IP and their bodies are limited
 * to {@link Config.Limits#maxUploadBytes()}.
 */
final class Api {
    private static final Logger log = Logging.get(Api.class);

    static final String PREFIX = "/api";
    static final String JSON = "application/json; charset=utf-8";

    /** Handles an upload whose body has passed the gate, rate limit and size limit. */
    @FunctionalInterface
    interface UploadHandler {
        void handle(HTTPRequest request, byte[] body) throws Exception;
    }

    private final Config config;
    private final List<IP> trustedProxies;
    private final RateLimiter rateLimiter;
    private final Map<String, UploadHandler> uploads = new ConcurrentHashMap<>();

    Api(Config config) {
        this(config, new RateLimiter(config.limits().uploadsPerMinutePerIp()));
    }

    Api(Config config, RateLimiter rateLimiter) {
        this.config = config;
        List<IP> proxies = new ArrayList<>();
        for (String proxy : config.trustedProxies()) {
            proxies.add(IP.getIP(proxy));
        }
        this.trustedProxies = List.copyOf(proxies);
        this.rateLimiter = rateLimiter;
    }

    static boolean isApiPath(String path) {
        return path.equals(PREFIX) || path.startsWith(PREFIX + "/");
    }

    /** Registers the upload endpoint {@code POST <path>}, e.g. {@code /api/crl}. */
    void registerUpload(String path, UploadHandler handler) {
        if (!isApiPath(path)) throw new IllegalArgumentException("not an API path: " + path);
        uploads.put(path, handler);
    }

    /**
     * Handles a request for an {@link #isApiPath API path}.
     *
     * @param peer the address the TCP connection actually comes from (not X-Forwarded-For)
     */
    void handle(HTTPRequest request, InetAddress peer) throws Exception {
        String refusal = httpsRefusal(request, peer);
        if (refusal != null) {
            log.fine(() -> "Refused " + request.method + " " + request.url + " from " + peer.getHostAddress()
                    + ": " + refusal);
            error(request, 403, "Forbidden", refusal, true);
            return;
        }

        UploadHandler upload = uploads.get(request.url);
        if (upload == null) {
            error(request, 404, "Not Found", "no such API endpoint", true);
            return;
        }
        if (!request.method.equals("POST")) {
            request.response.setHeader("Allow", "POST");
            error(request, 405, "Method Not Allowed", "use POST", true);
            return;
        }

        String client = request.getIPAddress();
        if (!rateLimiter.tryAcquire(client)) {
            long retryAfter = rateLimiter.retryAfterSeconds(client);
            log.info("Rate limited upload from " + client + " to " + request.url);
            request.response.setHeader("Retry-After", Long.toString(retryAfter));
            error(request, 429, "Too Many Requests",
                    "too many uploads from " + client + ", try again in " + retryAfter + " s", true);
            return;
        }

        byte[] body;
        try {
            body = readBody(request, config.limits().maxUploadBytes());
        } catch (TooLargeException e) {
            error(request, 413, "Content Too Large",
                    "upload exceeds the limit of " + config.limits().maxUploadBytes() + " bytes", true);
            return;
        }
        upload.handle(request, body);
    }

    /**
     * Why {@code request} doesn't count as having arrived over HTTPS through a trusted proxy,
     * or null if it does. Looks only at the connection and the headers, never the body.
     */
    String httpsRefusal(HTTPRequest request, InetAddress peer) {
        if (trustedProxies.isEmpty()) {
            return "uploads are disabled on this server (no trusted HTTPS proxy is configured)";
        }
        if (!isTrustedProxy(peer)) {
            return "the API is only available over HTTPS";
        }
        if (!"https".equalsIgnoreCase(forwardedProto(request))) {
            return "the API is only available over HTTPS";
        }
        return null;
    }

    boolean isTrustedProxy(InetAddress peer) {
        String address = peer.getHostAddress();
        int scope = address.indexOf('%');
        if (scope >= 0) address = address.substring(0, scope);
        IP ip;
        try {
            ip = IP.getIP(address);
        } catch (RuntimeException e) {
            return false;
        }
        for (IP proxy : trustedProxies) {
            if (proxy.contains(ip)) return true;
        }
        return false;
    }

    /**
     * The protocol set by the proxy that connected to us: the last value of the last
     * {@code X-Forwarded-Proto} header, since a proxy that appends rather than replaces puts
     * its own value after whatever the client sent.
     */
    static String forwardedProto(HTTPRequest request) {
        List<String> values = request.getHeaders("X-Forwarded-Proto");
        if (values == null || values.isEmpty()) return null;
        String last = values.get(values.size() - 1);
        if (last == null) return null;
        int comma = last.lastIndexOf(',');
        return last.substring(comma + 1).trim();
    }

    /**
     * Reads the request body, refusing it as soon as it's known to exceed {@code max} bytes:
     * from {@code Content-Length} before reading anything, otherwise (chunked) while reading.
     */
    static byte[] readBody(HTTPRequest request, long max) throws IOException, TooLargeException {
        List<String> lengths = request.getHeaders("Content-Length");
        if (lengths != null) {
            for (String value : lengths) {
                try {
                    if (Long.parseLong(value.trim()) > max) throw new TooLargeException();
                } catch (NumberFormatException e) {
                    throw new TooLargeException();
                }
            }
        }
        InputStream in = request.getInputStream();
        if (in == null) return new byte[0];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(buffer)) != -1) {
            total += n;
            if (total > max) throw new TooLargeException();
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    static final class TooLargeException extends Exception {
        TooLargeException() {
            super(null, null, false, false);
        }
    }

    /** Sends a JSON response. */
    static void json(HTTPRequest request, int status, String reason, JsonObject json) throws IOException {
        byte[] body = (json + "\n").getBytes(StandardCharsets.UTF_8);
        HTTPResponse response = request.response;
        response.setHeader(status + " " + reason);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType(JSON);
        response.contentLength(body.length);
        if (!request.method.equals("HEAD")) response.write(body);
    }

    /**
     * Sends a JSON error. With {@code closeConnection}, the connection is closed afterwards so
     * that a body we didn't read can't be mistaken for the next request.
     */
    static void error(HTTPRequest request, int status, String reason, String message, boolean closeConnection)
            throws IOException {
        JsonObject json = new JsonObject();
        json.addProperty("error", message);
        byte[] body = (json + "\n").getBytes(StandardCharsets.UTF_8);
        HTTPResponse response = request.response;
        response.setHeader(status + " " + reason);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType(JSON);
        if (closeConnection) response.keepAlive(false);
        response.contentLength(body.length);
        if (!request.method.equals("HEAD")) response.write(body);
    }
}
