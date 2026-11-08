package io.siggi.pkiserver;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class ApiGateTest {
    @TempDir
    Path dir;
    private PKIServer server;
    private final AtomicInteger uploads = new AtomicInteger();

    @AfterEach
    void stopServer() {
        if (server != null) server.stop();
    }

    private void start(String trustedProxies, String limits) throws Exception {
        String json = "{\"listen\": \"127.0.0.1:0\", \"dataDir\": \"data\", \"trustedProxies\": " + trustedProxies
                + (limits == null ? "" : ", \"limits\": " + limits) + "}";
        server = new PKIServer(Config.parse(json, dir));
        server.start();
        server.getApi().registerUpload("/api/test", (request, body) -> {
            uploads.incrementAndGet();
            byte[] reply = ("got " + body.length + " bytes from " + request.getIPAddress())
                    .getBytes(StandardCharsets.UTF_8);
            request.response.setContentType("text/plain");
            request.response.contentLength(reply.length);
            request.response.write(reply);
        });
    }

    record Response(int status, Map<String, String> headers, String body) {
        String error() {
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();
            return json.get("error").getAsString();
        }
    }

    /**
     * Sends a raw request and reads exactly one response (by Content-Length). Doesn't wait for
     * the connection to close: the server may keep it open waiting for a body we never send.
     */
    private Response send(String head, byte[] body) throws IOException {
        try (Socket socket = new Socket("127.0.0.1", server.getPort())) {
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            out.write(head.replace("\n", "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
            if (body != null) out.write(body);
            out.flush();
            return read(socket.getInputStream());
        }
    }

    private static Response read(InputStream in) throws IOException {
        ByteArrayOutputStream headBytes = new ByteArrayOutputStream();
        int matched = 0;
        while (matched < 4) {
            int b = in.read();
            if (b == -1) throw new IOException("connection closed in headers: " + headBytes);
            headBytes.write(b);
            matched = (b == "\r\n\r\n".charAt(matched)) ? matched + 1 : (b == '\r' ? 1 : 0);
        }
        String[] lines = headBytes.toString(StandardCharsets.ISO_8859_1).split("\r\n");
        int status = Integer.parseInt(lines[0].split(" ")[1]);
        Map<String, String> headers = new TreeMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.put(lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT), lines[i].substring(colon + 1).trim());
            }
        }
        String length = headers.get("content-length");
        assertNotNull(length, "response must have a Content-Length: " + headers);
        byte[] body = in.readNBytes(Integer.parseInt(length));
        return new Response(status, headers, new String(body, StandardCharsets.UTF_8));
    }

    private Response post(String path, String extraHeaders, byte[] body) throws IOException {
        return send("POST " + path + " HTTP/1.1\nHost: pki.test\n" + extraHeaders
                + "Content-Length: " + body.length + "\n", body);
    }

    private static final String VIA_PROXY = "X-Forwarded-Proto: https\nX-Forwarded-For: 203.0.113.7\n";
    private static final byte[] BODY = "-----BEGIN CERTIFICATE-----\n".getBytes(StandardCharsets.US_ASCII);

    @Test
    void uploadsDisabledWithoutTrustedProxy() throws Exception {
        start("[]", null);
        Response r = post("/api/test", VIA_PROXY, BODY);
        assertEquals(403, r.status());
        assertTrue(r.error().contains("disabled"), r.error());
        assertEquals(0, uploads.get());
    }

    @Test
    void refusesConnectionsNotFromTrustedProxy() throws Exception {
        // the client is on loopback (which SiggiHTTP itself would take X-Forwarded-* from),
        // but only 10.9.9.9 is configured as our proxy
        start("[\"10.9.9.9\", \"192.168.0.0/16\"]", null);
        Response r = post("/api/test", VIA_PROXY, BODY);
        assertEquals(403, r.status());
        assertTrue(r.error().contains("HTTPS"), r.error());
        assertEquals("close", r.headers().get("connection").toLowerCase(Locale.ROOT));
        assertTrue(r.headers().get("content-type").startsWith("application/json"));
        assertEquals(0, uploads.get());
    }

    @Test
    void requiresForwardedProtoHttpsFromTrustedProxy() throws Exception {
        start("[\"127.0.0.0/8\"]", null);
        assertEquals(403, post("/api/test", "", BODY).status());
        assertEquals(403, post("/api/test", "X-Forwarded-Proto: http\n", BODY).status());
        assertEquals(403, post("/api/test", "X-Forwarded-Proto: httpsx\n", BODY).status());
        // a proxy that appends puts its own value last
        assertEquals(403, post("/api/test", "X-Forwarded-Proto: https, http\n", BODY).status());
        assertEquals(0, uploads.get());

        Response ok = post("/api/test", VIA_PROXY, BODY);
        assertEquals(200, ok.status(), ok.body());
        assertEquals("got " + BODY.length + " bytes from 203.0.113.7", ok.body());
        assertEquals(200, post("/api/test", "X-Forwarded-Proto: http, HTTPS\n", BODY).status());
        assertEquals(2, uploads.get());
    }

    @Test
    void ipv6TrustedProxy() throws Exception {
        start("[\"::1\"]", null);
        // we connect over IPv4 loopback, which is not ::1
        assertEquals(403, post("/api/test", VIA_PROXY, BODY).status());
    }

    @Test
    void everyApiPathIsGated() throws Exception {
        start("[\"10.9.9.9\"]", null);
        for (String path : new String[]{"/api", "/api/", "/api/crl", "/api/crl/tls2", "/api/nothing"}) {
            Response r = send("GET " + path + " HTTP/1.1\nHost: pki.test\n" + VIA_PROXY, null);
            assertEquals(403, r.status(), path);
        }
        // public files stay on plain HTTP
        assertEquals(200, send("GET / HTTP/1.1\nHost: pki.test\n", null).status());
    }

    @Test
    void refusedBeforeBodyIsRead() throws Exception {
        start("[\"10.9.9.9\"]", null);
        String[] contentTypes = {
                "application/pkix-crl",
                "multipart/form-data; boundary=xyz",
        };
        for (String contentType : contentTypes) {
            // announce a large body but never send it: the answer must come anyway
            Response r = send("POST /api/test HTTP/1.1\nHost: pki.test\n" + VIA_PROXY
                    + "Content-Type: " + contentType + "\nContent-Length: 500000\n", null);
            assertEquals(403, r.status(), contentType);
            r = send("POST /api/test HTTP/1.1\nHost: pki.test\n" + VIA_PROXY
                    + "Content-Type: " + contentType + "\nTransfer-Encoding: chunked\n", null);
            assertEquals(403, r.status(), contentType);
        }
        // SiggiHTTP would read form bodies itself before calling us. With the post limit at 1
        // byte it refuses them up front instead and closes the connection (its 413 page is lost
        // because it doesn't flush before closing).
        IOException e = assertThrows(IOException.class, () -> send("POST /api/test HTTP/1.1\nHost: pki.test\n"
                + VIA_PROXY + "Content-Type: application/x-www-form-urlencoded\nContent-Length: 500000\n", null));
        assertTrue(e.getMessage().contains("connection closed"), e.getMessage());
        assertEquals(0, uploads.get());
    }

    @Test
    void bodySizeLimit() throws Exception {
        start("[\"127.0.0.1\"]", "{\"maxUploadBytes\": 100}");
        assertEquals(200, post("/api/test", VIA_PROXY, new byte[100]).status());

        Response r = post("/api/test", VIA_PROXY, new byte[101]);
        assertEquals(413, r.status());
        assertTrue(r.error().contains("100 bytes"), r.error());

        // too large by Content-Length: refused without waiting for the body
        r = send("POST /api/test HTTP/1.1\nHost: pki.test\n" + VIA_PROXY + "Content-Length: 1000000\n", null);
        assertEquals(413, r.status());

        // chunked: refused while reading
        String chunked = "60\r\n" + "x".repeat(0x60) + "\r\n" + "60\r\n" + "x".repeat(0x60) + "\r\n0\r\n\r\n";
        r = send("POST /api/test HTTP/1.1\nHost: pki.test\n" + VIA_PROXY + "Transfer-Encoding: chunked\n",
                chunked.getBytes(StandardCharsets.US_ASCII));
        assertEquals(413, r.status());
        String small = "10\r\n" + "x".repeat(0x10) + "\r\n0\r\n\r\n";
        r = send("POST /api/test HTTP/1.1\nHost: pki.test\n" + VIA_PROXY + "Transfer-Encoding: chunked\n",
                small.getBytes(StandardCharsets.US_ASCII));
        assertEquals(200, r.status());
        assertTrue(r.body().startsWith("got 16 bytes"), r.body());
        assertEquals(2, uploads.get());
    }

    @Test
    void perIpRateLimit() throws Exception {
        start("[\"127.0.0.1\"]", "{\"uploadsPerMinutePerIp\": 2}");
        assertEquals(200, post("/api/test", VIA_PROXY, BODY).status());
        assertEquals(200, post("/api/test", VIA_PROXY, BODY).status());
        Response r = post("/api/test", VIA_PROXY, BODY);
        assertEquals(429, r.status());
        assertEquals("30", r.headers().get("retry-after"));
        assertTrue(r.error().contains("203.0.113.7"), r.error());

        // another client behind the same proxy has its own budget
        String other = "X-Forwarded-Proto: https\nX-Forwarded-For: 198.51.100.1\n";
        assertEquals(200, post("/api/test", other, BODY).status());
        assertEquals(3, uploads.get());
    }

    @Test
    void unknownEndpointAndWrongMethod() throws Exception {
        start("[\"127.0.0.1\"]", null);
        Response r = post("/api/nothing", VIA_PROXY, BODY);
        assertEquals(404, r.status());
        assertEquals("no such API endpoint", r.error());

        r = send("GET /api/test HTTP/1.1\nHost: pki.test\n" + VIA_PROXY, null);
        assertEquals(405, r.status());
        assertEquals("POST", r.headers().get("allow"));
        assertEquals(0, uploads.get());
    }

    @Test
    void keepAliveConnectionHandlesSeveralUploads() throws Exception {
        start("[\"127.0.0.1\"]", null);
        try (Socket socket = new Socket("127.0.0.1", server.getPort())) {
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            for (int i = 0; i < 3; i++) {
                String head = "POST /api/test HTTP/1.1\r\nHost: pki.test\r\nX-Forwarded-Proto: https\r\n"
                        + "Content-Length: " + BODY.length + "\r\n\r\n";
                out.write(head.getBytes(StandardCharsets.US_ASCII));
                out.write(BODY);
                out.flush();
                assertEquals(200, read(in).status());
            }
        }
        assertEquals(3, uploads.get());
    }

    private Response get(String path, String extraHeaders) throws IOException {
        return send("GET " + path + " HTTP/1.1\nHost: pki.test\n" + extraHeaders, null);
    }

    @Test
    void malformedPathsAre400Json() throws Exception {
        start("[\"127.0.0.1\"]", null);
        for (String path : new String[]{"/%2e%2e/data/config.json", "/tls2/%2e%2e/%2e%2e/config.json",
                "/api/crl/%2e%2e", "/api/crl/..%2fx", "/a\\b.der", "/tls2.der%00", "/%C3%A9.der", "/tls2//x",
                "/tls2/", "/./tls2.der", "/api/../tls2.der", "/x:y", "/" + "a".repeat(600)}) {
            Response r = get(path, VIA_PROXY);
            assertEquals(400, r.status(), path);
            assertTrue(r.headers().get("content-type").startsWith("application/json"), path);
            assertFalse(r.error().isEmpty(), path);
        }
        // Malformed API paths are still behind the HTTPS gate.
        assertEquals(403, get("/api/crl/%2e%2e", "").status());
        // Same for uploads: refused before the body is read, without reaching the handler.
        Response r = post("/api/../api/test", VIA_PROXY, BODY);
        assertEquals(400, r.status());
        assertEquals(0, uploads.get());
    }

    @Test
    void malformedSlugOrSerialIs400() throws Exception {
        start("[\"127.0.0.1\"]", null);
        for (String path : new String[]{"/TLS2/a3f1/certificate.pem", "/tls2/00a3f1/chain.pem",
                "/tls2/A3F1/fullchain.pem", "/tls2/a3g1/certificate.der", "/api/crl/TLS2"}) {
            Response r = get(path, VIA_PROXY);
            assertEquals(400, r.status(), path);
            assertTrue(r.error().contains("invalid"), r.error());
        }
        // Not one of our file names: just not found.
        assertEquals(404, get("/.well-known/acme-challenge/token", "").status());
    }

    @Test
    void errorsAreJson() throws Exception {
        start("[\"127.0.0.1\"]", null);
        Response r = get("/nothing-here", "");
        assertEquals(404, r.status());
        assertEquals("not found", r.error());
        assertEquals("no-store", r.headers().get("cache-control"));

        r = post("/", "", BODY);
        assertEquals(405, r.status());
        assertEquals("GET, HEAD, OPTIONS", r.headers().get("allow"));
        assertEquals("use GET", r.error());
    }

    @Test
    void unexpectedFailureIsJson500WithoutDetails() throws Exception {
        start("[\"127.0.0.1\"]", null);
        server.getApi().registerUpload("/api/broken", (request, body) -> {
            throw new IllegalStateException("secret internal detail");
        });
        Response r = post("/api/broken", VIA_PROXY, BODY);
        assertEquals(500, r.status());
        assertTrue(r.headers().get("content-type").startsWith("application/json"));
        assertEquals("internal server error", r.error());
        assertFalse(r.body().contains("secret"), r.body());
        assertEquals("close", r.headers().get("connection").toLowerCase(Locale.ROOT));
    }
}
