package io.siggi.pkiserver;

import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.x509.X509Util;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class PublicFilesTest {
    private static KeyPair rootKey;
    private static X509Certificate root;
    private static X509Certificate inter;
    private static X509Certificate leaf;
    private static X509Certificate rootLeaf;

    @TempDir
    Path dir;
    private PKIServer server;
    private HttpClient client;

    @BeforeAll
    static void setUpCerts() throws Exception {
        rootKey = keyPair();
        KeyPair interKey = keyPair();
        root = cert("CN=Siggi.io", rootKey.getPublic(), "CN=Siggi.io", rootKey);
        inter = cert("CN=TLS 2,O=<Script & Co>", interKey.getPublic(), "CN=Siggi.io", rootKey);
        leaf = cert("CN=www.example.com", keyPair().getPublic(), "CN=TLS 2,O=<Script & Co>", interKey,
                new BigInteger("00a3f1", 16), false);
        rootLeaf = cert("CN=direct.example.com", keyPair().getPublic(), "CN=Siggi.io", rootKey,
                BigInteger.valueOf(0x1234), false);
    }

    @BeforeEach
    void startServer() throws Exception {
        Path dataDir = dir.resolve("data");
        Store store = Store.open(dataDir);
        store.addSigningCert("siggi.io", root);
        store.addSigningCert("tls2", inter);
        store.addCrl("siggi.io", crl(), CrlState.CURRENT, Instant.now());
        store.addEndEntityCert("tls2", leaf, Instant.now());
        store.addEndEntityCert("siggi.io", rootLeaf, Instant.now());
        server = new PKIServer(Config.parse("{\"listen\": \"127.0.0.1:0\", \"dataDir\": \"data\"}", dir));
        server.start();
        client = HttpClient.newHttpClient();
    }

    @AfterEach
    void stopServer() {
        server.stop();
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    private static X509Certificate cert(String subject, PublicKey key, String issuer, KeyPair issuerKey)
            throws Exception {
        return cert(subject, key, issuer, issuerKey, BigInteger.ONE, true);
    }

    private static X509Certificate cert(String subject, PublicKey key, String issuer, KeyPair issuerKey,
                                        BigInteger serial, boolean ca) throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer), serial,
                Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(30))),
                new X500Name(subject), key);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate())));
    }

    private static X509CRL crl() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return crl(42, now.minusSeconds(60), now.plus(Duration.ofDays(7)));
    }

    private static X509CRL crl(long number, Instant thisUpdate, Instant nextUpdate) throws Exception {
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name("CN=Siggi.io"), Date.from(thisUpdate));
        b.setNextUpdate(Date.from(nextUpdate));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        return new JcaX509CRLConverter().getCRL(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootKey.getPrivate())));
    }

    private HttpRequest.Builder req(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getPort() + path));
    }

    private HttpResponse<byte[]> get(String path) throws Exception {
        return client.send(req(path).build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    @Test
    void servesDerAndCrt() throws Exception {
        for (String path : new String[]{"/tls2.der", "/tls2.crt"}) {
            HttpResponse<byte[]> r = get(path);
            assertEquals(200, r.statusCode(), path);
            assertEquals("application/pkix-cert", r.headers().firstValue("Content-Type").orElseThrow());
            assertArrayEquals(inter.getEncoded(), r.body());
            assertTrue(r.headers().firstValue("ETag").isPresent());
            assertTrue(r.headers().firstValue("Last-Modified").isPresent());
            assertTrue(r.headers().firstValue("Cache-Control").orElseThrow().contains("max-age="));
        }
        // Dotted slug.
        HttpResponse<byte[]> r = get("/siggi.io.der");
        assertEquals(200, r.statusCode());
        assertArrayEquals(root.getEncoded(), r.body());
    }

    @Test
    void servesPem() throws Exception {
        HttpResponse<byte[]> r = get("/siggi.io.pem");
        assertEquals(200, r.statusCode());
        assertEquals("application/x-pem-file", r.headers().firstValue("Content-Type").orElseThrow());
        String body = new String(r.body(), StandardCharsets.US_ASCII);
        assertTrue(body.startsWith("-----BEGIN CERTIFICATE-----"));
        assertEquals(root, X509Util.parseCertificate(r.body()));
        assertNotEquals(get("/siggi.io.der").headers().firstValue("ETag"), r.headers().firstValue("ETag"));
    }

    @Test
    void conditionalRequests() throws Exception {
        HttpResponse<byte[]> first = get("/tls2.der");
        String etag = first.headers().firstValue("ETag").orElseThrow();
        String lastModified = first.headers().firstValue("Last-Modified").orElseThrow();

        HttpResponse<byte[]> r = client.send(req("/tls2.der").header("If-None-Match", etag).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(304, r.statusCode());
        assertEquals(0, r.body().length);

        r = client.send(req("/tls2.der").header("If-None-Match", "\"other\"").build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, r.statusCode());

        r = client.send(req("/tls2.der").header("If-Modified-Since", lastModified).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(304, r.statusCode());

        String longAgo = DateTimeFormatter.RFC_1123_DATE_TIME.withZone(ZoneOffset.UTC)
                .format(Instant.parse("2000-01-01T00:00:00Z"));
        r = client.send(req("/tls2.der").header("If-Modified-Since", longAgo).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, r.statusCode());
    }

    @Test
    void headAndMethods() throws Exception {
        HttpResponse<byte[]> r = client.send(req("/tls2.der").method("HEAD", HttpRequest.BodyPublishers.noBody())
                .build(), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, r.statusCode());
        assertEquals(String.valueOf(inter.getEncoded().length),
                r.headers().firstValue("Content-Length").orElseThrow());
        assertEquals(0, r.body().length);

        r = client.send(req("/tls2.der").POST(HttpRequest.BodyPublishers.ofString("x")).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(405, r.statusCode());
        assertTrue(r.headers().firstValue("Allow").orElseThrow().contains("GET"));

        r = client.send(req("/").DELETE().build(), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(405, r.statusCode());
    }

    @Test
    void unknownPathsAre404() throws Exception {
        for (String path : new String[]{"/tls3.der", "/tls2", "/tls2.txt", "/tls2.der/x", "/x/tls2.der",
                "/..der", "/TLS2.der", "/.der"}) {
            assertEquals(404, get(path).statusCode(), path);
        }
    }

    @Test
    void servesEndEntityCertificate() throws Exception {
        HttpResponse<byte[]> r = get("/tls2/a3f1/certificate.der");
        assertEquals(200, r.statusCode());
        assertEquals("application/pkix-cert", r.headers().firstValue("Content-Type").orElseThrow());
        assertArrayEquals(leaf.getEncoded(), r.body());
        String derEtag = r.headers().firstValue("ETag").orElseThrow();
        assertTrue(r.headers().firstValue("Last-Modified").isPresent());
        assertTrue(r.headers().firstValue("Cache-Control").orElseThrow().contains("max-age="));

        r = get("/tls2/a3f1/certificate.pem");
        assertEquals(200, r.statusCode());
        assertEquals("application/x-pem-file", r.headers().firstValue("Content-Type").orElseThrow());
        assertEquals(java.util.List.of(leaf), X509Util.parseCertificates(r.body()));
        String pemEtag = r.headers().firstValue("ETag").orElseThrow();
        assertNotEquals(derEtag, pemEtag);

        r = client.send(req("/tls2/a3f1/certificate.pem").header("If-None-Match", pemEtag).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(304, r.statusCode());
    }

    @Test
    void servesChainAndFullchain() throws Exception {
        HttpResponse<byte[]> r = get("/tls2/a3f1/chain.pem");
        assertEquals(200, r.statusCode());
        assertEquals("application/x-pem-file", r.headers().firstValue("Content-Type").orElseThrow());
        assertEquals(java.util.List.of(inter), X509Util.parseCertificates(r.body()), "issuer only, no root");
        String etag = r.headers().firstValue("ETag").orElseThrow();
        assertTrue(r.headers().firstValue("Last-Modified").isPresent());
        r = client.send(req("/tls2/a3f1/chain.pem").header("If-None-Match", etag).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(304, r.statusCode());

        r = get("/tls2/a3f1/fullchain.pem");
        assertEquals(200, r.statusCode());
        assertEquals(java.util.List.of(leaf, inter), X509Util.parseCertificates(r.body()));
        assertNotEquals(etag, r.headers().firstValue("ETag").orElseThrow());

        // Issued directly by the root: empty chain, fullchain is just the leaf.
        r = get("/siggi.io/1234/chain.pem");
        assertEquals(200, r.statusCode());
        assertEquals(0, r.body().length);
        r = get("/siggi.io/1234/fullchain.pem");
        assertEquals(200, r.statusCode());
        assertEquals(java.util.List.of(rootLeaf), X509Util.parseCertificates(r.body()));

        r = client.send(req("/siggi.io/1234/fullchain.pem").method("HEAD", HttpRequest.BodyPublishers.noBody())
                .build(), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, r.statusCode());
        assertEquals(0, r.body().length);
        r = client.send(req("/tls2/a3f1/chain.pem").POST(HttpRequest.BodyPublishers.ofString("x")).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(405, r.statusCode());
    }

    @Test
    void unknownEndEntityPathsAre404() throws Exception {
        for (String path : new String[]{"/tls3/a3f1/certificate.pem", "/tls2/a3f2/certificate.pem",
                "/siggi.io/a3f1/certificate.pem", "/tls2/a3f1/certificate.crt", "/tls2/a3f1/chain.der",
                "/tls2/a3f1", "/tls2/a3f1/certificate.pem/x", "/tls2.der/a3f1/certificate.pem"}) {
            assertEquals(404, get(path).statusCode(), path);
        }
        // Malformed slug/serial, traversal and empty segments: 400.
        for (String path : new String[]{"/tls2/00a3f1/certificate.pem", "/tls2/A3F1/certificate.pem",
                "/TLS2/a3f1/certificate.pem", "/tls2/a3f1/", "/tls2//certificate.pem",
                "/tls2/a3f1/../a3f1/chain.pem", "/../tls2/a3f1/chain.pem"}) {
            HttpResponse<byte[]> r = get(path);
            assertEquals(400, r.statusCode(), path);
            assertTrue(r.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"), path);
        }
    }

    @Test
    void unchainableEndEntityHasNoChain() throws Exception {
        server.getStore().removeSigningCert("siggi.io");
        assertEquals(404, get("/tls2/a3f1/chain.pem").statusCode());
        assertEquals(404, get("/tls2/a3f1/fullchain.pem").statusCode());
        assertEquals(200, get("/tls2/a3f1/certificate.pem").statusCode());
    }

    @Test
    void servesCrl() throws Exception {
        X509CRL expected = server.getStore().currentCrl("siggi.io").crl();
        HttpResponse<byte[]> r = get("/siggi.io.crl");
        assertEquals(200, r.statusCode());
        assertEquals("application/pkix-crl", r.headers().firstValue("Content-Type").orElseThrow());
        assertArrayEquals(expected.getEncoded(), r.body());
        String etag = r.headers().firstValue("ETag").orElseThrow();
        assertTrue(r.headers().firstValue("Last-Modified").isPresent());
        String cc = r.headers().firstValue("Cache-Control").orElseThrow();
        long maxAge = Long.parseLong(cc.replaceAll(".*max-age=(\\d+).*", "$1"));
        assertTrue(maxAge > 3000 && maxAge <= PublicFiles.CRL_MAX_AGE_SECONDS, cc);

        HttpResponse<byte[]> pem = get("/siggi.io.crl.pem");
        assertEquals(200, pem.statusCode());
        assertEquals("application/x-pem-file", pem.headers().firstValue("Content-Type").orElseThrow());
        assertTrue(new String(pem.body(), StandardCharsets.US_ASCII).startsWith("-----BEGIN X509 CRL-----"));
        assertEquals(expected, X509Util.parseCrls(pem.body()).get(0));
        assertNotEquals(etag, pem.headers().firstValue("ETag").orElseThrow());

        r = client.send(req("/siggi.io.crl").header("If-None-Match", etag).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(304, r.statusCode());

        // A CA without a current CRL, and unknown slugs: 404.
        assertEquals(404, get("/tls2.crl").statusCode());
        assertEquals(404, get("/tls2.crl.pem").statusCode());
        assertEquals(404, get("/nope.crl").statusCode());
        assertEquals(405, client.send(req("/siggi.io.crl").POST(HttpRequest.BodyPublishers.ofString("x")).build(),
                HttpResponse.BodyHandlers.ofByteArray()).statusCode());

        String html = new String(get("/").body(), StandardCharsets.UTF_8);
        assertTrue(html.contains("href=\"/siggi.io.crl\""), html);
        assertTrue(html.contains("href=\"/siggi.io.crl.pem\""), html);
        assertFalse(html.contains("stale"), html);
    }

    @Test
    void staleCrlIsStillServedAndFlagged(@TempDir Path other) throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Store store = Store.open(other.resolve("data"));
        store.addSigningCert("siggi.io", root);
        X509CRL stale = crl(7, now.minus(Duration.ofDays(8)), now.minus(Duration.ofDays(1)));
        store.addCrl("siggi.io", stale, CrlState.CURRENT, now.minus(Duration.ofDays(8)));
        PKIServer s = new PKIServer(Config.parse("{\"listen\": \"127.0.0.1:0\", \"dataDir\": \"data\"}", other));
        s.start();
        try {
            String base = "http://127.0.0.1:" + s.getPort();
            HttpResponse<byte[]> r = client.send(HttpRequest.newBuilder(URI.create(base + "/siggi.io.crl")).build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, r.statusCode());
            assertArrayEquals(stale.getEncoded(), r.body());
            assertEquals("public, max-age=0", r.headers().firstValue("Cache-Control").orElseThrow());
            String html = client.send(HttpRequest.newBuilder(URI.create(base + "/")).build(),
                    HttpResponse.BodyHandlers.ofString()).body();
            assertTrue(html.contains("#7</a>"), html);
            assertTrue(html.contains("class=\"warn\">stale"), html);
        } finally {
            s.stop();
        }
    }

    @Test
    void crlMaxAge() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        long cap = PublicFiles.CRL_MAX_AGE_SECONDS;
        assertEquals(cap, PublicFiles.crlMaxAge(now, now.plus(Duration.ofDays(7)), null));
        assertEquals(cap, PublicFiles.crlMaxAge(now, null, null));
        assertEquals(600, PublicFiles.crlMaxAge(now, now.plusSeconds(600), null));
        assertEquals(0, PublicFiles.crlMaxAge(now, now, null));
        assertEquals(0, PublicFiles.crlMaxAge(now, now.minusSeconds(5), null));
        assertEquals(120, PublicFiles.crlMaxAge(now, now.plus(Duration.ofDays(7)), now.plusSeconds(120)));
        // Rounded down, so caching never extends past the deadline.
        assertEquals(599, PublicFiles.crlMaxAge(now.plusMillis(1), now.plusSeconds(600), null));
    }

    @Test
    void indexPage() throws Exception {
        for (String path : new String[]{"/", "/index.html"}) {
            HttpResponse<byte[]> r = get(path);
            assertEquals(200, r.statusCode());
            assertEquals("text/html; charset=utf-8", r.headers().firstValue("Content-Type").orElseThrow());
            String html = new String(r.body(), StandardCharsets.UTF_8);
            assertTrue(html.contains("href=\"/tls2.der\""), html);
            assertTrue(html.contains("href=\"/siggi.io.pem\""), html);
            assertTrue(html.contains("&lt;Script &amp; Co"), html);
            assertFalse(html.contains("<Script"));
            assertTrue(html.contains("#42"), "current CRL number shown");
            assertTrue(html.contains("<td>siggi.io</td>"), "intermediate's issuer shown by slug");
            assertTrue(r.headers().firstValue("ETag").isPresent());
        }
    }

    @Test
    void emptyIndex(@TempDir Path other) throws Exception {
        PKIServer empty = new PKIServer(Config.parse("{\"listen\": \"127.0.0.1:0\"}", other));
        empty.start();
        try {
            HttpResponse<String> r = client.send(HttpRequest.newBuilder(
                    URI.create("http://127.0.0.1:" + empty.getPort() + "/")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, r.statusCode());
            assertTrue(r.body().contains("No signing certificates"));
        } finally {
            empty.stop();
        }
    }
}
