package io.siggi.pkiserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.Store;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class CrlCoverageTest {
    private static final Duration WARN = Duration.ofDays(30);
    private static KeyPair rootKey;
    private static X509Certificate root;

    @TempDir
    Path dir;
    private PKIServer server;

    @BeforeAll
    static void setUpCerts() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        rootKey = gen.generateKeyPair();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name("CN=Siggi.io"), BigInteger.ONE,
                Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(3650))),
                new X500Name("CN=Siggi.io"), rootKey.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        root = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootKey.getPrivate())));
    }

    @AfterEach
    void stopServer() {
        if (server != null) server.stop();
    }

    private static X509CRL crl(long number, Instant thisUpdate, Instant nextUpdate) throws Exception {
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name("CN=Siggi.io"), Date.from(thisUpdate));
        b.setNextUpdate(Date.from(nextUpdate));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        return new JcaX509CRLConverter().getCRL(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootKey.getPrivate())));
    }

    private Store store() throws Exception {
        Store store = Store.open(dir.resolve("data"));
        store.addSigningCert("siggi.io", root);
        return store;
    }

    @Test
    void noCrls() throws Exception {
        Instant now = Instant.now();
        CrlCoverage c = CrlCoverage.of(store(), "siggi.io", now, WARN);
        assertNull(c.current());
        assertTrue(c.pending().isEmpty());
        assertNull(c.highestNumber());
        assertEquals(BigInteger.ONE, c.nextNumber());
        assertNull(c.coverageUntil());
        assertFalse(c.warning());
        JsonObject j = c.toJson();
        assertTrue(j.get("current").isJsonNull());
        assertTrue(j.get("highestCrlNumber").isJsonNull());
        assertEquals("1", j.get("nextCrlNumber").getAsString());
        assertTrue(j.get("coverageUntil").isJsonNull());
        assertFalse(j.get("coverageWarning").getAsBoolean());
    }

    @Test
    void coverageAcrossCurrentAndPending() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Store store = store();
        store.addCrl("siggi.io", crl(1, now.minus(Duration.ofDays(20)), now.plus(Duration.ofDays(10))),
                CrlState.SUPERSEDED, now);
        store.addCrl("siggi.io", crl(2, now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(7))),
                CrlState.CURRENT, now);
        store.addCrl("siggi.io", crl(3, now.plus(Duration.ofDays(5)), now.plus(Duration.ofDays(40))),
                CrlState.PENDING, now);
        store.addCrl("siggi.io", crl(4, now.plus(Duration.ofDays(30)), now.plus(Duration.ofDays(60))),
                CrlState.PENDING, now);
        store.addCrl("siggi.io", crl(5, now.plus(Duration.ofDays(50)), now.plus(Duration.ofDays(80))),
                CrlState.PENDING, now);
        // A discarded backup still counts towards the highest number used.
        store.discardCrl("siggi.io", BigInteger.valueOf(5), now, "test");

        CrlCoverage c = CrlCoverage.of(store, "siggi.io", now, WARN);
        assertEquals(BigInteger.TWO, c.current().number());
        assertEquals(2, c.pending().size());
        assertEquals(BigInteger.valueOf(3), c.pending().get(0).number());
        assertEquals(BigInteger.valueOf(5), c.highestNumber());
        assertEquals(BigInteger.valueOf(6), c.nextNumber());
        assertEquals(now.plus(Duration.ofDays(60)), c.coverageUntil());
        assertFalse(c.warning());
        assertFalse(c.stale());

        // 60 days of coverage: warned about with a 90-day threshold.
        assertTrue(CrlCoverage.of(store, "siggi.io", now, Duration.ofDays(90)).warning());
        // ... and once it's less than 30 days away.
        assertTrue(CrlCoverage.of(store, "siggi.io", now.plus(Duration.ofDays(31)), WARN).warning());

        JsonObject j = c.toJson();
        assertEquals("2", j.getAsJsonObject("current").get("number").getAsString());
        assertFalse(j.getAsJsonObject("current").get("stale").getAsBoolean());
        JsonArray pending = j.getAsJsonArray("pending");
        assertEquals(2, pending.size());
        assertEquals("4", pending.get(1).getAsJsonObject().get("number").getAsString());
        assertEquals(now.plus(Duration.ofDays(30)).toString(),
                pending.get(1).getAsJsonObject().get("thisUpdate").getAsString());
        assertEquals("5", j.get("highestCrlNumber").getAsString());
        assertEquals("6", j.get("nextCrlNumber").getAsString());
        assertEquals(now.plus(Duration.ofDays(60)).toString(), j.get("coverageUntil").getAsString());
        assertEquals(Duration.ofDays(60).toSeconds(), j.get("coverageRemainingSeconds").getAsLong());
        assertEquals(30, j.get("coverageWarningDays").getAsInt());
        assertFalse(j.get("coverageWarning").getAsBoolean());
    }

    @Test
    void staleCurrentWithoutPendingIsWarned() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Store store = store();
        store.addCrl("siggi.io", crl(9, now.minus(Duration.ofDays(8)), now.minus(Duration.ofDays(1))),
                CrlState.CURRENT, now);
        CrlCoverage c = CrlCoverage.of(store, "siggi.io", now, WARN);
        assertTrue(c.stale());
        assertTrue(c.warning());
        assertTrue(c.remaining().isNegative());
    }

    private HttpResponse<String> get(String path, boolean viaProxy, String method) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getPort() + path))
                .method(method, HttpRequest.BodyPublishers.noBody());
        if (viaProxy) b.header("X-Forwarded-Proto", "https");
        return HttpClient.newHttpClient().send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private void start(String extra) throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Store store = store();
        store.addCrl("siggi.io", crl(2, now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(7))),
                CrlState.CURRENT, now);
        store.addCrl("siggi.io", crl(3, now.plus(Duration.ofDays(5)), now.plus(Duration.ofDays(20))),
                CrlState.PENDING, now);
        server = new PKIServer(Config.parse("{\"listen\": \"127.0.0.1:0\", \"dataDir\": \"data\", "
                + "\"trustedProxies\": [\"127.0.0.1\"]" + extra + "}", dir));
        server.start();
    }

    @Test
    void apiEndpoint() throws Exception {
        start("");
        HttpResponse<String> r = get("/api/crl/siggi.io", true, "GET");
        assertEquals(200, r.statusCode(), r.body());
        assertTrue(r.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"));
        JsonObject j = JsonParser.parseString(r.body()).getAsJsonObject();
        assertEquals("siggi.io", j.get("slug").getAsString());
        assertEquals("2", j.getAsJsonObject("current").get("number").getAsString());
        assertEquals(1, j.getAsJsonArray("pending").size());
        assertEquals("3", j.get("highestCrlNumber").getAsString());
        assertEquals("4", j.get("nextCrlNumber").getAsString());
        assertTrue(j.get("coverageWarning").getAsBoolean(), "20 days < 30 days");

        HttpResponse<String> head = get("/api/crl/siggi.io", true, "HEAD");
        assertEquals(200, head.statusCode(), head.headers().map().toString());
        assertEquals(404, get("/api/crl/nope", true, "GET").statusCode());
        assertEquals(404, get("/api/crl/..", true, "GET").statusCode());
        HttpResponse<String> post = get("/api/crl/siggi.io", true, "POST");
        assertEquals(405, post.statusCode());
        assertEquals("GET, HEAD", post.headers().firstValue("Allow").orElseThrow());
        // Same HTTPS gate as the rest of the API.
        assertEquals(403, get("/api/crl/siggi.io", false, "GET").statusCode());
        // The upload endpoint itself is still POST only.
        assertEquals(405, get("/api/crl", true, "GET").statusCode());

        String html = get("/", false, "GET").body();
        assertTrue(html.contains("#3: "), html);
        assertTrue(html.contains("next: #4"), html);
        assertTrue(html.contains("class=\"warn\">coverage runs out in 19 days"), html);
    }

    @Test
    void configurableThreshold() throws Exception {
        start(", \"limits\": {\"coverageWarningDays\": 10}");
        JsonObject j = JsonParser.parseString(get("/api/crl/siggi.io", true, "GET").body()).getAsJsonObject();
        assertEquals(10, j.get("coverageWarningDays").getAsInt());
        assertFalse(j.get("coverageWarning").getAsBoolean());
        assertFalse(get("/", false, "GET").body().contains("coverage runs out"));
    }
}
