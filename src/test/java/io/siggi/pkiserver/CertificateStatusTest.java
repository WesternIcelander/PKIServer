package io.siggi.pkiserver;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.Store;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
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
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class CertificateStatusTest {
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final Instant REVOKED_AT = NOW.minus(Duration.ofHours(2));

    private static KeyPair rootKey;
    private static KeyPair interKey;
    private static X509Certificate root;
    private static X509Certificate inter;
    private static X509Certificate inter3;
    private static X509Certificate good;
    private static X509Certificate revoked;
    private static X509Certificate expired;
    private static X509Certificate underRevokedCa;

    @TempDir
    Path dir;
    private PKIServer server;

    @BeforeAll
    static void setUpCerts() throws Exception {
        rootKey = keyPair();
        interKey = keyPair();
        KeyPair inter3Key = keyPair();
        root = cert("CN=Siggi.io", rootKey.getPublic(), "CN=Siggi.io", rootKey, BigInteger.ONE, true, 0, 30);
        inter = cert("CN=TLS 2", interKey.getPublic(), "CN=Siggi.io", rootKey, BigInteger.TWO, true, 0, 30);
        inter3 = cert("CN=TLS 3", inter3Key.getPublic(), "CN=Siggi.io", rootKey, BigInteger.valueOf(3), true, 0, 30);
        good = cert("CN=good.example.com", keyPair().getPublic(), "CN=TLS 2", interKey,
                BigInteger.valueOf(0xa1), false, 0, 30);
        revoked = cert("CN=revoked.example.com", keyPair().getPublic(), "CN=TLS 2", interKey,
                BigInteger.valueOf(0xb2), false, 0, 30);
        expired = cert("CN=old.example.com", keyPair().getPublic(), "CN=TLS 2", interKey,
                BigInteger.valueOf(0xc3), false, 10, -1);
        underRevokedCa = cert("CN=orphan.example.com", keyPair().getPublic(), "CN=TLS 3", inter3Key,
                BigInteger.valueOf(0xd4), false, 0, 30);
    }

    @BeforeEach
    void startServer() throws Exception {
        Store store = Store.open(dir.resolve("data"));
        store.addSigningCert("siggi.io", root);
        store.addSigningCert("tls2", inter);
        store.addSigningCert("tls3", inter3);
        Instant past = NOW.minus(Duration.ofDays(20));
        store.addEndEntityCert("tls2", good, past);
        store.addEndEntityCert("tls2", revoked, past);
        store.addEndEntityCert("tls2", expired, past);
        store.addEndEntityCert("tls3", underRevokedCa, past);
        // tls2 revokes b2 (keyCompromise); the root revokes tls3 itself.
        store.addCrl("tls2", crl("CN=TLS 2", interKey, 5, BigInteger.valueOf(0xb2), CRLReason.keyCompromise),
                CrlState.CURRENT, NOW);
        store.addCrl("siggi.io", crl("CN=Siggi.io", rootKey, 7, BigInteger.valueOf(3), -1),
                CrlState.CURRENT, NOW);
        server = new PKIServer(Config.parse("{\"listen\": \"127.0.0.1:0\", \"dataDir\": \"data\", "
                + "\"trustedProxies\": [\"127.0.0.1\"]}", dir));
        server.start();
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

    private static X509Certificate cert(String subject, PublicKey key, String issuer, KeyPair issuerKey,
                                        BigInteger serial, boolean ca, int daysAgo, int daysLeft) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer), serial,
                Date.from(NOW.minus(Duration.ofDays(daysAgo + 1))), Date.from(NOW.plus(Duration.ofDays(daysLeft))),
                new X500Name(subject), key);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate())));
    }

    private static X509CRL crl(String issuer, KeyPair key, long number, BigInteger revokedSerial, int reason)
            throws Exception {
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name(issuer), Date.from(NOW.minusSeconds(60)));
        b.setNextUpdate(Date.from(NOW.plus(Duration.ofDays(7))));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        if (reason >= 0) {
            b.addCRLEntry(revokedSerial, Date.from(REVOKED_AT), reason);
        } else {
            b.addCRLEntry(revokedSerial, Date.from(REVOKED_AT), null);
        }
        return new JcaX509CRLConverter().getCRL(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key.getPrivate())));
    }

    private HttpResponse<String> get(String path, boolean viaProxy) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getPort() + path));
        if (viaProxy) b.header("X-Forwarded-Proto", "https");
        return HttpClient.newHttpClient().send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private JsonObject status(String path) throws Exception {
        HttpResponse<String> r = get(path, true);
        assertEquals(200, r.statusCode(), r.body());
        assertTrue(r.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"));
        return JsonParser.parseString(r.body()).getAsJsonObject();
    }

    @Test
    void validCertificate() throws Exception {
        JsonObject j = status("/api/certificate/tls2/a1");
        assertEquals("tls2", j.get("issuer").getAsString());
        assertEquals("a1", j.get("serial").getAsString());
        assertEquals("CN=good.example.com", j.get("subject").getAsString());
        assertEquals("valid", j.get("status").getAsString());
        assertFalse(j.get("revoked").getAsBoolean());
        assertTrue(j.get("revocation").isJsonNull());
        assertEquals("/tls2/a1/fullchain.pem", j.getAsJsonObject("urls").get("fullchain").getAsString());
    }

    @Test
    void revokedCertificate() throws Exception {
        JsonObject j = status("/api/certificate/tls2/b2");
        assertEquals("revoked", j.get("status").getAsString());
        assertTrue(j.get("revoked").getAsBoolean());
        JsonObject r = j.getAsJsonObject("revocation");
        assertEquals(REVOKED_AT.toString(), r.get("revocationDate").getAsString());
        assertEquals("keyCompromise", r.get("reason").getAsString());
        assertEquals("tls2", r.get("crlIssuer").getAsString());
        assertEquals("5", r.get("crlNumber").getAsString());
        assertEquals("b2", r.get("revokedSerial").getAsString());
        assertTrue(r.get("revokedCa").isJsonNull());
    }

    @Test
    void revokedIssuingCa() throws Exception {
        JsonObject j = status("/api/certificate/tls3/d4");
        assertEquals("revoked", j.get("status").getAsString());
        JsonObject r = j.getAsJsonObject("revocation");
        assertEquals("tls3", r.get("revokedCa").getAsString());
        assertEquals("3", r.get("revokedSerial").getAsString());
        assertEquals("siggi.io", r.get("crlIssuer").getAsString());
        assertEquals("7", r.get("crlNumber").getAsString());
        assertTrue(r.get("reason").isJsonNull());
    }

    @Test
    void expiredCertificate() throws Exception {
        JsonObject j = status("/api/certificate/tls2/c3");
        assertEquals("expired", j.get("status").getAsString());
        assertFalse(j.get("revoked").getAsBoolean());
    }

    @Test
    void apiErrors() throws Exception {
        assertEquals(404, get("/api/certificate/tls2/ff", true).statusCode());
        assertEquals(404, get("/api/certificate/nope/a1", true).statusCode());
        assertEquals(404, get("/api/certificate/tls2", true).statusCode());
        assertEquals(404, get("/api/certificate/tls2/a1/x", true).statusCode());
        assertEquals(400, get("/api/certificate/tls2/A1", true).statusCode());
        assertEquals(400, get("/api/certificate/tls2/00a1", true).statusCode());
        assertEquals(400, get("/api/certificate/TLS2/a1", true).statusCode());
        // Same HTTPS gate as the rest of the API.
        assertEquals(403, get("/api/certificate/tls2/a1", false).statusCode());
        // The upload endpoint itself is still POST only, and /api/crl/<slug> unchanged.
        assertEquals(405, get("/api/certificate", true).statusCode());
        assertEquals(200, get("/api/crl/tls2", true).statusCode());
        assertEquals(404, get("/api/crl/tls2/x", true).statusCode());
    }

    @Test
    void indexShowsRevokedCertificates() throws Exception {
        String html = get("/", false).body();
        assertTrue(html.contains("End-entity certificates"), html);
        assertTrue(html.contains("<tr id=\"tls2/a1\">"), html);
        int good = html.indexOf("<tr id=\"tls2/a1\">");
        assertTrue(html.substring(good, html.indexOf("</tr>", good)).contains("<td>valid</td>"), html);

        int rev = html.indexOf("<tr id=\"tls2/b2\" class=\"revoked\">");
        assertTrue(rev >= 0, html);
        String row = html.substring(rev, html.indexOf("</tr>", rev));
        assertTrue(row.contains("class=\"warn\">revoked</span>"), row);
        assertTrue(row.contains("reason: keyCompromise"), row);
        assertTrue(row.contains("CRL #5"), row);

        int orphan = html.indexOf("<tr id=\"tls3/d4\" class=\"revoked\">");
        assertTrue(orphan >= 0, html);
        assertTrue(html.substring(orphan, html.indexOf("</tr>", orphan))
                .contains("issuing CA <code>tls3</code> is revoked"), html);

        int old = html.indexOf("<tr id=\"tls2/c3\">");
        assertTrue(html.substring(old, html.indexOf("</tr>", old)).contains(">expired<"), html);
    }
}
