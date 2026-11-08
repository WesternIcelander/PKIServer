package io.siggi.pkiserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.x509.X509Util;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class CertificateUploadTest {
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final AtomicLong SERIALS = new AtomicLong(100);

    private static KeyPair rootKey;
    private static X509Certificate root;

    @TempDir
    Path dir;
    private Store store;
    private PKIServer server;
    private final HttpClient client = HttpClient.newHttpClient();

    @BeforeAll
    static void setUpRoot() throws Exception {
        rootKey = keyPair();
        root = new Spec("CN=Siggi.io", "CN=Siggi.io", rootKey).key(rootKey).build();
    }

    @AfterEach
    void stopServer() {
        if (server != null) server.stop();
    }

    // ------------------------------------------------------------------ helpers

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    /** Certificate builder with CA defaults: valid from yesterday for 30 days, CA:TRUE, no KU. */
    private static final class Spec {
        final String subject;
        final String issuer;
        final KeyPair issuerKey;
        KeyPair key;
        Instant notBefore = NOW.minus(Duration.ofDays(1));
        Instant notAfter = NOW.plus(Duration.ofDays(30));
        boolean ca = true;
        Integer keyUsage;

        Spec(String subject, String issuer, KeyPair issuerKey) {
            this.subject = subject;
            this.issuer = issuer;
            this.issuerKey = issuerKey;
        }

        Spec key(KeyPair key) {
            this.key = key;
            return this;
        }

        Spec validity(Instant from, Instant to) {
            this.notBefore = from;
            this.notAfter = to;
            return this;
        }

        Spec endEntity() {
            this.ca = false;
            return this;
        }

        Spec keyUsage(int bits) {
            this.keyUsage = bits;
            return this;
        }

        X509Certificate build() throws Exception {
            if (key == null) key = keyPair();
            JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                    BigInteger.valueOf(SERIALS.incrementAndGet()), Date.from(notBefore), Date.from(notAfter),
                    new X500Name(subject), key.getPublic());
            b.addExtension(Extension.basicConstraints, true, ca ? new BasicConstraints(true) : new BasicConstraints(false));
            if (keyUsage != null) b.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
            return new JcaX509CertificateConverter().getCertificate(
                    b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate())));
        }
    }

    private static X509CRL rootCrl(long number, X509Certificate... revoked) throws Exception {
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name("CN=Siggi.io"), Date.from(NOW.minusSeconds(60)));
        b.setNextUpdate(Date.from(NOW.plus(Duration.ofDays(7))));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        for (X509Certificate cert : revoked) {
            b.addCRLEntry(cert.getSerialNumber(), Date.from(NOW.minusSeconds(120)), CRLReason.keyCompromise);
        }
        return new JcaX509CRLConverter().getCRL(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootKey.getPrivate())));
    }

    /** Opens the store with the root installed (more can be added before {@link #start()}). */
    private Store store() throws Exception {
        if (store == null) {
            store = Store.open(dir.resolve("data"));
            store.addSigningCert("root2026", root);
        }
        return store;
    }

    private void start() throws Exception {
        store();
        server = new PKIServer(Config.parse(
                "{\"listen\": \"127.0.0.1:0\", \"dataDir\": \"data\", \"trustedProxies\": [\"127.0.0.1\"],"
                        + " \"limits\": {\"uploadsPerMinutePerIp\": 1000}}", dir));
        server.start();
    }

    record Response(int status, JsonObject json) {
        JsonObject result(int i) {
            return json.getAsJsonArray("certificates").get(i).getAsJsonObject();
        }

        String error() {
            return json.get("error").getAsString();
        }
    }

    private Response upload(byte[] body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + server.getPort() + CertificateUpload.PATH))
                .header("X-Forwarded-Proto", "https")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        HttpResponse<String> r = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertTrue(r.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"));
        return new Response(r.statusCode(), JsonParser.parseString(r.body()).getAsJsonObject());
    }

    private Response upload(X509Certificate... certs) throws Exception {
        if (certs.length == 1) return upload(certs[0].getEncoded());
        return upload(X509Util.pem(java.util.List.of(certs)).getBytes(StandardCharsets.US_ASCII));
    }

    private byte[] get(String path) throws Exception {
        HttpResponse<byte[]> r = client.send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getPort() + path)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, r.statusCode(), path);
        return r.body();
    }

    // ------------------------------------------------------------------ tests

    @Test
    void uploadsIntermediateAndServesIt() throws Exception {
        start();
        X509Certificate tls2 = new Spec("CN=TLS 2", "CN=Siggi.io", rootKey)
                .keyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature).build();
        Response r = upload(tls2);
        assertEquals(200, r.status(), r.json().toString());
        JsonObject result = r.result(0);
        assertEquals("installed", result.get("result").getAsString());
        assertEquals("tls2", result.get("slug").getAsString());
        assertEquals("/tls2.der", result.getAsJsonObject("urls").get("der").getAsString());

        assertArrayEquals(tls2.getEncoded(), get("/tls2.der"));
        assertEquals(tls2, server.getStore().signingCert("tls2").cert());
        assertTrue(Files.isRegularFile(dir.resolve("data/ca/tls2/cert.der")));

        // identical re-upload (DER or PEM) is a no-op
        r = upload(X509Util.pem(tls2).getBytes(StandardCharsets.US_ASCII));
        assertEquals(200, r.status());
        assertEquals("unchanged", r.result(0).get("result").getAsString());
        assertEquals("tls2", r.result(0).get("slug").getAsString());
    }

    @Test
    void notYetValidIsAccepted() throws Exception {
        start();
        X509Certificate tls3 = new Spec("CN=TLS 3", "CN=Siggi.io", rootKey)
                .validity(NOW.plus(Duration.ofDays(60)), NOW.plus(Duration.ofDays(400))).build();
        Response r = upload(tls3);
        assertEquals(200, r.status(), r.json().toString());
        assertEquals("tls3", r.result(0).get("slug").getAsString());
        assertEquals(tls3.getNotBefore().toInstant().toString(), r.result(0).get("notBefore").getAsString());
    }

    @Test
    void expiredIsRejected() throws Exception {
        start();
        X509Certificate old = new Spec("CN=Old", "CN=Siggi.io", rootKey)
                .validity(NOW.minus(Duration.ofDays(60)), NOW.minus(Duration.ofDays(1))).build();
        Response r = upload(old);
        assertEquals(400, r.status());
        assertTrue(r.error().contains("expired"), r.error());
        assertEquals("rejected", r.result(0).get("result").getAsString());
        assertNull(server.getStore().signingCert("old"));
    }

    @Test
    void unknownIssuerIsRejected() throws Exception {
        start();
        KeyPair otherKey = keyPair();
        X509Certificate cert = new Spec("CN=Stray", "CN=Elsewhere", otherKey).build();
        Response r = upload(cert);
        assertEquals(400, r.status());
        assertTrue(r.error().contains("CN=Elsewhere is not installed"), r.error());
    }

    @Test
    void wrongSignatureIsRejected() throws Exception {
        start();
        // claims the installed root as issuer but is signed by another key
        X509Certificate forged = new Spec("CN=Forged", "CN=Siggi.io", keyPair()).build();
        Response r = upload(forged);
        assertEquals(400, r.status());
        assertTrue(r.error().contains("signature does not verify"), r.error());
        assertNull(server.getStore().signingCert("forged"));
    }

    @Test
    void untrustedSelfSignedRootIsNotATrustAnchor() throws Exception {
        start();
        // a self-signed "root" with the same DN as ours: neither a root upload nor a path
        KeyPair fakeKey = keyPair();
        X509Certificate fakeRoot = new Spec("CN=Siggi.io", "CN=Siggi.io", fakeKey).key(fakeKey).build();
        Response r = upload(fakeRoot);
        assertEquals(400, r.status());
        assertTrue(r.error().contains("root certificates can't be uploaded"), r.error());

        X509Certificate child = new Spec("CN=Child", "CN=Siggi.io", fakeKey).build();
        r = upload(fakeRoot, child);
        assertEquals(400, r.status());
        assertNull(server.getStore().signingCert("child"));
    }

    @Test
    void installedRootReuploadIsNoOp() throws Exception {
        start();
        Response r = upload(root);
        assertEquals(200, r.status(), r.json().toString());
        assertEquals("unchanged", r.result(0).get("result").getAsString());
        assertEquals("root2026", r.result(0).get("slug").getAsString());
    }

    @Test
    void keyUsageMustIncludeKeyCertSign() throws Exception {
        start();
        X509Certificate cert = new Spec("CN=No Sign", "CN=Siggi.io", rootKey)
                .keyUsage(KeyUsage.cRLSign | KeyUsage.digitalSignature).build();
        Response r = upload(cert);
        assertEquals(400, r.status());
        assertTrue(r.error().contains("keyCertSign"), r.error());
    }

    @Test
    void endEntityIsNotASigningCertificate() throws Exception {
        start();
        X509Certificate leaf = new Spec("CN=www.example.com", "CN=Siggi.io", rootKey).endEntity().build();
        Response r = upload(leaf);
        assertEquals(400, r.status());
        assertTrue(r.error().contains("not a CA certificate"), r.error());
    }

    @Test
    void garbageIsRejected() throws Exception {
        start();
        Response r = upload("hello".getBytes(StandardCharsets.US_ASCII));
        assertEquals(400, r.status());
        assertTrue(r.error().startsWith("could not parse certificate"), r.error());
    }

    @Test
    void slugTakenByDifferentCertificateIsConflict() throws Exception {
        start();
        X509Certificate first = new Spec("CN=TLS 2", "CN=Siggi.io", rootKey).build();
        assertEquals(200, upload(first).status());

        // renewed with the same CN: different key
        X509Certificate renewed = new Spec("CN=TLS 2", "CN=Siggi.io", rootKey).build();
        Response r = upload(renewed);
        assertEquals(409, r.status());
        assertTrue(r.error().contains("slug \"tls2\" is already taken by a different certificate"), r.error());
        assertEquals("tls2", r.result(0).get("slug").getAsString());
        assertEquals(first, server.getStore().signingCert("tls2").cert());

        // a CN that normalizes to the hand-installed root's slug
        X509Certificate clash = new Spec("CN=Root 2026", "CN=Siggi.io", rootKey).build();
        r = upload(clash);
        assertEquals(409, r.status());
        assertTrue(r.error().contains("\"root2026\""), r.error());
    }

    @Test
    void badSlugsAreRejected() throws Exception {
        start();
        Response r = upload(new Spec("O=No CN", "CN=Siggi.io", rootKey).build());
        assertEquals(400, r.status());
        assertTrue(r.error().contains("no CN"), r.error());

        r = upload(new Spec("CN=%%%", "CN=Siggi.io", rootKey).build());
        assertEquals(400, r.status());
        assertTrue(r.error().contains("no URL-safe characters"), r.error());

        r = upload(new Spec("CN=API", "CN=Siggi.io", rootKey).build());
        assertEquals(400, r.status());
        assertTrue(r.error().contains("reserved"), r.error());
        assertNull(server.getStore().signingCert("api"));
    }

    @Test
    void revokedByCurrentCrlIsRejected() throws Exception {
        X509Certificate revoked = new Spec("CN=Revoked", "CN=Siggi.io", rootKey).build();
        store().addCrl("root2026", rootCrl(1, revoked), CrlState.CURRENT, NOW);
        start();
        Response r = upload(revoked);
        assertEquals(400, r.status());
        assertTrue(r.error().contains("revoked by CRL #1 of \"root2026\""), r.error());

        // a non-revoked sibling is fine
        assertEquals(200, upload(new Spec("CN=Fine", "CN=Siggi.io", rootKey).build()).status());
    }

    @Test
    void revokedIntermediateBreaksThePath() throws Exception {
        KeyPair interKey = keyPair();
        X509Certificate inter = new Spec("CN=Inter", "CN=Siggi.io", rootKey).key(interKey).build();
        store().addSigningCert("inter", inter);
        store().addCrl("root2026", rootCrl(1, inter), CrlState.CURRENT, NOW);
        start();
        Response r = upload(new Spec("CN=Sub", "CN=Inter", interKey).build());
        assertEquals(400, r.status());
        assertTrue(r.error().contains("CN=Inter") && r.error().contains("revoked"), r.error());
    }

    @Test
    void pathThroughInstalledIntermediates() throws Exception {
        start();
        KeyPair interKey = keyPair();
        X509Certificate inter = new Spec("CN=Inter", "CN=Siggi.io", rootKey).key(interKey).build();
        X509Certificate sub = new Spec("CN=Sub", "CN=Inter", interKey).build();

        // the intermediate isn't installed yet
        Response r = upload(sub);
        assertEquals(400, r.status());
        assertTrue(r.error().contains("CN=Inter is not installed"), r.error());

        // in one body, in any order
        r = upload(sub, inter);
        assertEquals(200, r.status(), r.json().toString());
        JsonArray results = r.json().getAsJsonArray("certificates");
        assertEquals("sub", results.get(0).getAsJsonObject().get("slug").getAsString());
        assertEquals("inter", results.get(1).getAsJsonObject().get("slug").getAsString());
        assertNotNull(server.getStore().signingCert("sub"));
    }

    @Test
    void pathLengthConstraintIsEnforced() throws Exception {
        KeyPair interKey = keyPair();
        // pathlen:0 intermediate, built by hand
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name("CN=Siggi.io"),
                BigInteger.valueOf(SERIALS.incrementAndGet()), Date.from(NOW.minus(Duration.ofDays(1))),
                Date.from(NOW.plus(Duration.ofDays(30))), new X500Name("CN=Leaf CA"), interKey.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        X509Certificate inter = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootKey.getPrivate())));
        store().addSigningCert("leafca", inter);
        start();
        // a CA certificate issued by it is fine (it is the end of the path)...
        KeyPair midKey = keyPair();
        assertEquals(200, upload(new Spec("CN=Mid", "CN=Leaf CA", interKey).key(midKey).build()).status());
        // ...but one issued below that has one intermediate too many
        Response r = upload(new Spec("CN=Too Deep", "CN=Mid", midKey).build());
        assertEquals(400, r.status());
        assertTrue(r.error().contains("path validation failed"), r.error());
    }

    @Test
    void sampleCertificates() throws Exception {
        Path samples = Path.of("sample-certificates");
        assumeTrue(Files.isRegularFile(samples.resolve("Siggi.io.crt")), "sample certificates not present");
        store = Store.open(dir.resolve("data"));
        store.addSigningCert("root2026", X509Util.parseCertificate(Files.readAllBytes(samples.resolve("Siggi.io.crt"))));
        start();
        Response r = upload(Files.readAllBytes(samples.resolve("TLS_2.crt")));
        assertEquals(200, r.status(), r.json().toString());
        assertEquals("tls2", r.result(0).get("slug").getAsString());

        // TLS 3 is valid from 2027
        r = upload(Files.readAllBytes(samples.resolve("TLS_3.crt")));
        assertEquals(200, r.status(), r.json().toString());
        assertEquals("tls3", r.result(0).get("slug").getAsString());

        // an end-entity certificate isn't a signing certificate
        r = upload(Files.readAllBytes(samples.resolve("Stromno_MITM.crt")));
        assertEquals(400, r.status());
    }
}
