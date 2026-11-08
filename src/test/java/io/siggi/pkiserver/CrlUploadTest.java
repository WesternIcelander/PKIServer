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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CrlUploadTest {
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final String ROOT_DN = "CN=Siggi.io";

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
        root = cert(ROOT_DN, ROOT_DN, rootKey, rootKey, 1, null);
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

    private static X509Certificate cert(String subject, String issuer, KeyPair key, KeyPair issuerKey, long serial,
                                        Integer keyUsage) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(serial), Date.from(NOW.minus(Duration.ofDays(1))),
                Date.from(NOW.plus(Duration.ofDays(3650))), new X500Name(subject), key.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        if (keyUsage != null) b.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate())));
    }

    /** CRL builder: issued by the root, valid for 7 days from {@code thisUpdate}. */
    private static final class Crl {
        String issuer = ROOT_DN;
        KeyPair key = rootKey;
        Long number;
        Instant thisUpdate;
        Instant nextUpdate;
        boolean noNextUpdate;
        boolean delta;
        final List<Long> revoked = new ArrayList<>();

        Crl(Long number, Instant thisUpdate) {
            this.number = number;
            this.thisUpdate = thisUpdate;
            this.nextUpdate = thisUpdate.plus(Duration.ofDays(7));
        }

        Crl issuer(String dn, KeyPair key) {
            this.issuer = dn;
            this.key = key;
            return this;
        }

        Crl nextUpdate(Instant nextUpdate) {
            this.nextUpdate = nextUpdate;
            return this;
        }

        Crl noNextUpdate() {
            this.noNextUpdate = true;
            return this;
        }

        Crl delta() {
            this.delta = true;
            return this;
        }

        Crl revoke(long... serials) {
            for (long s : serials) revoked.add(s);
            return this;
        }

        X509CRL build() throws Exception {
            X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name(issuer), Date.from(thisUpdate));
            if (!noNextUpdate) b.setNextUpdate(Date.from(nextUpdate));
            if (number != null) b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
            if (delta) b.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(BigInteger.ONE));
            for (long s : revoked) {
                b.addCRLEntry(BigInteger.valueOf(s), Date.from(NOW.minus(Duration.ofDays(2))), CRLReason.keyCompromise);
            }
            return new JcaX509CRLConverter().getCRL(
                    b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key.getPrivate())));
        }
    }

    private static Crl crl(long number, Instant thisUpdate) {
        return new Crl(number, thisUpdate);
    }

    private static Instant ago(Duration d) {
        return NOW.minus(d);
    }

    private static Instant in(Duration d) {
        return NOW.plus(d);
    }

    private Store store() throws Exception {
        if (store == null) {
            store = Store.open(dir.resolve("data"));
            store.addSigningCert("root2026", root);
        }
        return store;
    }

    private void start() throws Exception {
        start("");
    }

    private void start(String extraLimits) throws Exception {
        store();
        server = new PKIServer(Config.parse(
                "{\"listen\": \"127.0.0.1:0\", \"dataDir\": \"data\", \"trustedProxies\": [\"127.0.0.1\"],"
                        + " \"limits\": {\"uploadsPerMinutePerIp\": 1000" + extraLimits + "}}", dir));
        server.start();
    }

    record Response(int status, JsonObject json) {
        JsonObject result(int i) {
            return json.getAsJsonArray("crls").get(i).getAsJsonObject();
        }

        String result() {
            return result(0).get("result").getAsString();
        }

        String error() {
            return json.get("error").getAsString();
        }
    }

    private Response upload(byte[] body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + server.getPort() + CrlUpload.PATH))
                .header("X-Forwarded-Proto", "https")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        HttpResponse<String> r = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertTrue(r.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"));
        return new Response(r.statusCode(), JsonParser.parseString(r.body()).getAsJsonObject());
    }

    private Response upload(X509CRL... crls) throws Exception {
        if (crls.length == 1) return upload(crls[0].getEncoded());
        StringBuilder pem = new StringBuilder();
        for (X509CRL c : crls) pem.append(X509Util.pem(c));
        return upload(pem.toString().getBytes(StandardCharsets.US_ASCII));
    }

    private Response upload(Crl... specs) throws Exception {
        X509CRL[] crls = new X509CRL[specs.length];
        for (int i = 0; i < specs.length; i++) crls[i] = specs[i].build();
        return upload(crls);
    }

    private CrlState state(long number) throws Exception {
        var c = server.getStore().crl("root2026", BigInteger.valueOf(number));
        return c == null ? null : c.state();
    }

    // ------------------------------------------------------------------ accepted

    @Test
    void immediateCrlBecomesCurrent() throws Exception {
        start();
        X509CRL first = crl(1, ago(Duration.ofMinutes(1))).build();
        Response r = upload(first);
        assertEquals(200, r.status(), r.json().toString());
        JsonObject result = r.result(0);
        assertEquals("current", result.get("result").getAsString());
        assertEquals("root2026", result.get("slug").getAsString());
        assertEquals("1", result.get("number").getAsString());
        assertEquals(0, result.getAsJsonArray("discarded").size());
        assertEquals(CrlState.CURRENT, state(1));
        assertTrue(Files.isRegularFile(dir.resolve("data/ca/root2026/crl/1.crl")));

        // identical re-upload (DER or PEM) is a no-op
        r = upload(X509Util.pem(first).getBytes(StandardCharsets.US_ASCII));
        assertEquals(200, r.status(), r.json().toString());
        assertEquals("current", r.result());
        assertTrue(r.result(0).get("unchanged").getAsBoolean());

        // the next one supersedes it
        r = upload(crl(2, ago(Duration.ofSeconds(30))));
        assertEquals(200, r.status(), r.json().toString());
        assertEquals(CrlState.SUPERSEDED, state(1));
        assertEquals(CrlState.CURRENT, state(2));
    }

    @Test
    void futureCrlIsPending() throws Exception {
        start();
        assertEquals(200, upload(crl(1, ago(Duration.ofMinutes(1)))).status());
        Instant later = in(Duration.ofDays(5));
        Response r = upload(crl(2, later));
        assertEquals(200, r.status(), r.json().toString());
        assertEquals("pending", r.result());
        assertEquals(later.toString(), r.result(0).get("activatesAt").getAsString());
        assertEquals(CrlState.PENDING, state(2));
        assertEquals(CrlState.CURRENT, state(1));
    }

    @Test
    void batchOfBackupsInAnyOrder() throws Exception {
        start();
        Response r = upload(crl(1, ago(Duration.ofMinutes(1))), crl(4, in(Duration.ofDays(15))),
                crl(2, in(Duration.ofDays(5))), crl(3, in(Duration.ofDays(10))));
        assertEquals(200, r.status(), r.json().toString());
        assertEquals("current", r.result(0).get("result").getAsString());
        assertEquals("pending", r.result(1).get("result").getAsString());
        assertEquals("4", r.result(1).get("number").getAsString());
        assertEquals("pending", r.result(2).get("result").getAsString());
        assertEquals("pending", r.result(3).get("result").getAsString());
        // uploading another backup keeps the others
        assertEquals(200, upload(crl(5, in(Duration.ofDays(20)))).status());
        assertEquals(CrlState.PENDING, state(2));
        assertEquals(CrlState.PENDING, state(5));
    }

    @Test
    void emergencyCrlDiscardsBackups() throws Exception {
        start();
        X509CRL backup2 = crl(2, in(Duration.ofDays(5))).build();
        assertEquals(200, upload(crl(1, ago(Duration.ofMinutes(1)))).status());
        assertEquals(200, upload(backup2, crl(3, in(Duration.ofDays(10))).build()).status());

        Response r = upload(crl(4, ago(Duration.ofSeconds(10))).revoke(77));
        assertEquals(200, r.status(), r.json().toString());
        assertEquals("current", r.result());
        JsonArray discarded = r.result(0).getAsJsonArray("discarded");
        assertEquals(2, discarded.size());
        assertEquals("2", discarded.get(0).getAsJsonObject().get("number").getAsString());
        assertEquals("3", discarded.get(1).getAsJsonObject().get("number").getAsString());
        assertNull(state(2));
        assertNull(state(3));
        assertEquals(CrlState.SUPERSEDED, state(1));
        assertEquals(CrlState.CURRENT, state(4));
        assertFalse(Files.exists(dir.resolve("data/ca/root2026/crl/2.crl")));
        assertTrue(Files.isRegularFile(dir.resolve("data/ca/root2026/crl/discarded.json")));
        assertEquals(2, server.getStore().discardedCrls("root2026").size());

        // a discarded backup can't come back (rule 1)
        r = upload(backup2);
        assertEquals(409, r.status());
        assertTrue(r.error().contains("not greater than 4"), r.error());
    }

    @Test
    void emergencyCrlDatedNowIsAcceptedDespiteLaterBackups() throws Exception {
        start();
        assertEquals(200, upload(crl(1, ago(Duration.ofHours(1))), crl(2, in(Duration.ofDays(5)))).status());
        // thisUpdate is before the pending CRL's, but the pending one is discarded first
        Response r = upload(crl(3, ago(Duration.ofMinutes(1))));
        assertEquals(200, r.status(), r.json().toString());
        assertEquals(1, r.result(0).getAsJsonArray("discarded").size());
    }

    @Test
    void crlOfIntermediate() throws Exception {
        KeyPair interKey = keyPair();
        X509Certificate inter = cert("CN=TLS 2", ROOT_DN, interKey, rootKey, 10,
                KeyUsage.keyCertSign | KeyUsage.cRLSign);
        store().addSigningCert("tls2", inter);
        start();
        Response r = upload(crl(1, ago(Duration.ofMinutes(1))).issuer("CN=TLS 2", interKey));
        assertEquals(200, r.status(), r.json().toString());
        assertEquals("tls2", r.result(0).get("slug").getAsString());
        assertNotNull(server.getStore().currentCrl("tls2"));
        assertNull(server.getStore().currentCrl("root2026"));
    }

    // ------------------------------------------------------------------ format checks

    @Test
    void garbageIsRejected() throws Exception {
        start();
        Response r = upload("nope".getBytes(StandardCharsets.US_ASCII));
        assertEquals(400, r.status());
        assertTrue(r.error().startsWith("could not parse CRL"), r.error());
    }

    @Test
    void unknownIssuerIsRejected() throws Exception {
        start();
        Response r = upload(crl(1, ago(Duration.ofMinutes(1))).issuer("CN=Elsewhere", keyPair()));
        assertEquals(400, r.status());
        assertTrue(r.error().contains("CN=Elsewhere is not installed"), r.error());
    }

    @Test
    void wrongSignatureIsRejected() throws Exception {
        start();
        Response r = upload(crl(1, ago(Duration.ofMinutes(1))).issuer(ROOT_DN, keyPair()));
        assertEquals(400, r.status());
        assertTrue(r.error().contains("signature does not verify"), r.error());
        assertNull(state(1));
    }

    @Test
    void issuerWithoutCrlSignIsRejected() throws Exception {
        KeyPair interKey = keyPair();
        store().addSigningCert("nocrl", cert("CN=No CRL", ROOT_DN, interKey, rootKey, 11, KeyUsage.keyCertSign));
        start();
        Response r = upload(crl(1, ago(Duration.ofMinutes(1))).issuer("CN=No CRL", interKey));
        assertEquals(400, r.status());
        assertTrue(r.error().contains("cRLSign"), r.error());
    }

    @Test
    void missingCrlNumberIsRejected() throws Exception {
        start();
        Crl c = new Crl(null, ago(Duration.ofMinutes(1)));
        Response r = upload(c);
        assertEquals(400, r.status());
        assertTrue(r.error().contains("no CRL Number"), r.error());
    }

    @Test
    void deltaCrlIsRejected() throws Exception {
        start();
        Response r = upload(crl(1, ago(Duration.ofMinutes(1))).delta());
        assertEquals(400, r.status());
        assertTrue(r.error().contains("delta CRLs are not supported"), r.error());
    }

    @Test
    void nextUpdateIsRequiredAndInTheFuture() throws Exception {
        start();
        Response r = upload(crl(1, ago(Duration.ofMinutes(1))).noNextUpdate());
        assertEquals(400, r.status());
        assertTrue(r.error().contains("no nextUpdate"), r.error());

        r = upload(crl(1, ago(Duration.ofDays(10))).nextUpdate(ago(Duration.ofDays(1))));
        assertEquals(400, r.status());
        assertTrue(r.error().contains("expired"), r.error());

        r = upload(crl(1, in(Duration.ofDays(10))).nextUpdate(in(Duration.ofDays(9))));
        assertEquals(400, r.status());
        assertTrue(r.error().contains("is not before nextUpdate"), r.error());
    }

    @Test
    void horizonIsEnforced() throws Exception {
        start(", \"crlMaxFutureDays\": 30");
        Response r = upload(crl(1, in(Duration.ofDays(31))));
        assertEquals(400, r.status());
        assertTrue(r.error().contains("more than 30 days in the future"), r.error());
        assertEquals(200, upload(crl(1, in(Duration.ofDays(29)))).status());
    }

    @Test
    void defaultHorizonIsAboutAYear() throws Exception {
        start();
        assertEquals(400, upload(crl(1, in(Duration.ofDays(400)))).status());
        assertEquals(200, upload(crl(1, in(Duration.ofDays(300)))).status());
    }

    // ------------------------------------------------------------------ CRL rules

    @Test
    void rule1NumbersOnlyGoUp() throws Exception {
        start();
        assertEquals(200, upload(crl(5, ago(Duration.ofMinutes(10)))).status());
        Response r = upload(crl(5, ago(Duration.ofMinutes(5))));
        assertEquals(409, r.status());
        assertTrue(r.error().contains("CRL Number 5 is not greater than 5"), r.error());
        r = upload(crl(4, ago(Duration.ofMinutes(5))));
        assertEquals(409, r.status());

        // also against pending ones
        assertEquals(200, upload(crl(10, in(Duration.ofDays(3)))).status());
        r = upload(crl(8, in(Duration.ofDays(5))));
        assertEquals(409, r.status());
        assertTrue(r.error().contains("not greater than 10"), r.error());
    }

    @Test
    void rule2TimeGoesUpWithNumbers() throws Exception {
        start();
        assertEquals(200, upload(crl(1, ago(Duration.ofMinutes(10)))).status());
        Response r = upload(crl(2, ago(Duration.ofHours(1))));
        assertEquals(409, r.status());
        assertTrue(r.error().contains("before that of the current CRL #1"), r.error());

        assertEquals(200, upload(crl(3, in(Duration.ofDays(10)))).status());
        r = upload(crl(4, in(Duration.ofDays(5))));
        assertEquals(409, r.status());
        assertTrue(r.error().contains("before that of pending CRL #3"), r.error());
        assertNull(state(4));
    }

    @Test
    void rule5NoUnrevoking() throws Exception {
        start();
        assertEquals(200, upload(crl(1, ago(Duration.ofMinutes(10))).revoke(0xa1, 0xb2)).status());
        Response r = upload(crl(2, ago(Duration.ofMinutes(5))).revoke(0xb2));
        assertEquals(409, r.status());
        assertTrue(r.error().contains("are missing") && r.error().contains("a1"), r.error());
        assertFalse(r.error().contains("b2"), r.error());
        assertNull(state(2));

        // also for pending ones
        r = upload(crl(2, in(Duration.ofDays(5))));
        assertEquals(409, r.status());
        assertNull(state(2));

        // adding serials is fine
        r = upload(crl(2, ago(Duration.ofMinutes(5))).revoke(0xa1, 0xb2, 0xc3));
        assertEquals(200, r.status(), r.json().toString());
    }

    @Test
    void mixedResultsInOneBody() throws Exception {
        start();
        Response r = upload(crl(1, ago(Duration.ofMinutes(1))), crl(2, in(Duration.ofDays(5))).delta());
        assertEquals(400, r.status());
        assertEquals("current", r.result(0).get("result").getAsString());
        assertEquals("rejected", r.result(1).get("result").getAsString());
        assertTrue(r.result(1).get("error").getAsString().contains("delta"));
    }

    @Test
    void stateSurvivesRestart() throws Exception {
        start();
        assertEquals(200, upload(crl(1, ago(Duration.ofMinutes(1))), crl(2, in(Duration.ofDays(5)))).status());
        server.stop();
        store = null;
        server = null;
        Store reopened = Store.open(dir.resolve("data"));
        assertEquals(CrlState.CURRENT, reopened.crl("root2026", BigInteger.ONE).state());
        assertEquals(CrlState.PENDING, reopened.crl("root2026", BigInteger.TWO).state());
    }
}
