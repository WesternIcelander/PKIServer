package io.siggi.pkiserver;

import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.DiscardedCrl;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoredCrl;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CrlSchedulerTest {
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final String ROOT_DN = "CN=Siggi.io";
    private static final String SLUG = "root2026";

    private static KeyPair rootKey;
    private static X509Certificate root;

    @TempDir
    Path dir;
    private Store store;
    private PKIServer server;

    @BeforeAll
    static void setUpRoot() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        rootKey = gen.generateKeyPair();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(ROOT_DN), BigInteger.ONE,
                Date.from(NOW.minus(Duration.ofDays(1))), Date.from(NOW.plus(Duration.ofDays(3650))),
                new X500Name(ROOT_DN), rootKey.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        root = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootKey.getPrivate())));
    }

    @AfterEach
    void stopServer() {
        if (server != null) server.stop();
    }

    private static X509CRL crl(long number, Instant thisUpdate, long... revoked) throws Exception {
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name(ROOT_DN), Date.from(thisUpdate));
        b.setNextUpdate(Date.from(thisUpdate.plus(Duration.ofDays(7))));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        for (long s : revoked) {
            b.addCRLEntry(BigInteger.valueOf(s), Date.from(NOW.minus(Duration.ofDays(2))), CRLReason.keyCompromise);
        }
        return new JcaX509CRLConverter().getCRL(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootKey.getPrivate())));
    }

    private Store store() throws Exception {
        if (store == null) {
            store = Store.open(dir.resolve("data"));
            store.addSigningCert(SLUG, root);
        }
        return store;
    }

    private CrlState state(long number) {
        StoredCrl c = store.crl(SLUG, BigInteger.valueOf(number));
        return c == null ? null : c.state();
    }

    private static BigInteger n(long number) {
        return BigInteger.valueOf(number);
    }

    @Test
    void nothingDueChangesNothing() throws Exception {
        store().addCrl(SLUG, crl(1, NOW.minus(Duration.ofHours(1))), CrlState.CURRENT, NOW);
        store.addCrl(SLUG, crl(2, NOW.plus(Duration.ofDays(1))), CrlState.PENDING, NOW);
        CrlScheduler scheduler = new CrlScheduler(store, Clock.systemUTC());
        assertNull(scheduler.promoteDue(SLUG, NOW));
        assertEquals(CrlState.CURRENT, state(1));
        assertEquals(CrlState.PENDING, state(2));
        assertEquals(NOW.plus(Duration.ofDays(1)), scheduler.runOnce(NOW));
    }

    @Test
    void dueCrlIsPromoted() throws Exception {
        store().addCrl(SLUG, crl(1, NOW.minus(Duration.ofHours(1)), 5), CrlState.CURRENT, NOW);
        store.addCrl(SLUG, crl(2, NOW.plus(Duration.ofDays(1)), 5), CrlState.PENDING, NOW);
        store.addCrl(SLUG, crl(3, NOW.plus(Duration.ofDays(2)), 5), CrlState.PENDING, NOW);
        CrlScheduler scheduler = new CrlScheduler(store, Clock.systemUTC());

        StoredCrl promoted = scheduler.promoteDue(SLUG, NOW.plus(Duration.ofDays(1)));
        assertEquals(n(2), promoted.number());
        assertEquals(CrlState.SUPERSEDED, state(1));
        assertEquals(CrlState.CURRENT, state(2));
        assertEquals(CrlState.PENDING, state(3));
        assertEquals(NOW.plus(Duration.ofDays(2)), scheduler.runOnce(NOW.plus(Duration.ofDays(1))));

        // Persisted: a reopened store sees the same states.
        Store reopened = Store.open(dir.resolve("data"));
        assertEquals(CrlState.SUPERSEDED, reopened.crl(SLUG, n(1)).state());
        assertEquals(CrlState.CURRENT, reopened.crl(SLUG, n(2)).state());
        assertEquals(CrlState.PENDING, reopened.crl(SLUG, n(3)).state());
    }

    @Test
    void highestDueCrlWinsAndJumpedOverOnesAreSuperseded() throws Exception {
        store().addCrl(SLUG, crl(1, NOW.minus(Duration.ofDays(10))), CrlState.CURRENT, NOW);
        store.addCrl(SLUG, crl(2, NOW.minus(Duration.ofDays(3))), CrlState.PENDING, NOW);
        store.addCrl(SLUG, crl(3, NOW.minus(Duration.ofDays(2))), CrlState.PENDING, NOW);
        store.addCrl(SLUG, crl(4, NOW.minus(Duration.ofDays(1))), CrlState.PENDING, NOW);
        store.addCrl(SLUG, crl(5, NOW.plus(Duration.ofDays(1))), CrlState.PENDING, NOW);

        assertNull(new CrlScheduler(store, Clock.systemUTC()).runOnce(NOW.plus(Duration.ofDays(1))));
        assertEquals(CrlState.SUPERSEDED, state(1));
        assertEquals(CrlState.SUPERSEDED, state(2));
        assertEquals(CrlState.SUPERSEDED, state(3));
        assertEquals(CrlState.SUPERSEDED, state(4));
        assertEquals(CrlState.CURRENT, state(5));
    }

    @Test
    void firstCrlIsPromotedWithoutCurrent() throws Exception {
        store().addCrl(SLUG, crl(7, NOW.minus(Duration.ofMinutes(1))), CrlState.PENDING, NOW);
        assertEquals(n(7), new CrlScheduler(store, Clock.systemUTC()).promoteDue(SLUG, NOW).number());
        assertEquals(CrlState.CURRENT, state(7));
    }

    @Test
    void rule5FailureDiscardsAndCurrentStays() throws Exception {
        store().addCrl(SLUG, crl(1, NOW.minus(Duration.ofHours(1)), 5, 6), CrlState.CURRENT, NOW);
        store.addCrl(SLUG, crl(2, NOW.minus(Duration.ofMinutes(1)), 5), CrlState.PENDING, NOW);

        assertNull(new CrlScheduler(store, Clock.systemUTC()).promoteDue(SLUG, NOW));
        assertEquals(CrlState.CURRENT, state(1));
        assertNull(state(2));
        List<DiscardedCrl> discarded = store.discardedCrls(SLUG);
        assertEquals(1, discarded.size());
        assertEquals(n(2), discarded.get(0).number());
        assertTrue(discarded.get(0).reason().contains("6"), discarded.get(0).reason());
        assertFalse(Files.exists(dir.resolve("data/ca/" + SLUG + "/crl/2.crl")));

        Store reopened = Store.open(dir.resolve("data"));
        assertEquals(1, reopened.discardedCrls(SLUG).size());
        assertEquals(n(2), reopened.highestCrlNumber(SLUG));
    }

    @Test
    void rule5FailureFallsBackToLowerDueCrl() throws Exception {
        store().addCrl(SLUG, crl(1, NOW.minus(Duration.ofDays(3)), 5), CrlState.CURRENT, NOW);
        store.addCrl(SLUG, crl(2, NOW.minus(Duration.ofDays(2)), 5), CrlState.PENDING, NOW);
        store.addCrl(SLUG, crl(3, NOW.minus(Duration.ofDays(1))), CrlState.PENDING, NOW);

        assertEquals(n(2), new CrlScheduler(store, Clock.systemUTC()).promoteDue(SLUG, NOW).number());
        assertEquals(CrlState.SUPERSEDED, state(1));
        assertEquals(CrlState.CURRENT, state(2));
        assertNull(state(3));
        assertEquals(n(3), store.discardedCrls(SLUG).get(0).number());
    }

    @Test
    void stalePendingOlderThanCurrentIsSuperseded() throws Exception {
        // As after a promotion interrupted between its two writes.
        store().addCrl(SLUG, crl(2, NOW.minus(Duration.ofDays(2))), CrlState.PENDING, NOW);
        store.addCrl(SLUG, crl(3, NOW.minus(Duration.ofDays(1))), CrlState.CURRENT, NOW);

        assertNull(new CrlScheduler(store, Clock.systemUTC()).promoteDue(SLUG, NOW));
        assertEquals(CrlState.SUPERSEDED, state(2));
        assertEquals(CrlState.CURRENT, state(3));
    }

    @Test
    void serverPromotesOnStartupAndOnTime() throws Exception {
        // Came due while the server was down.
        store().addCrl(SLUG, crl(1, NOW.minus(Duration.ofDays(2))), CrlState.CURRENT, NOW);
        store.addCrl(SLUG, crl(2, NOW.minus(Duration.ofDays(1))), CrlState.PENDING, NOW);
        store = null;

        server = new PKIServer(Config.parse(
                "{\"listen\": \"127.0.0.1:0\", \"dataDir\": \"data\", \"trustedProxies\": [\"127.0.0.1\"],"
                        + " \"limits\": {\"uploadsPerMinutePerIp\": 1000}}", dir));
        server.start();
        store = server.getStore();
        assertEquals(CrlState.CURRENT, state(2));
        assertEquals(CrlState.SUPERSEDED, state(1));

        // Uploaded as pending, due in a moment: promoted well before the one-minute safety net.
        Instant soon = Instant.now().truncatedTo(ChronoUnit.SECONDS).plus(Duration.ofSeconds(2));
        HttpResponse<String> r = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + server.getPort() + CrlUpload.PATH))
                .header("X-Forwarded-Proto", "https")
                .POST(HttpRequest.BodyPublishers.ofByteArray(crl(3, soon).getEncoded()))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode(), r.body());
        assertEquals(CrlState.PENDING, state(3));

        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while (state(3) != CrlState.CURRENT && System.nanoTime() < deadline) {
            Thread.sleep(50);
        }
        assertEquals(CrlState.CURRENT, state(3));
        assertEquals(CrlState.SUPERSEDED, state(2));
        assertFalse(Instant.now().isBefore(soon));
    }
}
