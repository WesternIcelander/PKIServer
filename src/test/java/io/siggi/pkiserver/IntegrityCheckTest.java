package io.siggi.pkiserver;

import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoreException;
import io.siggi.pkiserver.x509.X509Util;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
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
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class IntegrityCheckTest {
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final AtomicLong SERIALS = new AtomicLong(1000);

    @TempDir
    Path dir;
    private Path data;

    private KeyPair rootKey, tls2Key, issuingKey;
    private X509Certificate root, tls2, issuing, leaf;

    @BeforeEach
    void setUp() throws Exception {
        data = dir.resolve("data");
        rootKey = keyPair();
        tls2Key = keyPair();
        issuingKey = keyPair();
        root = cert("CN=Siggi.io", "CN=Siggi.io", rootKey, rootKey, true, NOW.minus(Duration.ofDays(1)));
        tls2 = cert("CN=TLS 2", "CN=Siggi.io", tls2Key, rootKey, true, NOW.minus(Duration.ofDays(1)));
        issuing = cert("CN=TLS 2 Issuing", "CN=TLS 2", issuingKey, tls2Key, true, NOW.minus(Duration.ofDays(1)));
        leaf = cert("CN=www.example.com", "CN=TLS 2 Issuing", keyPair(), issuingKey, false,
                NOW.minus(Duration.ofDays(1)));
        Store store = Store.open(data);
        store.addSigningCert("root2026", root);
        store.addSigningCert("tls2", tls2);
        store.addSigningCert("tls2issuing", issuing);
        store.addEndEntityCert("tls2issuing", leaf, NOW);
        store.addCrl("tls2", crl("CN=TLS 2", tls2Key, 1, NOW.minusSeconds(60)), CrlState.CURRENT, NOW);
        store.addCrl("tls2", crl("CN=TLS 2", tls2Key, 2, NOW.plus(Duration.ofDays(3))), CrlState.PENDING, NOW);
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    private static X509Certificate cert(String subject, String issuer, KeyPair key, KeyPair issuerKey, boolean ca,
                                        Instant notBefore) throws Exception {
        return cert(subject, issuer, key, issuerKey, ca, notBefore, notBefore.plus(Duration.ofDays(30)), null);
    }

    private static X509Certificate cert(String subject, String issuer, KeyPair key, KeyPair issuerKey, boolean ca,
                                        Instant notBefore, Instant notAfter, KeyUsage keyUsage) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(SERIALS.incrementAndGet()), Date.from(notBefore), Date.from(notAfter),
                new X500Name(subject), key.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (keyUsage != null) b.addExtension(Extension.keyUsage, true, keyUsage);
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate())));
    }

    private static X509CRL crl(String issuer, KeyPair key, long number, Instant thisUpdate) throws Exception {
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name(issuer), Date.from(thisUpdate));
        b.setNextUpdate(Date.from(thisUpdate.plus(Duration.ofDays(7))));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        return new JcaX509CRLConverter().getCRL(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key.getPrivate())));
    }

    private Store reopen() throws Exception {
        Store store = Store.open(data);
        new IntegrityCheck(store).run();
        return store;
    }

    private static List<String> slugs(Store store) {
        return store.signingCerts().stream().map(SigningCert::slug).toList();
    }

    private String leafSerial() {
        return X509Util.formatSerial(leaf.getSerialNumber());
    }

    @Test
    void everythingValidIsKept() throws Exception {
        Store store = Store.open(data);
        assertEquals(List.of(), new IntegrityCheck(store).run());
        assertEquals(List.of("root2026", "tls2", "tls2issuing"), slugs(store));
        assertEquals(2, store.crls("tls2").size());
        assertNotNull(store.endEntityCert("tls2issuing", leafSerial()));
    }

    @Test
    void removedRootWithholdsEverythingBelowIt() throws Exception {
        // Remove the root by hand (stop server, delete directory).
        Path rootDir = data.resolve("ca/root2026");
        try (var files = Files.walk(rootDir)) {
            files.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
        Store store = Store.open(data);
        List<String> withheld = new IntegrityCheck(store).run();
        assertEquals(2, withheld.size(), withheld.toString());
        assertEquals(List.of(), slugs(store));
        assertNull(store.endEntityCert("tls2issuing", leafSerial()));
        assertNull(store.currentCrl("tls2"));

        // Files are untouched: slugs stay taken, and reinstalling the root brings it all back.
        assertTrue(Files.exists(data.resolve("ca/tls2/cert.der")));
        assertTrue(Files.exists(data.resolve("ca/tls2/crl/1.crl")));
        assertThrows(StoreException.class, () -> store.addSigningCert("tls2", tls2));
        store.addSigningCert("root2026", root);
        Store again = reopen();
        assertEquals(List.of("root2026", "tls2", "tls2issuing"), slugs(again));
        assertNotNull(again.endEntityCert("tls2issuing", leafSerial()));
        assertEquals(BigInteger.ONE, again.currentCrl("tls2").number());
    }

    @Test
    void slugsAreKeptAsTheyAre() throws Exception {
        // A hand-renamed intermediate directory keeps its name, not a slug derived from the CN.
        Files.move(data.resolve("ca/tls2"), data.resolve("ca/my-intermediate"));
        Store store = reopen();
        assertEquals(List.of("my-intermediate", "root2026", "tls2issuing"), slugs(store));
        assertTrue(Files.exists(data.resolve("ca/my-intermediate/cert.der")));
        assertFalse(Files.exists(data.resolve("ca/tls2")));
    }

    @Test
    void forgedObjectsAreWithheld() throws Exception {
        KeyPair evil = keyPair();
        // An intermediate signed by the wrong key, under the right issuer name.
        Store store = Store.open(data);
        X509Certificate forgedCa = cert("CN=TLS 9", "CN=Siggi.io", keyPair(), evil, true,
                NOW.minus(Duration.ofDays(1)));
        store.addSigningCert("tls9", forgedCa);
        // A CRL and an end-entity certificate signed by the wrong key.
        X509CRL forgedCrl = crl("CN=TLS 2", evil, 3, NOW.minusSeconds(30));
        store.addCrl("tls2", forgedCrl, CrlState.CURRENT, NOW);
        X509Certificate forgedLeaf = cert("CN=evil.example.com", "CN=TLS 2", keyPair(), evil, false,
                NOW.minus(Duration.ofDays(1)));
        store.addEndEntityCert("tls2", forgedLeaf, NOW);
        // A CA certificate stored as an end-entity certificate.
        X509Certificate caAsLeaf = cert("CN=Sub CA", "CN=TLS 2", keyPair(), tls2Key, true,
                NOW.minus(Duration.ofDays(1)));
        store.addEndEntityCert("tls2", caAsLeaf, NOW);

        Store reloaded = reopen();
        assertEquals(List.of("root2026", "tls2", "tls2issuing"), slugs(reloaded));
        assertNull(reloaded.crl("tls2", BigInteger.valueOf(3)));
        assertNull(reloaded.currentCrl("tls2"), "the forged current CRL is not served, nor an older one");
        assertNotNull(reloaded.crl("tls2", BigInteger.valueOf(2)), "the valid pending CRL is kept");
        assertEquals(BigInteger.valueOf(3), reloaded.highestCrlNumber("tls2"), "its number stays used");
        assertThrows(StoreException.class, () -> reloaded.addCrl("tls2",
                crl("CN=TLS 2", tls2Key, 3, NOW.minusSeconds(10)), CrlState.CURRENT, NOW));
        assertNull(reloaded.endEntityCert("tls2", X509Util.formatSerial(forgedLeaf.getSerialNumber())));
        assertNull(reloaded.endEntityCert("tls2", X509Util.formatSerial(caAsLeaf.getSerialNumber())));
        assertThrows(StoreException.class, () -> reloaded.addEndEntityCert("tls2", forgedLeaf, NOW));
        assertNotNull(reloaded.endEntityCert("tls2issuing", leafSerial()));
        assertTrue(Files.exists(data.resolve("ca/tls2/crl/3.crl")), "withheld files stay on disk");
    }

    @Test
    void badRootsAndIntermediatesAreWithheld() throws Exception {
        Store store = Store.open(data);
        // A self-signed non-CA placed as a root by hand.
        KeyPair k = keyPair();
        store.addSigningCert("notaca", cert("CN=Not A CA", "CN=Not A CA", k, k, false,
                NOW.minus(Duration.ofDays(1))));
        // An intermediate without keyCertSign.
        store.addSigningCert("nosign", cert("CN=No Sign", "CN=Siggi.io", keyPair(), rootKey, true,
                NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(30)), new KeyUsage(KeyUsage.cRLSign)));

        Store reloaded = reopen();
        assertEquals(List.of("root2026", "tls2", "tls2issuing"), slugs(reloaded));
    }

    @Test
    void expiryIsNotAFailure() throws Exception {
        // Valid when uploaded, expired now: still published.
        Store store = Store.open(data);
        X509Certificate old = cert("CN=old.example.com", "CN=TLS 2", keyPair(), tls2Key, false,
                NOW.minus(Duration.ofDays(1)), NOW.minus(Duration.ofHours(1)), null);
        store.addEndEntityCert("tls2", old, NOW);
        Store reloaded = reopen();
        assertNotNull(reloaded.endEntityCert("tls2", X509Util.formatSerial(old.getSerialNumber())));
    }

    @Test
    void serverRunsTheCheckAtStartup() throws Exception {
        Files.delete(data.resolve("ca/root2026/cert.der"));
        Path configFile = dir.resolve("config.json");
        Files.writeString(configFile, "{\"listen\": \"127.0.0.1:0\", \"dataDir\": \"data\"}");
        PKIServer server = new PKIServer(Config.load(configFile));
        server.start();
        try {
            assertEquals(List.of(), slugs(server.getStore()));
        } finally {
            server.stop();
        }
    }
}
