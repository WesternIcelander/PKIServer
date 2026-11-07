package io.siggi.pkiserver.store;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.siggi.pkiserver.x509.X509Util;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.file.Files;
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
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class StoreTest {
    private static KeyPair rootKey;
    private static KeyPair interKey;
    private static KeyPair leafKey;
    private static X509Certificate root;
    private static X509Certificate inter;
    private static X509Certificate leaf;

    @BeforeAll
    static void setUp() throws Exception {
        rootKey = keyPair();
        interKey = keyPair();
        leafKey = keyPair();
        root = cert("CN=Siggi.io", rootKey.getPublic(), "CN=Siggi.io", rootKey, BigInteger.valueOf(1), true, null);
        inter = cert("CN=TLS 2", interKey.getPublic(), "CN=Siggi.io", rootKey, BigInteger.valueOf(2), true, null);
        leaf = cert("CN=example.com", leafKey.getPublic(), "CN=TLS 2", interKey, new BigInteger("00a3f1", 16), false,
                "example.com");
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    private static X509Certificate cert(String subject, PublicKey key, String issuer, KeyPair issuerKey,
                                        BigInteger serial, boolean ca, String dns) throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer), serial,
                Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(30))),
                new X500Name(subject), key);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (dns != null) {
            b.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, dns)));
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate())));
    }

    private static X509CRL crl(String issuer, KeyPair key, long number, Instant thisUpdate) throws Exception {
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name(issuer), Date.from(thisUpdate));
        b.setNextUpdate(Date.from(thisUpdate.plus(Duration.ofDays(7))));
        b.addCRLEntry(BigInteger.valueOf(42), Date.from(thisUpdate), CRLReason.keyCompromise);
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        return new JcaX509CRLConverter().getCRL(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key.getPrivate())));
    }

    private static X509CRL interCrl(long number, Instant thisUpdate) throws Exception {
        return crl("CN=TLS 2", interKey, number, thisUpdate);
    }

    private static JsonObject json(Path file) throws Exception {
        return JsonParser.parseString(Files.readString(file)).getAsJsonObject();
    }

    private static Store populated(Path dir) throws Exception {
        Store store = Store.open(dir);
        assertTrue(store.addSigningCert("root2026", root));
        assertTrue(store.addSigningCert("tls2", inter));
        return store;
    }

    @Test
    void signingCertsAreStoredAndReloaded(@TempDir Path dir) throws Exception {
        Store store = populated(dir);
        assertFalse(store.addSigningCert("tls2", inter), "identical re-add is a no-op");

        Path caDir = dir.resolve("ca/tls2");
        assertArrayEquals(inter.getEncoded(), Files.readAllBytes(caDir.resolve("cert.der")));
        JsonObject meta = json(caDir.resolve("meta.json"));
        assertEquals("intermediate", meta.get("role").getAsString());
        assertEquals("CN=TLS 2", meta.get("subject").getAsString());
        assertEquals(X509Util.spkiSha256Hex(interKey.getPublic()), meta.get("spkiSha256").getAsString());
        assertEquals("root", json(dir.resolve("ca/root2026/meta.json")).get("role").getAsString());

        Store reloaded = Store.open(dir);
        assertEquals(List.of("root2026", "tls2"), reloaded.signingCerts().stream().map(SigningCert::slug).toList());
        SigningCert tls2 = reloaded.signingCert("tls2");
        assertEquals(inter, tls2.cert());
        assertEquals(CaRole.INTERMEDIATE, tls2.role());
        assertEquals(CaRole.ROOT, reloaded.signingCert("root2026").role());
        assertSame(tls2, reloaded.signingCert(new X500Principal("CN=TLS 2"), interKey.getPublic()));
        assertNull(reloaded.signingCert(new X500Principal("CN=TLS 2"), rootKey.getPublic()));
        assertEquals(List.of(tls2), reloaded.signingCertsBySubject(new X500Principal("CN=TLS 2")));
        assertTrue(reloaded.signingCertsBySubject(new X500Principal("CN=Nobody")).isEmpty());
        assertNull(reloaded.signingCert("nope"));
    }

    @Test
    void signingCertConflicts(@TempDir Path dir) throws Exception {
        Store store = populated(dir);
        StoreException e = assertThrows(StoreException.class, () -> store.addSigningCert("tls2", root));
        assertTrue(e.getMessage().contains("already used"), e.getMessage());
        e = assertThrows(StoreException.class, () -> store.addSigningCert("other", inter));
        assertTrue(e.getMessage().contains("\"tls2\""), e.getMessage());
        for (String bad : new String[]{"", ".", "..", "a/b", "UPPER", "a b"}) {
            assertThrows(StoreException.class, () -> store.addSigningCert(bad, inter), bad);
        }
    }

    @Test
    void handPlacedCertificatesArePickedUp(@TempDir Path dir) throws Exception {
        Path rootDir = dir.resolve("ca/root2026");
        Files.createDirectories(rootDir);
        Files.writeString(rootDir.resolve("cert.der"), X509Util.pem(root)); // PEM is accepted
        Path interDir = dir.resolve("ca/tls2");
        Files.createDirectories(interDir);
        Files.write(interDir.resolve("cert.der"), inter.getEncoded());
        Files.writeString(interDir.resolve("meta.json"), "{\"role\": \"root\"}"); // wrong: rebuilt

        Store store = Store.open(dir);
        assertEquals(CaRole.ROOT, store.signingCert("root2026").role());
        assertArrayEquals(root.getEncoded(), Files.readAllBytes(rootDir.resolve("cert.der")), "rewritten as DER");
        assertEquals("root", json(rootDir.resolve("meta.json")).get("role").getAsString());
        assertEquals("intermediate", json(interDir.resolve("meta.json")).get("role").getAsString());
        assertEquals(CaRole.INTERMEDIATE, store.signingCert("tls2").role());
    }

    @Test
    void brokenEntriesAreSkipped(@TempDir Path dir) throws Exception {
        populated(dir);
        Files.createDirectories(dir.resolve("ca/Bad Slug"));
        Files.write(dir.resolve("ca/Bad Slug/cert.der"), root.getEncoded());
        Files.createDirectories(dir.resolve("ca/empty"));
        Files.createDirectories(dir.resolve("ca/garbage"));
        Files.writeString(dir.resolve("ca/garbage/cert.der"), "not a certificate");
        Files.createDirectories(dir.resolve("ca/tls2-copy"));
        Files.write(dir.resolve("ca/tls2-copy/cert.der"), inter.getEncoded()); // same subject + key as tls2: first slug wins
        Files.writeString(dir.resolve("ca/tls2/.cert.der.123.tmp"), "leftover");

        Store store = Store.open(dir);
        assertEquals(List.of("root2026", "tls2"), store.signingCerts().stream().map(SigningCert::slug).toList());
        assertFalse(Files.exists(dir.resolve("ca/tls2/.cert.der.123.tmp")), "temp files are cleaned up");
        assertThrows(StoreException.class, () -> store.addSigningCert("garbage", leaf),
                "doesn't overwrite an unloadable cert.der");
    }

    @Test
    void removeSigningCert(@TempDir Path dir) throws Exception {
        Store store = populated(dir);
        store.addCrl("tls2", interCrl(1, Instant.now().minusSeconds(60)), CrlState.CURRENT, Instant.now());
        store.addEndEntityCert("tls2", leaf, Instant.now());
        store.removeSigningCert("tls2");
        assertNull(store.signingCert("tls2"));
        assertNull(store.signingCert(new X500Principal("CN=TLS 2"), interKey.getPublic()));
        assertTrue(store.signingCertsBySubject(new X500Principal("CN=TLS 2")).isEmpty());
        assertFalse(Files.exists(dir.resolve("ca/tls2")));
        assertThrows(StoreException.class, () -> store.removeSigningCert("tls2"));
        assertTrue(store.addSigningCert("tls2", inter), "slug can be reused after removal");
        assertTrue(store.crls("tls2").isEmpty());
    }

    @Test
    void crlsAreStoredWithStateAndReloaded(@TempDir Path dir) throws Exception {
        Store store = populated(dir);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant received = now.minusSeconds(5);
        StoredCrl c1 = store.addCrl("tls2", interCrl(1, now.minusSeconds(3600)), CrlState.CURRENT, received);
        assertSame(c1, store.addCrl("tls2", c1.crl(), CrlState.CURRENT, now), "identical re-add is a no-op");
        store.addCrl("tls2", interCrl(2, now.plus(Duration.ofDays(5))), CrlState.PENDING, received);
        store.addCrl("tls2", interCrl(3, now.plus(Duration.ofDays(10))), CrlState.PENDING, received);
        StoredCrl c4 = store.addCrl("tls2", interCrl(4, now.minusSeconds(60)), CrlState.CURRENT, received);

        assertEquals(c4, store.currentCrl("tls2"));
        assertEquals(CrlState.SUPERSEDED, store.crl("tls2", BigInteger.ONE).state());
        assertEquals(BigInteger.valueOf(4), store.highestCrlNumber("tls2"));

        Path crlDir = dir.resolve("ca/tls2/crl");
        assertArrayEquals(c4.der(), Files.readAllBytes(crlDir.resolve("4.crl")));
        JsonObject m4 = json(crlDir.resolve("4.json"));
        assertEquals("current", m4.get("state").getAsString());
        assertEquals(received.toString(), m4.get("receivedAt").getAsString());
        assertEquals(c4.thisUpdate().toString(), m4.get("thisUpdate").getAsString());
        assertEquals(c4.nextUpdate().toString(), m4.get("nextUpdate").getAsString());
        assertEquals("superseded", json(crlDir.resolve("1.json")).get("state").getAsString());

        DiscardedCrl d = store.discardCrl("tls2", BigInteger.valueOf(3), now, "superseded by emergency CRL 4");
        assertEquals(BigInteger.valueOf(3), d.number());
        assertFalse(Files.exists(crlDir.resolve("3.crl")));
        assertFalse(Files.exists(crlDir.resolve("3.json")));
        JsonArray discarded = JsonParser.parseString(Files.readString(crlDir.resolve("discarded.json"))).getAsJsonArray();
        assertEquals(1, discarded.size());
        assertEquals("3", discarded.get(0).getAsJsonObject().get("number").getAsString());

        assertThrows(StoreException.class,
                () -> store.addCrl("tls2", interCrl(3, now), CrlState.PENDING, now), "discarded number");
        assertThrows(StoreException.class,
                () -> store.addCrl("tls2", interCrl(4, now), CrlState.PENDING, now), "number in use");
        assertThrows(StoreException.class,
                () -> store.addCrl("tls2", crl("CN=Siggi.io", rootKey, 9, now), CrlState.PENDING, now),
                "wrong issuer");
        assertThrows(StoreException.class,
                () -> store.addCrl("nope", interCrl(9, now), CrlState.PENDING, now), "unknown slug");

        store.setCrlState("tls2", BigInteger.TWO, CrlState.SUPERSEDED);

        Store reloaded = Store.open(dir);
        List<StoredCrl> crls = reloaded.crls("tls2");
        assertEquals(List.of(BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(4)),
                crls.stream().map(StoredCrl::number).toList());
        assertEquals(List.of(CrlState.SUPERSEDED, CrlState.SUPERSEDED, CrlState.CURRENT),
                crls.stream().map(StoredCrl::state).toList());
        assertEquals(received, reloaded.currentCrl("tls2").receivedAt());
        assertEquals(c4.crl(), reloaded.currentCrl("tls2").crl());
        assertEquals(List.of(d), reloaded.discardedCrls("tls2"));
        assertEquals(BigInteger.valueOf(4), reloaded.highestCrlNumber("tls2"));
        assertTrue(reloaded.crls("root2026").isEmpty());
        assertNull(reloaded.highestCrlNumber("root2026"));
    }

    @Test
    void highestCrlNumberCountsDiscarded(@TempDir Path dir) throws Exception {
        Store store = populated(dir);
        Instant now = Instant.now();
        store.addCrl("tls2", interCrl(1, now.minusSeconds(60)), CrlState.CURRENT, now);
        store.addCrl("tls2", interCrl(7, now.plus(Duration.ofDays(3))), CrlState.PENDING, now);
        store.discardCrl("tls2", BigInteger.valueOf(7), now, "test");
        assertEquals(BigInteger.valueOf(7), store.highestCrlNumber("tls2"));
        assertEquals(BigInteger.valueOf(7), Store.open(dir).highestCrlNumber("tls2"));
    }

    @Test
    void crlStateIsRebuiltWhenMetadataIsLostOrInconsistent(@TempDir Path dir) throws Exception {
        Store store = populated(dir);
        Instant now = Instant.now();
        store.addCrl("tls2", interCrl(1, now.minusSeconds(3600)), CrlState.CURRENT, now);
        store.addCrl("tls2", interCrl(2, now.minusSeconds(60)), CrlState.CURRENT, now);
        store.addCrl("tls2", interCrl(3, now.plus(Duration.ofDays(2))), CrlState.PENDING, now);
        Path crlDir = dir.resolve("ca/tls2/crl");

        // Metadata lost entirely: past CRLs -> highest becomes current, future -> pending.
        try (Stream<Path> s = Files.list(crlDir)) {
            for (Path p : s.filter(p -> p.toString().endsWith(".json")).toList()) Files.delete(p);
        }
        Store reloaded = Store.open(dir);
        assertEquals(List.of(CrlState.SUPERSEDED, CrlState.CURRENT, CrlState.PENDING),
                reloaded.crls("tls2").stream().map(StoredCrl::state).toList());
        assertEquals("current", json(crlDir.resolve("2.json")).get("state").getAsString());

        // Interrupted state change left two current CRLs: the highest wins.
        Files.writeString(crlDir.resolve("1.json"),
                Files.readString(crlDir.resolve("1.json")).replace("superseded", "current"));
        reloaded = Store.open(dir);
        assertEquals(BigInteger.TWO, reloaded.currentCrl("tls2").number());
        assertEquals("superseded", json(crlDir.resolve("1.json")).get("state").getAsString());

        // Interrupted discard (recorded but files still there): finished on load.
        reloaded.discardCrl("tls2", BigInteger.valueOf(3), now, "test");
        Files.write(crlDir.resolve("3.crl"), interCrl(3, now.plus(Duration.ofDays(2))).getEncoded());
        reloaded = Store.open(dir);
        assertNull(reloaded.crl("tls2", BigInteger.valueOf(3)));
        assertFalse(Files.exists(crlDir.resolve("3.crl")));

        // Misnamed CRL files are ignored.
        Files.write(crlDir.resolve("5.crl"), interCrl(6, now).getEncoded());
        Files.write(crlDir.resolve("abc.crl"), interCrl(7, now).getEncoded());
        reloaded = Store.open(dir);
        assertEquals(List.of(BigInteger.ONE, BigInteger.TWO),
                reloaded.crls("tls2").stream().map(StoredCrl::number).toList());
    }

    @Test
    void unreadableDiscardedListSkipsTheCa(@TempDir Path dir) throws Exception {
        Store store = populated(dir);
        Instant now = Instant.now();
        store.addCrl("tls2", interCrl(1, now.plus(Duration.ofDays(1))), CrlState.PENDING, now);
        store.discardCrl("tls2", BigInteger.ONE, now, "test");
        Files.writeString(dir.resolve("ca/tls2/crl/discarded.json"), "{broken");
        assertNull(Store.open(dir).signingCert("tls2"),
                "a CA whose discarded numbers are unknown is not loaded");
    }

    @Test
    void endEntityCertsAreStoredAndReloaded(@TempDir Path dir) throws Exception {
        Store store = populated(dir);
        Instant uploaded = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        assertTrue(store.addEndEntityCert("tls2", leaf, uploaded));
        assertFalse(store.addEndEntityCert("tls2", leaf, Instant.now()), "identical re-add is a no-op");

        X509Certificate sameSerial = cert("CN=other.example", leafKey.getPublic(), "CN=TLS 2", interKey,
                leaf.getSerialNumber(), false, null);
        StoreException e = assertThrows(StoreException.class,
                () -> store.addEndEntityCert("tls2", sameSerial, uploaded));
        assertTrue(e.getMessage().contains("a3f1"), e.getMessage());
        assertThrows(StoreException.class, () -> store.addEndEntityCert("root2026", leaf, uploaded),
                "issuer mismatch");

        Path eeDir = dir.resolve("ca/tls2/certs/a3f1");
        assertArrayEquals(leaf.getEncoded(), Files.readAllBytes(eeDir.resolve("certificate.der")));
        JsonObject meta = json(eeDir.resolve("meta.json"));
        assertEquals("CN=example.com", meta.get("subject").getAsString());
        assertEquals("DNS:example.com", meta.getAsJsonArray("subjectAltNames").get(0).getAsString());
        assertEquals(uploaded.toString(), meta.get("uploadedAt").getAsString());
        assertEquals(leaf.getNotAfter().toInstant().toString(), meta.get("notAfter").getAsString());

        Store reloaded = Store.open(dir);
        EndEntityCert ee = reloaded.endEntityCert("tls2", "a3f1");
        assertEquals(leaf, ee.cert());
        assertEquals(uploaded, ee.uploadedAt());
        assertEquals(List.of(ee), reloaded.endEntityCerts("tls2"));
        assertNull(reloaded.endEntityCert("tls2", "a3f2"));
        assertTrue(reloaded.endEntityCerts("root2026").isEmpty());

        // Hand-placed end-entity cert without metadata, and one in the wrong directory.
        Files.delete(eeDir.resolve("meta.json"));
        Files.createDirectories(dir.resolve("ca/tls2/certs/ffff"));
        Files.write(dir.resolve("ca/tls2/certs/ffff/certificate.der"), leaf.getEncoded());
        reloaded = Store.open(dir);
        assertNotNull(reloaded.endEntityCert("tls2", "a3f1"));
        assertNull(reloaded.endEntityCert("tls2", "ffff"));
        assertTrue(Files.isRegularFile(eeDir.resolve("meta.json")), "metadata rebuilt");
    }

    @Test
    void noTemporaryFilesAreLeftBehind(@TempDir Path dir) throws Exception {
        Store store = populated(dir);
        Instant now = Instant.now();
        store.addCrl("tls2", interCrl(1, now.minusSeconds(60)), CrlState.CURRENT, now);
        store.addCrl("tls2", interCrl(2, now.minusSeconds(30)), CrlState.CURRENT, now);
        store.addEndEntityCert("tls2", leaf, now);
        try (Stream<Path> s = Files.walk(dir)) {
            assertEquals(List.of(), s.filter(p -> p.getFileName().toString().endsWith(".tmp")).toList());
        }
    }
}
