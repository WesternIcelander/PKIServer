package io.siggi.pkiserver;

import io.siggi.pkiserver.store.EndEntityCert;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.x509.X509Util;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class ChainBuilderTest {
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final AtomicLong SERIALS = new AtomicLong(1000);

    @TempDir
    Path dir;
    private Store store;
    private ChainBuilder chains;

    private KeyPair rootKey, tls2Key, issuingKey;
    private X509Certificate root, tls2, issuing;

    @BeforeEach
    void setUp() throws Exception {
        store = Store.open(dir.resolve("data"));
        chains = new ChainBuilder(store);
        rootKey = keyPair();
        tls2Key = keyPair();
        issuingKey = keyPair();
        root = cert("CN=Siggi.io", "CN=Siggi.io", rootKey, rootKey, true);
        tls2 = cert("CN=TLS 2", "CN=Siggi.io", tls2Key, rootKey, true);
        issuing = cert("CN=TLS 2 Issuing", "CN=TLS 2", issuingKey, tls2Key, true);
        store.addSigningCert("root2026", root);
        store.addSigningCert("tls2", tls2);
        store.addSigningCert("tls2issuing", issuing);
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    private static X509Certificate cert(String subject, String issuer, KeyPair key, KeyPair issuerKey, boolean ca)
            throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(SERIALS.incrementAndGet()), Date.from(NOW.minus(Duration.ofDays(1))),
                Date.from(NOW.plus(Duration.ofDays(30))), new X500Name(subject), key.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate())));
    }

    private EndEntityCert leaf(String slug, KeyPair issuerKey, String issuerDn) throws Exception {
        X509Certificate cert = cert("CN=www.example.com", issuerDn, keyPair(), issuerKey, false);
        store.addEndEntityCert(slug, cert, NOW);
        return store.endEntityCert(slug, X509Util.formatSerial(cert.getSerialNumber()));
    }

    private static List<String> slugs(List<SigningCert> chain) {
        return chain.stream().map(SigningCert::slug).toList();
    }

    private static List<X509Certificate> parse(String pem) throws Exception {
        if (pem.isEmpty()) return List.of();
        return X509Util.parseCertificates(pem.getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void chainIsIssuerFirstAndExcludesTheRoot() throws Exception {
        assertEquals(List.of("tls2issuing", "tls2"), slugs(chains.chain("tls2issuing")));
        assertEquals(List.of("tls2"), slugs(chains.chain("tls2")));

        EndEntityCert ee = leaf("tls2issuing", issuingKey, "CN=TLS 2 Issuing");
        assertEquals(List.of(issuing, tls2), parse(chains.chainPem(ee)));
        assertEquals(List.of(ee.cert(), issuing, tls2), parse(chains.fullchainPem(ee)));
        assertEquals(X509Util.pem(ee.cert()) + chains.chainPem(ee), chains.fullchainPem(ee));
    }

    @Test
    void leafIssuedByRootHasAnEmptyChain() throws Exception {
        assertEquals(List.of(), chains.chain("root2026"));
        EndEntityCert ee = leaf("root2026", rootKey, "CN=Siggi.io");
        assertEquals("", chains.chainPem(ee));
        assertEquals(X509Util.pem(ee.cert()), chains.fullchainPem(ee));
    }

    @Test
    void unknownSlugHasNoChain() {
        assertNull(chains.chain("nope"));
    }

    @Test
    void builtFromInstalledCertsAtServeTime() throws Exception {
        EndEntityCert ee = leaf("tls2issuing", issuingKey, "CN=TLS 2 Issuing");
        assertNotNull(chains.chainPem(ee));

        // Removing a CA in the middle breaks the path: nothing is served from a stale chain.
        store.removeSigningCert("tls2");
        assertNull(chains.chain("tls2issuing"));
        assertNull(chains.chainPem(ee));
        assertNull(chains.fullchainPem(ee));

        // Reinstalling it restores the chain, with no cached state in between.
        store.addSigningCert("tls2", tls2);
        assertEquals(List.of(issuing, tls2), parse(chains.chainPem(ee)));

        // Same with the root.
        store.removeSigningCert("root2026");
        assertNull(chains.chain("tls2"));
    }
}
