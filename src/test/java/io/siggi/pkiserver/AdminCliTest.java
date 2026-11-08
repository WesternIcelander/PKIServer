package io.siggi.pkiserver;

import io.siggi.pkiserver.store.CaRole;
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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AdminCliTest {
    private static KeyPair rootKey;
    private static KeyPair interKey;
    private static X509Certificate root;
    private static X509Certificate inter;
    private static X509Certificate selfSignedLeaf;
    private static X509Certificate badSignature;

    @BeforeAll
    static void setUp() throws Exception {
        rootKey = keyPair();
        interKey = keyPair();
        root = cert("CN=Siggi.io", rootKey.getPublic(), "CN=Siggi.io", rootKey, true);
        inter = cert("CN=TLS 2", interKey.getPublic(), "CN=Siggi.io", rootKey, true);
        selfSignedLeaf = cert("CN=example.com", interKey.getPublic(), "CN=example.com", interKey, false);
        // Claims to be self-signed, but signed by a different key.
        badSignature = cert("CN=Fake Root", rootKey.getPublic(), "CN=Fake Root", interKey, true);
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    private static X509Certificate cert(String subject, PublicKey key, String issuer, KeyPair issuerKey, boolean ca)
            throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer), BigInteger.ONE,
                Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(30))),
                new X500Name(subject), key);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate())));
    }

    private static X509CRL crl() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name("CN=Siggi.io"), Date.from(now.minusSeconds(60)));
        b.setNextUpdate(Date.from(now.plus(Duration.ofDays(7))));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(7)));
        return new JcaX509CRLConverter().getCRL(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootKey.getPrivate())));
    }

    private record Result(int code, String out, String err) {
    }

    private static Result run(Path dataDir, String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = new AdminCli(dataDir, new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8)).run(Arrays.asList(args));
        return new Result(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private static Path write(Path dir, String name, byte[] data) throws Exception {
        Path file = dir.resolve(name);
        Files.write(file, data);
        return file;
    }

    @Test
    void addRootListRemove(@TempDir Path dir) throws Exception {
        Path data = dir.resolve("data");
        Path pem = write(dir, "root.pem", X509Util.pem(root).getBytes(StandardCharsets.US_ASCII));

        Result r = run(data, "add-root", "root2026", pem.toString());
        assertEquals(AdminCli.OK, r.code(), r.err());
        assertTrue(r.out().contains("Installed root CN=Siggi.io as \"root2026\""), r.out());
        assertArrayEquals(root.getEncoded(), Files.readAllBytes(data.resolve("ca/root2026/cert.der")));
        assertEquals(CaRole.ROOT, Store.open(data).signingCert("root2026").role());

        // Identical re-install is a no-op; DER input works too.
        Path der = write(dir, "root.der", root.getEncoded());
        r = run(data, "add-root", "root2026", der.toString());
        assertEquals(AdminCli.OK, r.code(), r.err());
        assertTrue(r.out().contains("already installed"), r.out());

        Store store = Store.open(data);
        store.addSigningCert("tls2", inter);
        store.addCrl("root2026", crl(), CrlState.CURRENT, Instant.now());

        r = run(data, "list");
        assertEquals(AdminCli.OK, r.code(), r.err());
        List<String> lines = r.out().lines().toList();
        assertEquals(3, lines.size(), r.out());
        assertTrue(lines.get(0).startsWith("SLUG"), r.out());
        assertTrue(lines.get(1).matches("root2026 +root +CN=Siggi\\.io +\\S+ +#7 +0"), lines.get(1));
        assertTrue(lines.get(2).matches("tls2 +intermediate +CN=TLS 2 +\\S+ +- +0"), lines.get(2));

        r = run(data, "remove", "root2026");
        assertEquals(AdminCli.OK, r.code(), r.err());
        assertTrue(r.out().contains("with 1 CRL(s)"), r.out());
        assertTrue(r.out().contains("no longer validate: tls2"), r.out());
        assertFalse(Files.exists(data.resolve("ca/root2026")));
        assertNull(Store.open(data).signingCert("root2026"));

        r = run(data, "remove", "root2026");
        assertEquals(AdminCli.FAILED, r.code());
        assertTrue(r.err().contains("no signing certificate \"root2026\""), r.err());
    }

    @Test
    void listEmpty(@TempDir Path dir) {
        Result r = run(dir, "list");
        assertEquals(AdminCli.OK, r.code());
        assertTrue(r.out().startsWith("No signing certificates"), r.out());
    }

    @Test
    void addRootRejectsBadSlugs(@TempDir Path dir) throws Exception {
        Path file = write(dir, "root.der", root.getEncoded());
        for (String slug : new String[]{"Root2026", "root 2026", "a/b", "..", ".", "api", "index.html", "ä"}) {
            Result r = run(dir.resolve("data"), "add-root", slug, file.toString());
            assertEquals(AdminCli.FAILED, r.code(), slug);
            assertTrue(r.err().contains("slug"), slug + ": " + r.err());
        }
        assertFalse(Files.exists(dir.resolve("data/ca")), "nothing is written for a bad slug");
    }

    @Test
    void addRootRejectsTakenSlugAndDuplicateKey(@TempDir Path dir) throws Exception {
        Path data = dir.resolve("data");
        Store.open(data).addSigningCert("tls2", inter);
        Path file = write(dir, "root.der", root.getEncoded());

        Result r = run(data, "add-root", "tls2", file.toString());
        assertEquals(AdminCli.FAILED, r.code());
        assertTrue(r.err().contains("already used"), r.err());

        assertEquals(AdminCli.OK, run(data, "add-root", "root2026", file.toString()).code());
        r = run(data, "add-root", "other", file.toString());
        assertEquals(AdminCli.FAILED, r.code());
        assertTrue(r.err().contains("\"root2026\""), r.err());
    }

    @Test
    void addRootRejectsNonRoots(@TempDir Path dir) throws Exception {
        Path data = dir.resolve("data");
        Result r = run(data, "add-root", "tls2", write(dir, "inter.der", inter.getEncoded()).toString());
        assertEquals(AdminCli.FAILED, r.code());
        assertTrue(r.err().contains("not self-signed"), r.err());

        r = run(data, "add-root", "leaf", write(dir, "leaf.der", selfSignedLeaf.getEncoded()).toString());
        assertEquals(AdminCli.FAILED, r.code());
        assertTrue(r.err().contains("CA:TRUE"), r.err());

        r = run(data, "add-root", "fake", write(dir, "fake.der", badSignature.getEncoded()).toString());
        assertEquals(AdminCli.FAILED, r.code());
        assertTrue(r.err().contains("signature does not verify"), r.err());

        r = run(data, "add-root", "x", write(dir, "junk.der", "junk".getBytes()).toString());
        assertEquals(AdminCli.FAILED, r.code());

        r = run(data, "add-root", "x", dir.resolve("missing.der").toString());
        assertEquals(AdminCli.FAILED, r.code());
        assertTrue(r.err().contains("no such file"), r.err());

        String twoCerts = X509Util.pem(List.of(root, inter));
        r = run(data, "add-root", "x", write(dir, "two.pem", twoCerts.getBytes()).toString());
        assertEquals(AdminCli.FAILED, r.code());

        assertTrue(Store.open(data).signingCerts().isEmpty());
    }

    @Test
    void usageErrors(@TempDir Path dir) {
        assertEquals(AdminCli.USAGE, run(dir).code());
        assertEquals(AdminCli.USAGE, run(dir, "frobnicate").code());
        assertEquals(AdminCli.USAGE, run(dir, "add-root", "x").code());
        assertEquals(AdminCli.USAGE, run(dir, "list", "extra").code());
        Result r = run(dir, "remove");
        assertEquals(AdminCli.USAGE, r.code());
        assertTrue(r.err().contains("Usage:"), r.err());
    }

    @Test
    void sampleRootIsAccepted(@TempDir Path dir) throws Exception {
        Path sample = Path.of("sample-certificates/Siggi.io.crt");
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.exists(sample), "sample certificates not present");
        X509Certificate cert = X509Util.parseCertificate(Files.readAllBytes(sample));
        org.junit.jupiter.api.Assumptions.assumeTrue(
                cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()), "sample is not a root");
        Result r = run(dir, "add-root", "root2026", sample.toString());
        assertEquals(AdminCli.OK, r.code(), r.err());
    }
}
