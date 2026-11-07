package io.siggi.pkiserver.x509;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
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
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class X509UtilTest {
    private static final Path SAMPLES = Path.of("sample-certificates");
    private static final String SIGGI_SKI = "83ce8faca405a7be4f245371cb395acd630ed7b0";

    private static KeyPair caKey;
    private static X509Certificate caCert;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        caKey = gen.generateKeyPair();
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        Instant now = Instant.now();
        X500Name name = new X500Name("CN=Test Root");
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, new BigInteger("00A3F1", 16),
                Date.from(now), Date.from(now.plus(Duration.ofDays(1))), name, caKey.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(caKey.getPublic()));
        caCert = new JcaX509CertificateConverter().getCertificate(b.build(signer()));
    }

    private static ContentSigner signer() throws Exception {
        return new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.getPrivate());
    }

    private static X509CRL crl(BigInteger number, boolean delta, boolean aki) throws Exception {
        Instant now = Instant.now();
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name("CN=Test Root"), Date.from(now));
        b.setNextUpdate(Date.from(now.plus(Duration.ofDays(7))));
        b.addCRLEntry(BigInteger.valueOf(42), Date.from(now), CRLReason.keyCompromise);
        if (number != null) {
            b.addExtension(Extension.cRLNumber, false, new CRLNumber(number));
        }
        if (delta) {
            b.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(BigInteger.ONE));
        }
        if (aki) {
            b.addExtension(Extension.authorityKeyIdentifier, false,
                    new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));
        }
        X509CRLHolder holder = b.build(signer());
        return new JcaX509CRLConverter().getCRL(holder);
    }

    private static byte[] sample(String file) throws Exception {
        Path p = SAMPLES.resolve(file);
        assumeTrue(Files.isRegularFile(p), "sample certificate not present: " + p);
        return Files.readAllBytes(p);
    }

    // ---- sample certificates ----

    @Test
    void sampleSlugs() throws Exception {
        assertEquals("tls2", X509Util.slugFor(X509Util.parseCertificate(sample("TLS_2.crt"))));
        assertEquals("tls", X509Util.slugFor(X509Util.parseCertificate(sample("TLS.crt"))));
        assertEquals("tls3", X509Util.slugFor(X509Util.parseCertificate(sample("TLS_3.crt"))));
        assertEquals("tls4", X509Util.slugFor(X509Util.parseCertificate(sample("TLS_4.crt"))));
        assertEquals("siggi.io", X509Util.slugFor(X509Util.parseCertificate(sample("Siggi.io.crt"))));
        assertEquals("stromno.com", X509Util.slugFor(X509Util.parseCertificate(sample("Stromno_MITM.crt"))));
    }

    @Test
    void sampleFields() throws Exception {
        X509Certificate root = X509Util.parseCertificate(sample("Siggi.io.crt"));
        X509Certificate tls2 = X509Util.parseCertificate(sample("TLS_2.crt"));
        assertEquals("CN=TLS 2", tls2.getSubjectX500Principal().getName());
        assertEquals("58575bf985bfbb08", X509Util.formatSerial(tls2.getSerialNumber()));
        assertEquals("243ef913d5973ae6", X509Util.formatSerial(root.getSerialNumber()));
        assertEquals("0371fe475267407767c8e1db0feff6b153eb585bd42097a6bb8fd9cf3ed4900a",
                X509Util.spkiSha256Hex(tls2.getPublicKey()));
        assertEquals("4151dcb2ea693893218e1f56f62635221d8460d75d7f6be30a30a4cfc6879fcb",
                X509Util.spkiSha256Hex(root.getPublicKey()));
        assertEquals("f91941fd604fa4a235d5136e7d85f87a8803eca7", X509Util.hex(X509Util.subjectKeyIdentifier(tls2)));
        assertEquals(SIGGI_SKI, X509Util.hex(X509Util.authorityKeyIdentifier(tls2)));
        assertEquals(SIGGI_SKI, X509Util.hex(X509Util.subjectKeyIdentifier(root)));
        tls2.verify(root.getPublicKey());
    }

    @Test
    void sampleMultiplePemBlocksAndDerRoundTrip() throws Exception {
        String[] files = {"Siggi.io.crt", "TLS.crt", "TLS_2.crt", "TLS_3.crt", "TLS_4.crt"};
        StringBuilder bundle = new StringBuilder();
        for (String f : files) {
            bundle.append("subject=whatever\n").append(new String(sample(f), StandardCharsets.US_ASCII)).append('\n');
        }
        List<X509Certificate> certs = X509Util.parseCertificates(bundle.toString().getBytes(StandardCharsets.US_ASCII));
        assertEquals(files.length, certs.size());
        assertEquals("tls", X509Util.slugFor(certs.get(1)));
        assertEquals("tls4", X509Util.slugFor(certs.get(4)));
        for (X509Certificate c : certs) {
            byte[] der = X509Util.der(c);
            assertEquals(c, X509Util.parseCertificate(der));
            assertEquals(c, X509Util.parseCertificate(X509Util.pem(c).getBytes(StandardCharsets.US_ASCII)));
        }
        String joined = X509Util.pem(certs);
        assertEquals(certs, X509Util.parseCertificates(joined.getBytes(StandardCharsets.US_ASCII)));
    }

    // ---- slug normalization ----

    @Test
    void normalizeSlug() {
        assertEquals("tls2", X509Util.normalizeSlug("TLS 2"));
        assertEquals("siggi.io", X509Util.normalizeSlug("Siggi.io"));
        assertEquals("a-b_c~d.e", X509Util.normalizeSlug("A-B_C~D.E"));
        assertEquals("ab", X509Util.normalizeSlug("a/b?#%&é"));
        assertEquals("", X509Util.normalizeSlug("   ///"));
        assertEquals("i", X509Util.normalizeSlug("I")); // Locale.ROOT: no Turkish dotless i
    }

    @Test
    void isValidSlug() {
        assertTrue(X509Util.isValidSlug("root2026"));
        assertTrue(X509Util.isValidSlug("siggi.io"));
        assertFalse(X509Util.isValidSlug(""));
        assertFalse(X509Util.isValidSlug(null));
        assertFalse(X509Util.isValidSlug("Root"));
        assertFalse(X509Util.isValidSlug("a/b"));
        assertFalse(X509Util.isValidSlug("tls 2"));
    }

    @Test
    void commonName() {
        assertEquals("TLS 2", X509Util.commonName(new X500Principal("CN=TLS 2, O=Siggi")));
        assertEquals("Leaf", X509Util.commonName(new X500Principal("CN=Leaf, OU=x, CN=Other")));
        assertNull(X509Util.commonName(new X500Principal("O=No CN")));
    }

    // ---- serial formatting ----

    @Test
    void formatSerial() {
        assertEquals("a3f1", X509Util.formatSerial(new BigInteger("00A3F1", 16)));
        assertEquals("0", X509Util.formatSerial(BigInteger.ZERO));
        assertEquals("1", X509Util.formatSerial(BigInteger.ONE));
        assertEquals("ff", X509Util.formatSerial(BigInteger.valueOf(-1)));
        assertEquals("ff7f", X509Util.formatSerial(BigInteger.valueOf(-129)));
        assertEquals("a3f1", X509Util.formatSerial(caCert.getSerialNumber()));
    }

    // ---- CRLs ----

    @Test
    void crlFields() throws Exception {
        X509CRL crl = crl(BigInteger.valueOf(1234567), false, true);
        assertEquals(BigInteger.valueOf(1234567), X509Util.crlNumber(crl));
        assertFalse(X509Util.isDeltaCrl(crl));
        assertArrayEquals(X509Util.subjectKeyIdentifier(caCert), X509Util.authorityKeyIdentifier(crl));
        crl.verify(caKey.getPublic());

        X509CRL bare = crl(null, false, false);
        assertNull(X509Util.crlNumber(bare));
        assertNull(X509Util.authorityKeyIdentifier(bare));
        assertNull(X509Util.authorityKeyIdentifier(caCert));

        assertTrue(X509Util.isDeltaCrl(crl(BigInteger.TWO, true, false)));
    }

    @Test
    void crlDerAndPem() throws Exception {
        X509CRL a = crl(BigInteger.ONE, false, true);
        X509CRL b = crl(BigInteger.TWO, false, true);
        assertEquals(a, X509Util.parseCrl(X509Util.der(a)));
        assertEquals(a, X509Util.parseCrl(X509Util.pem(a).getBytes(StandardCharsets.US_ASCII)));
        String both = X509Util.pem(a) + "\r\n" + X509Util.pem(b).replace("\n", "\r\n");
        List<X509CRL> crls = X509Util.parseCrls(both.getBytes(StandardCharsets.US_ASCII));
        assertEquals(List.of(a, b), crls);
        assertEquals(BigInteger.TWO, X509Util.crlNumber(crls.get(1)));
        assertTrue(X509Util.pem(a).startsWith("-----BEGIN X509 CRL-----\n"));
        assertThrows(InvalidX509Exception.class, () -> X509Util.parseCrl(both.getBytes(StandardCharsets.US_ASCII)));
    }

    // ---- error handling ----

    @Test
    void rejectsBadInput() throws Exception {
        byte[] der = X509Util.der(caCert);
        String pem = X509Util.pem(caCert);
        assertThrows(InvalidX509Exception.class, () -> X509Util.parseCertificates(new byte[0]));
        assertThrows(InvalidX509Exception.class, () -> X509Util.parseCertificates("hello".getBytes()));
        // truncated DER
        assertThrows(InvalidX509Exception.class, () -> X509Util.parseCertificates(Arrays.copyOf(der, der.length - 1)));
        // trailing garbage after DER
        assertThrows(InvalidX509Exception.class, () -> X509Util.parseCertificates(Arrays.copyOf(der, der.length + 1)));
        // a CRL where a certificate is expected, and vice versa
        assertThrows(InvalidX509Exception.class,
                () -> X509Util.parseCertificates(X509Util.pem(crl(BigInteger.ONE, false, false)).getBytes()));
        assertThrows(InvalidX509Exception.class, () -> X509Util.parseCrls(pem.getBytes()));
        assertThrows(InvalidX509Exception.class, () -> X509Util.parseCrls(der));
        // unterminated block
        assertThrows(InvalidX509Exception.class,
                () -> X509Util.parseCertificates((pem + "-----BEGIN CERTIFICATE-----\nMIIB\n").getBytes()));
        // mismatched END label
        assertThrows(InvalidX509Exception.class,
                () -> X509Util.parseCertificates(pem.replace("END CERTIFICATE", "END X509 CRL").getBytes()));
        // bad base64
        assertThrows(InvalidX509Exception.class,
                () -> X509Util.parseCertificates(pem.replaceFirst("\n", "\n!!").getBytes()));
        // two certs where one is expected
        assertThrows(InvalidX509Exception.class, () -> X509Util.parseCertificate((pem + pem).getBytes()));
    }

    @Test
    void pemEncodeFormat() {
        byte[] data = new byte[100];
        String pem = Pem.encode("TEST", data);
        String[] lines = pem.split("\n");
        assertEquals("-----BEGIN TEST-----", lines[0]);
        assertEquals(64, lines[1].length());
        assertEquals("-----END TEST-----", lines[lines.length - 1]);
        assertTrue(pem.endsWith("\n"));
        assertFalse(pem.contains("\r"));
    }
}
