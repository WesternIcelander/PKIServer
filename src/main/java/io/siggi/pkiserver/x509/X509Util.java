package io.siggi.pkiserver.x509;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/** Decoding, encoding and field extraction for X.509 certificates and CRLs, JDK only. */
public final class X509Util {
    public static final String OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
    public static final String OID_CRL_NUMBER = "2.5.29.20";
    public static final String OID_DELTA_CRL_INDICATOR = "2.5.29.27";
    public static final String OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";

    private static final HexFormat HEX = HexFormat.of();

    private X509Util() {
    }

    private static CertificateFactory factory() {
        try {
            return CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException("X.509 CertificateFactory unavailable", e);
        }
    }

    // ---- decoding ----

    /**
     * Decodes certificates from either a single DER certificate or PEM text holding one or
     * more {@code CERTIFICATE} blocks. Never returns an empty list.
     */
    public static List<X509Certificate> parseCertificates(byte[] data) throws InvalidX509Exception {
        List<X509Certificate> result = new ArrayList<>();
        for (byte[] der : derBlobs(data, Pem.CERTIFICATE, "certificate")) {
            result.add(parseCertificateDer(der));
        }
        return result;
    }

    /** Decodes exactly one certificate (DER or PEM). */
    public static X509Certificate parseCertificate(byte[] data) throws InvalidX509Exception {
        List<X509Certificate> certs = parseCertificates(data);
        if (certs.size() != 1) {
            throw new InvalidX509Exception("expected one certificate, found " + certs.size());
        }
        return certs.get(0);
    }

    /**
     * Decodes CRLs from either a single DER CRL or PEM text holding one or more
     * {@code X509 CRL} blocks. Never returns an empty list.
     */
    public static List<X509CRL> parseCrls(byte[] data) throws InvalidX509Exception {
        List<X509CRL> result = new ArrayList<>();
        for (byte[] der : derBlobs(data, Pem.X509_CRL, "CRL")) {
            result.add(parseCrlDer(der));
        }
        return result;
    }

    /** Decodes exactly one CRL (DER or PEM). */
    public static X509CRL parseCrl(byte[] data) throws InvalidX509Exception {
        List<X509CRL> crls = parseCrls(data);
        if (crls.size() != 1) {
            throw new InvalidX509Exception("expected one CRL, found " + crls.size());
        }
        return crls.get(0);
    }

    private static List<byte[]> derBlobs(byte[] data, String label, String what) throws InvalidX509Exception {
        if (data == null || data.length == 0) {
            throw new InvalidX509Exception("no " + what + " data");
        }
        if (isSingleDerSequence(data)) {
            return List.of(data);
        }
        if (!Pem.looksLikePem(data)) {
            if ((data[0] & 0xff) == Der.SEQUENCE) {
                Der.readSingle(data); // throws with the specific DER problem
            }
            throw new InvalidX509Exception("input is neither DER nor PEM");
        }
        List<byte[]> blobs = new ArrayList<>();
        for (Pem.Block block : Pem.decode(new String(data, StandardCharsets.US_ASCII))) {
            if (!block.label().equals(label)) {
                throw new InvalidX509Exception("unexpected PEM block \"" + block.label() + "\", expected \"" + label + "\"");
            }
            blobs.add(block.der());
        }
        if (blobs.isEmpty()) {
            throw new InvalidX509Exception("no " + what + " found");
        }
        return blobs;
    }

    private static boolean isSingleDerSequence(byte[] data) {
        if ((data[0] & 0xff) != Der.SEQUENCE) {
            return false;
        }
        try {
            Der.readSingle(data);
            return true;
        } catch (InvalidX509Exception e) {
            return false;
        }
    }

    private static X509Certificate parseCertificateDer(byte[] der) throws InvalidX509Exception {
        Der.Tlv outer = Der.readSingle(der);
        if (outer.tag() != Der.SEQUENCE) {
            throw new InvalidX509Exception("certificate is not a DER SEQUENCE");
        }
        try {
            return (X509Certificate) factory().generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException | RuntimeException e) {
            throw new InvalidX509Exception("invalid certificate: " + e.getMessage(), e);
        }
    }

    private static X509CRL parseCrlDer(byte[] der) throws InvalidX509Exception {
        Der.Tlv outer = Der.readSingle(der);
        if (outer.tag() != Der.SEQUENCE) {
            throw new InvalidX509Exception("CRL is not a DER SEQUENCE");
        }
        try {
            return (X509CRL) factory().generateCRL(new ByteArrayInputStream(der));
        } catch (CRLException | RuntimeException e) {
            throw new InvalidX509Exception("invalid CRL: " + e.getMessage(), e);
        }
    }

    // ---- encoding ----

    public static byte[] der(X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] der(X509CRL crl) {
        try {
            return crl.getEncoded();
        } catch (CRLException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String pem(X509Certificate cert) {
        return Pem.encode(Pem.CERTIFICATE, der(cert));
    }

    public static String pem(X509CRL crl) {
        return Pem.encode(Pem.X509_CRL, der(crl));
    }

    /** Concatenated PEM of all {@code certs}, in order. Empty string for an empty list. */
    public static String pem(List<X509Certificate> certs) {
        StringBuilder sb = new StringBuilder();
        for (X509Certificate cert : certs) {
            sb.append(pem(cert));
        }
        return sb.toString();
    }

    // ---- slugs ----

    /**
     * Normalizes a name to a slug: lowercase, then keep only RFC 3986 unreserved
     * characters ({@code a-z 0-9 - . _ ~}). May return an empty string.
     */
    public static String normalizeSlug(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder(lower.length());
        for (int i = 0; i < lower.length(); i++) {
            char c = lower.charAt(i);
            if (isSlugChar(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Whether {@code slug} is non-empty and consists only of slug characters. */
    public static boolean isValidSlug(String slug) {
        if (slug == null || slug.isEmpty()) {
            return false;
        }
        for (int i = 0; i < slug.length(); i++) {
            if (!isSlugChar(slug.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSlugChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
    }

    /**
     * The most specific CN of {@code subject}, or {@code null} if it has none.
     */
    public static String commonName(X500Principal subject) {
        LdapName name;
        try {
            name = new LdapName(subject.getName(X500Principal.RFC2253));
        } catch (InvalidNameException e) {
            return null;
        }
        // LdapName lists RDNs from least to most specific.
        List<Rdn> rdns = name.getRdns();
        for (int i = rdns.size() - 1; i >= 0; i--) {
            Rdn rdn = rdns.get(i);
            if (rdn.getType().equalsIgnoreCase("CN") && rdn.getValue() instanceof String s) {
                return s;
            }
        }
        return null;
    }

    /** Slug derived from the certificate's subject CN; empty if there is no usable CN. */
    public static String slugFor(X509Certificate cert) {
        String cn = commonName(cert.getSubjectX500Principal());
        return cn == null ? "" : normalizeSlug(cn);
    }

    // ---- serials ----

    /**
     * Serial number as lowercase hex, no separators, no leading zeros ({@code 0x00A3F1} →
     * {@code a3f1}). Negative serials (invalid, but they exist) are formatted from their
     * two's-complement encoding so the result is always plain hex.
     */
    public static String formatSerial(BigInteger serial) {
        if (serial.signum() >= 0) {
            return serial.toString(16);
        }
        return new BigInteger(1, serial.toByteArray()).toString(16);
    }

    // ---- hashes and identifiers ----

    /** SHA-256 of the DER SubjectPublicKeyInfo. */
    public static byte[] spkiSha256(PublicKey key) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** SHA-256 of the DER SubjectPublicKeyInfo, as lowercase hex. */
    public static String spkiSha256Hex(PublicKey key) {
        return hex(spkiSha256(key));
    }

    /** SHA-256 of arbitrary bytes, as lowercase hex (e.g. for the DER of a CRL). */
    public static String sha256Hex(byte[] data) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String hex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    /** Raw extension value with the outer OCTET STRING removed, or null if absent. */
    private static byte[] extension(X509Extension x, String oid) throws InvalidX509Exception {
        byte[] wrapped = x.getExtensionValue(oid);
        if (wrapped == null) {
            return null;
        }
        return Der.expect(wrapped, Der.OCTET_STRING);
    }

    /** Subject Key Identifier, or null if the certificate has none. */
    public static byte[] subjectKeyIdentifier(X509Certificate cert) throws InvalidX509Exception {
        byte[] ext = extension(cert, OID_SUBJECT_KEY_IDENTIFIER);
        return ext == null ? null : Der.expect(ext, Der.OCTET_STRING);
    }

    /**
     * The keyIdentifier field of the Authority Key Identifier of a certificate or CRL, or
     * null if there is no AKI or it has no keyIdentifier.
     */
    public static byte[] authorityKeyIdentifier(X509Extension certOrCrl) throws InvalidX509Exception {
        byte[] ext = extension(certOrCrl, OID_AUTHORITY_KEY_IDENTIFIER);
        if (ext == null) {
            return null;
        }
        byte[] seq = Der.expect(ext, Der.SEQUENCE);
        int pos = 0;
        while (pos < seq.length) {
            Der.Tlv field = Der.read(seq, pos);
            if (field.tag() == 0x80) { // [0] IMPLICIT KeyIdentifier
                return field.value();
            }
            pos = field.end();
        }
        return null;
    }

    /** CRL Number, or null if the CRL has none. */
    public static BigInteger crlNumber(X509CRL crl) throws InvalidX509Exception {
        byte[] ext = extension(crl, OID_CRL_NUMBER);
        return ext == null ? null : Der.integer(ext);
    }

    /** Whether the CRL carries a Delta CRL Indicator (delta CRLs are not supported). */
    public static boolean isDeltaCrl(X509CRL crl) {
        return crl.getExtensionValue(OID_DELTA_CRL_INDICATOR) != null;
    }
}
