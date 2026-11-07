package io.siggi.pkiserver.x509;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** PEM encoding and decoding (RFC 7468). */
public final class Pem {
    public static final String CERTIFICATE = "CERTIFICATE";
    public static final String X509_CRL = "X509 CRL";

    private static final Pattern BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END ([A-Z0-9 ]+)-----", Pattern.DOTALL);
    private static final Pattern BEGIN = Pattern.compile("-----BEGIN ");

    private Pem() {
    }

    /** One decoded PEM block. */
    public record Block(String label, byte[] der) {
    }

    /** Encodes {@code der} as one PEM block with 64-character lines and {@code \n} line endings. */
    public static String encode(String label, byte[] der) {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    /** Whether {@code data} looks like PEM text rather than DER. */
    public static boolean looksLikePem(byte[] data) {
        return BEGIN.matcher(new String(data, StandardCharsets.ISO_8859_1)).find();
    }

    /**
     * Decodes all PEM blocks in {@code text}. Text between blocks (e.g. the
     * {@code subject=...} lines openssl prints) is ignored.
     */
    public static List<Block> decode(String text) throws InvalidX509Exception {
        List<Block> blocks = new ArrayList<>();
        Matcher m = BLOCK.matcher(text);
        int begins = 0;
        Matcher b = BEGIN.matcher(text);
        while (b.find()) {
            begins++;
        }
        while (m.find()) {
            String label = m.group(1);
            if (!label.equals(m.group(3))) {
                throw new InvalidX509Exception("PEM block BEGIN " + label + " ends with END " + m.group(3));
            }
            String body = m.group(2);
            if (body.contains(":")) {
                throw new InvalidX509Exception("PEM headers are not supported (block " + label + ")");
            }
            byte[] der;
            try {
                der = Base64.getDecoder().decode(body.replaceAll("\\s+", ""));
            } catch (IllegalArgumentException e) {
                throw new InvalidX509Exception("invalid base64 in PEM block " + label, e);
            }
            if (der.length == 0) {
                throw new InvalidX509Exception("empty PEM block " + label);
            }
            blocks.add(new Block(label, der));
        }
        if (blocks.size() != begins) {
            throw new InvalidX509Exception("unterminated or malformed PEM block");
        }
        return blocks;
    }
}
