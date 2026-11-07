package io.siggi.pkiserver.x509;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Minimal DER reader: just enough to unwrap the extension values the JDK doesn't decode
 * (SKI, AKI, CRL Number) and to check that a DER blob is exactly one TLV.
 * Only single-byte tags and definite lengths are supported, which is all DER allows
 * for the structures we read.
 */
public final class Der {
    public static final int INTEGER = 0x02;
    public static final int OCTET_STRING = 0x04;
    public static final int SEQUENCE = 0x30;

    private Der() {
    }

    /** One tag-length-value element, {@code end} is the offset just past it. */
    public record Tlv(int tag, byte[] value, int end) {
    }

    /** Reads the element starting at {@code offset}. */
    public static Tlv read(byte[] data, int offset) throws InvalidX509Exception {
        if (offset + 2 > data.length) {
            throw new InvalidX509Exception("truncated DER");
        }
        int tag = data[offset] & 0xff;
        if ((tag & 0x1f) == 0x1f) {
            throw new InvalidX509Exception("multi-byte DER tags not supported");
        }
        int pos = offset + 1;
        int first = data[pos++] & 0xff;
        long length;
        if (first < 0x80) {
            length = first;
        } else {
            int count = first & 0x7f;
            if (count == 0 || count > 4) {
                throw new InvalidX509Exception("unsupported DER length encoding");
            }
            if (pos + count > data.length) {
                throw new InvalidX509Exception("truncated DER");
            }
            length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | (data[pos++] & 0xff);
            }
        }
        if (length > data.length - pos) {
            throw new InvalidX509Exception("truncated DER");
        }
        int end = pos + (int) length;
        return new Tlv(tag, Arrays.copyOfRange(data, pos, end), end);
    }

    /** Reads {@code data} as exactly one element; trailing bytes are an error. */
    public static Tlv readSingle(byte[] data) throws InvalidX509Exception {
        Tlv tlv = read(data, 0);
        if (tlv.end() != data.length) {
            throw new InvalidX509Exception("trailing data after DER element");
        }
        return tlv;
    }

    /** Reads exactly one element and checks its tag. */
    public static byte[] expect(byte[] data, int tag) throws InvalidX509Exception {
        Tlv tlv = readSingle(data);
        if (tlv.tag() != tag) {
            throw new InvalidX509Exception(String.format("expected DER tag 0x%02x, got 0x%02x", tag, tlv.tag()));
        }
        return tlv.value();
    }

    /** Decodes an INTEGER element. */
    public static BigInteger integer(byte[] data) throws InvalidX509Exception {
        byte[] value = expect(data, INTEGER);
        if (value.length == 0) {
            throw new InvalidX509Exception("empty DER INTEGER");
        }
        return new BigInteger(value);
    }
}
