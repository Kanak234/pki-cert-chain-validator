package com.kanak.pki.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Strict ASN.1 DER encoder generating byte streams conforming to ITU-T X.690 §10.
 */
public final class DerWriter {

    private DerWriter() {
        // Utility class
    }

    public static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, content.length);
        try {
            out.write(content);
        } catch (IOException e) {
            throw new IllegalStateException("IO error writing ASN.1 content", e);
        }
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 128) {
            out.write(length);
        } else if (length < 256) {
            out.write(0x81);
            out.write(length);
        } else if (length < 65536) {
            out.write(0x82);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        } else if (length < 16777216) {
            out.write(0x83);
            out.write((length >> 16) & 0xFF);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        } else {
            out.write(0x84);
            out.write((length >> 24) & 0xFF);
            out.write((length >> 16) & 0xFF);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
    }

    public static byte[] sequence(byte[]... items) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] item : items) {
            try {
                body.write(item);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return tlv(Asn1Tag.TAG_SEQUENCE, body.toByteArray());
    }

    public static byte[] set(byte[]... items) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] item : items) {
            try {
                body.write(item);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return tlv(Asn1Tag.TAG_SET, body.toByteArray());
    }

    public static byte[] integer(BigInteger val) {
        return tlv(Asn1Tag.INTEGER, val.toByteArray());
    }

    public static byte[] integer(long val) {
        return integer(BigInteger.valueOf(val));
    }

    public static byte[] booleanVal(boolean val) {
        return tlv(Asn1Tag.BOOLEAN, new byte[]{(byte) (val ? 0xFF : 0x00)});
    }

    public static byte[] oid(String dotted) {
        return tlv(Asn1Tag.OBJECT_IDENTIFIER, Oid.encodeOid(dotted));
    }

    public static byte[] nullVal() {
        return tlv(Asn1Tag.NULL, new byte[0]);
    }

    public static byte[] bitString(byte[] data, int unusedBits) {
        byte[] content = new byte[data.length + 1];
        content[0] = (byte) (unusedBits & 0xFF);
        System.arraycopy(data, 0, content, 1, data.length);
        return tlv(Asn1Tag.BIT_STRING, content);
    }

    public static byte[] octetString(byte[] data) {
        return tlv(Asn1Tag.OCTET_STRING, data);
    }

    public static byte[] utf8String(String s) {
        return tlv(Asn1Tag.UTF8_STRING, s.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] printableString(String s) {
        return tlv(Asn1Tag.PRINTABLE_STRING, s.getBytes(StandardCharsets.US_ASCII));
    }

    public static byte[] ia5String(String s) {
        return tlv(Asn1Tag.IA5_STRING, s.getBytes(StandardCharsets.US_ASCII));
    }

    public static byte[] utcTime(Instant instant) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        return tlv(Asn1Tag.UTC_TIME, formatter.format(instant).getBytes(StandardCharsets.US_ASCII));
    }

    public static byte[] generalizedTime(Instant instant) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        return tlv(Asn1Tag.GENERALIZED_TIME, formatter.format(instant).getBytes(StandardCharsets.US_ASCII));
    }

    public static byte[] contextExplicit(int tagNumber, byte[] content) {
        int tag = Asn1Tag.CLASS_CONTEXT_SPECIFIC | Asn1Tag.CONSTRUCTED | tagNumber;
        return tlv(tag, content);
    }

    public static byte[] contextImplicit(int tagNumber, byte[] content, boolean constructed) {
        int tag = Asn1Tag.CLASS_CONTEXT_SPECIFIC | (constructed ? Asn1Tag.CONSTRUCTED : 0) | tagNumber;
        return tlv(tag, content);
    }
}
