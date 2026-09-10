package com.kanak.pki.asn1;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable in-memory representation of a parsed ASN.1 syntax node.
 */
public final class Asn1Node {

    private final Asn1Header header;
    private final byte[] rawEncodedBytes;
    private final byte[] contentBytes;
    private final List<Asn1Node> children;

    public Asn1Node(Asn1Header header, byte[] rawEncodedBytes, byte[] contentBytes, List<Asn1Node> children) {
        this.header = Objects.requireNonNull(header, "header must not be null");
        this.rawEncodedBytes = Objects.requireNonNull(rawEncodedBytes, "rawEncodedBytes must not be null");
        this.contentBytes = Objects.requireNonNull(contentBytes, "contentBytes must not be null");
        this.children = children != null ? Collections.unmodifiableList(new ArrayList<>(children)) : Collections.emptyList();
    }

    public Asn1Header getHeader() {
        return header;
    }

    public int getTag() {
        return header.getTag();
    }

    public int getTagClass() {
        return header.getTagClass();
    }

    public int getTagNumber() {
        return header.getTagNumber();
    }

    public boolean isConstructed() {
        return header.isConstructed();
    }

    public byte[] getRawEncodedBytes() {
        return rawEncodedBytes.clone();
    }

    public byte[] getContentBytes() {
        return contentBytes.clone();
    }

    public List<Asn1Node> getChildren() {
        return children;
    }

    public int getChildCount() {
        return children.size();
    }

    public Asn1Node getChild(int index) {
        if (index < 0 || index >= children.size()) {
            throw new IndexOutOfBoundsException("Child index " + index + " out of bounds for node with " + children.size() + " children");
        }
        return children.get(index);
    }

    public Optional<Asn1Node> findChild(int tag) {
        for (Asn1Node child : children) {
            if (child.getTag() == tag) {
                return Optional.of(child);
            }
        }
        return Optional.empty();
    }

    public Optional<Asn1Node> findChildByTagNumber(int tagNumber) {
        for (Asn1Node child : children) {
            if (child.getTagNumber() == tagNumber) {
                return Optional.of(child);
            }
        }
        return Optional.empty();
    }

    /**
     * Decodes ASN.1 BOOLEAN per ITU-T X.690 §11.1 (DER: 0x00 is false, 0xFF is true).
     */
    public boolean asBoolean() {
        if (contentBytes.length != 1) {
            throw new IllegalStateException("ASN.1 BOOLEAN must have length 1, found: " + contentBytes.length);
        }
        int b = contentBytes[0] & 0xFF;
        if (b == 0x00) {
            return false;
        } else if (b == 0xFF) {
            return true;
        }
        throw new IllegalStateException("Invalid DER BOOLEAN encoding: 0x" + Integer.toHexString(b) + " (must be 0x00 or 0xFF)");
    }

    /**
     * Decodes ASN.1 INTEGER per ITU-T X.690 §8.3.
     */
    public BigInteger asBigInteger() {
        if (contentBytes.length == 0) {
            throw new IllegalStateException("ASN.1 INTEGER has zero content length");
        }
        // Minimal octets validation in DER
        if (contentBytes.length > 1) {
            if (contentBytes[0] == 0x00 && (contentBytes[1] & 0x80) == 0) {
                throw new IllegalStateException("Non-minimal DER INTEGER encoding: superfluous leading zero byte");
            }
            if ((contentBytes[0] & 0xFF) == 0xFF && (contentBytes[1] & 0x80) != 0) {
                throw new IllegalStateException("Non-minimal DER INTEGER encoding: superfluous leading 0xFF byte");
            }
        }
        return new BigInteger(contentBytes);
    }

    public int asInt() {
        return asBigInteger().intValueExact();
    }

    /**
     * Decodes ASN.1 OBJECT IDENTIFIER per ITU-T X.690 §8.19.
     */
    public Oid asOid() {
        return new Oid(contentBytes);
    }

    /**
     * Decodes ASN.1 string types (UTF8String, PrintableString, IA5String, TeletexString).
     */
    public String asString() {
        return switch (header.getTagNumber()) {
            case Asn1Tag.UTF8_STRING -> new String(contentBytes, StandardCharsets.UTF_8);
            case Asn1Tag.PRINTABLE_STRING, Asn1Tag.IA5_STRING, Asn1Tag.TELETEX_STRING ->
                    new String(contentBytes, StandardCharsets.US_ASCII);
            default -> new String(contentBytes, StandardCharsets.UTF_8);
        };
    }

    /**
     * Decodes ASN.1 BIT STRING per ITU-T X.690 §8.4 and §11.2.
     * Returns the payload bytes excluding the initial unused-bits indicator octet.
     */
    public byte[] asBitStringData() {
        if (contentBytes.length == 0) {
            return new byte[0];
        }
        int unusedBits = contentBytes[0] & 0xFF;
        if (unusedBits > 7) {
            throw new IllegalStateException("Invalid unused bits count in BIT STRING: " + unusedBits);
        }
        if (contentBytes.length == 1 && unusedBits != 0) {
            throw new IllegalStateException("Zero-length BIT STRING with non-zero unused bits: " + unusedBits);
        }
        // DER Rule: Trailing unused bits in the final octet must be zero
        if (unusedBits > 0 && contentBytes.length > 1) {
            int lastByte = contentBytes[contentBytes.length - 1] & 0xFF;
            int mask = (1 << unusedBits) - 1;
            if ((lastByte & mask) != 0) {
                throw new IllegalStateException("DER BIT STRING violation: non-zero trailing unused bits in final octet");
            }
        }
        return Arrays.copyOfRange(contentBytes, 1, contentBytes.length);
    }

    public int getBitStringUnusedBits() {
        if (contentBytes.length == 0) return 0;
        return contentBytes[0] & 0xFF;
    }

    /**
     * Parses RFC 5280 UTCTime or GeneralizedTime into a java.time.Instant.
     */
    public Instant asInstant() {
        String timeStr = new String(contentBytes, StandardCharsets.US_ASCII).trim();
        int tagNum = header.getTagNumber();

        if (tagNum == Asn1Tag.UTC_TIME) {
            // RFC 5280 §4.1.2.5.1: YYMMDDHHMMSSZ
            if (timeStr.length() < 13 || !timeStr.endsWith("Z")) {
                throw new IllegalArgumentException("Malformed UTCTime string: " + timeStr);
            }
            int year = Integer.parseInt(timeStr.substring(0, 2));
            int month = Integer.parseInt(timeStr.substring(2, 4));
            int day = Integer.parseInt(timeStr.substring(4, 6));
            int hour = Integer.parseInt(timeStr.substring(6, 8));
            int minute = Integer.parseInt(timeStr.substring(8, 10));
            int second = Integer.parseInt(timeStr.substring(10, 12));

            // RFC 5280: If YY >= 50, year is 19YY; if YY < 50, year is 20YY
            int fullYear = (year >= 50) ? 1900 + year : 2000 + year;
            return LocalDateTime.of(fullYear, month, day, hour, minute, second).toInstant(ZoneOffset.UTC);

        } else if (tagNum == Asn1Tag.GENERALIZED_TIME) {
            // RFC 5280 §4.1.2.5.2: YYYYMMDDHHMMSSZ (fractional seconds optional)
            if (!timeStr.endsWith("Z")) {
                throw new IllegalArgumentException("Malformed GeneralizedTime (must end with 'Z'): " + timeStr);
            }
            if (timeStr.contains(".")) {
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss.SSS'Z'").withZone(ZoneOffset.UTC);
                return Instant.from(formatter.parse(timeStr));
            } else {
                int fullYear = Integer.parseInt(timeStr.substring(0, 4));
                int month = Integer.parseInt(timeStr.substring(4, 6));
                int day = Integer.parseInt(timeStr.substring(6, 8));
                int hour = Integer.parseInt(timeStr.substring(8, 10));
                int minute = Integer.parseInt(timeStr.substring(10, 12));
                int second = Integer.parseInt(timeStr.substring(12, 14));
                return LocalDateTime.of(fullYear, month, day, hour, minute, second).toInstant(ZoneOffset.UTC);
            }
        }
        throw new IllegalStateException("Node is not a time type (tag=" + header.getTag() + ")");
    }

    @Override
    public String toString() {
        return "Asn1Node[tag=0x" + Integer.toHexString(header.getTag()).toUpperCase() +
                ", constructed=" + isConstructed() +
                ", length=" + header.getContentLength() +
                ", children=" + children.size() + "]";
    }
}
