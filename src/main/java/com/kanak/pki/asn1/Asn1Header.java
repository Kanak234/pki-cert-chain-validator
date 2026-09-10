package com.kanak.pki.asn1;

/**
 * Parsed ASN.1 Tag-Length header conforming to ITU-T X.690 §8.1 and §10.1 (DER definite length).
 */
public final class Asn1Header {

    private final int tag;
    private final int tagClass;
    private final boolean constructed;
    private final int tagNumber;
    private final int contentLength;
    private final int headerLength;

    public Asn1Header(int tag, int tagClass, boolean constructed, int tagNumber, int contentLength, int headerLength) {
        this.tag = tag;
        this.tagClass = tagClass;
        this.constructed = constructed;
        this.tagNumber = tagNumber;
        this.contentLength = contentLength;
        this.headerLength = headerLength;
    }

    public static Asn1Header read(byte[] buffer, int offset, int limit) {
        if (offset >= limit) {
            throw new IllegalArgumentException("Unexpected end of ASN.1 buffer at offset " + offset);
        }

        int startOffset = offset;
        int tagByte = buffer[offset++] & 0xFF;
        int tagClass = Asn1Tag.getTagClass(tagByte);
        boolean constructed = Asn1Tag.isConstructed(tagByte);
        int tagNumber = Asn1Tag.getTagNumber(tagByte);

        // High-tag-number form (ITU-T X.690 §8.1.2.4)
        if (tagNumber == 0x1F) {
            tagNumber = 0;
            while (true) {
                if (offset >= limit) {
                    throw new IllegalArgumentException("Truncated high-tag-number ASN.1 sequence");
                }
                int next = buffer[offset++] & 0xFF;
                tagNumber = (tagNumber << 7) | (next & 0x7F);
                if ((next & 0x80) == 0) {
                    break;
                }
            }
        }

        if (offset >= limit) {
            throw new IllegalArgumentException("Truncated ASN.1 header before length octets at offset " + offset);
        }

        int lengthByte = buffer[offset++] & 0xFF;
        int contentLength;

        if (lengthByte == 0x80) {
            // Indefinite length encoding is strictly prohibited under DER (ITU-T X.690 §10.1)
            throw new IllegalArgumentException("Indefinite length encoding is strictly prohibited in DER (ITU-T X.690 §10.1)");
        } else if ((lengthByte & 0x80) == 0) {
            // Short definite length form: 0 <= length <= 127
            contentLength = lengthByte;
        } else {
            // Long definite length form: (lengthByte & 0x7F) gives number of subsequent length octets
            int numLengthBytes = lengthByte & 0x7F;
            if (numLengthBytes == 0 || numLengthBytes > 4) {
                throw new IllegalArgumentException("Illegal DER length octet count: " + numLengthBytes);
            }
            if (offset + numLengthBytes > limit) {
                throw new IllegalArgumentException("Truncated DER length octets");
            }

            // Minimal octets rule in DER (ITU-T X.690 §10.1): first length byte must not be 0x00
            int firstOctet = buffer[offset] & 0xFF;
            if (firstOctet == 0) {
                throw new IllegalArgumentException("Non-minimal DER length encoding (leading zero octet)");
            }

            contentLength = 0;
            for (int i = 0; i < numLengthBytes; i++) {
                contentLength = (contentLength << 8) | (buffer[offset++] & 0xFF);
            }

            // DER minimal length rule: if length <= 127, short form MUST be used
            if (contentLength < 128) {
                throw new IllegalArgumentException("Non-minimal DER length encoding: value " + contentLength + " encoded in long form");
            }
        }

        if (contentLength < 0 || offset + contentLength > limit) {
            throw new IllegalArgumentException("ASN.1 content length " + contentLength + " exceeds buffer boundary (offset " + offset + ", limit " + limit + ")");
        }

        int totalHeaderLen = offset - startOffset;
        return new Asn1Header(tagByte, tagClass, constructed, tagNumber, contentLength, totalHeaderLen);
    }

    public int getTag() {
        return tag;
    }

    public int getTagClass() {
        return tagClass;
    }

    public boolean isConstructed() {
        return constructed;
    }

    public int getTagNumber() {
        return tagNumber;
    }

    public int getContentLength() {
        return contentLength;
    }

    public int getHeaderLength() {
        return headerLength;
    }

    public int getTotalLength() {
        return headerLength + contentLength;
    }
}
