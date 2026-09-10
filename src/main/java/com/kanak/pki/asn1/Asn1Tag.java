package com.kanak.pki.asn1;

/**
 * ASN.1 Tag constants according to ITU-T X.680 / X.690 specifications.
 */
public final class Asn1Tag {

    private Asn1Tag() {
        // Prevent instantiation
    }

    // Tag Classes (Bits 8-7)
    public static final int CLASS_UNIVERSAL = 0x00;
    public static final int CLASS_APPLICATION = 0x40;
    public static final int CLASS_CONTEXT_SPECIFIC = 0x80;
    public static final int CLASS_PRIVATE = 0xC0;

    // Constructed Flag (Bit 6)
    public static final int CONSTRUCTED = 0x20;

    // Universal Primitive & Constructed Tags (Bits 5-1)
    public static final int BOOLEAN = 0x01;
    public static final int INTEGER = 0x02;
    public static final int BIT_STRING = 0x03;
    public static final int OCTET_STRING = 0x04;
    public static final int NULL = 0x05;
    public static final int OBJECT_IDENTIFIER = 0x06;
    public static final int UTF8_STRING = 0x0C;
    public static final int PRINTABLE_STRING = 0x13;
    public static final int TELETEX_STRING = 0x14;
    public static final int IA5_STRING = 0x16;
    public static final int UTC_TIME = 0x17;
    public static final int GENERALIZED_TIME = 0x18;
    public static final int SEQUENCE = 0x10; // When combined with CONSTRUCTED -> 0x30
    public static final int SET = 0x11;      // When combined with CONSTRUCTED -> 0x31

    // Compound Common Tags
    public static final int TAG_SEQUENCE = SEQUENCE | CONSTRUCTED; // 0x30
    public static final int TAG_SET = SET | CONSTRUCTED;           // 0x31

    public static boolean isConstructed(int tagByte) {
        return (tagByte & CONSTRUCTED) != 0;
    }

    public static int getTagClass(int tagByte) {
        return tagByte & 0xC0;
    }

    public static int getTagNumber(int tagByte) {
        return tagByte & 0x1F;
    }
}
