package com.kanak.pki.asn1;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Immutable representation of an ASN.1 Object Identifier (OID) conforming to ITU-T X.690 §8.19.
 */
public final class Oid {

    // Common X.500 Distinguished Name Attribute OIDs
    public static final String COMMON_NAME = "2.5.4.3";
    public static final String SURNAME = "2.5.4.4";
    public static final String SERIAL_NUMBER = "2.5.4.5";
    public static final String COUNTRY_NAME = "2.5.4.6";
    public static final String LOCALITY_NAME = "2.5.4.7";
    public static final String STATE_OR_PROVINCE = "2.5.4.8";
    public static final String ORGANIZATION_NAME = "2.5.4.10";
    public static final String ORGANIZATIONAL_UNIT = "2.5.4.11";

    // Standard X.509 v3 Extension OIDs (2.5.29.*)
    public static final String SUBJECT_DIRECTORY_ATTRIBUTES = "2.5.29.9";
    public static final String SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
    public static final String KEY_USAGE = "2.5.29.15";
    public static final String PRIVATE_KEY_USAGE_PERIOD = "2.5.29.16";
    public static final String SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";
    public static final String ISSUER_ALTERNATIVE_NAME = "2.5.29.18";
    public static final String BASIC_CONSTRAINTS = "2.5.29.19";
    public static final String CRL_NUMBER = "2.5.29.20";
    public static final String REASON_CODE = "2.5.29.21";
    public static final String NAME_CONSTRAINTS = "2.5.29.30";
    public static final String CRL_DISTRIBUTION_POINTS = "2.5.29.31";
    public static final String CERTIFICATE_POLICIES = "2.5.29.32";
    public static final String POLICY_MAPPINGS = "2.5.29.33";
    public static final String AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
    public static final String POLICY_CONSTRAINTS = "2.5.29.36";
    public static final String EXTENDED_KEY_USAGE = "2.5.29.37";
    public static final String INHIBIT_ANY_POLICY = "2.5.29.54";

    // Extended Key Usage (EKU) Purposes (1.3.6.1.5.5.7.3.*)
    public static final String EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    public static final String EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    public static final String EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
    public static final String EKU_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";
    public static final String EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
    public static final String EKU_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    // Public Key Algorithms
    public static final String RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
    public static final String EC_PUBLIC_KEY = "1.2.840.10045.2.1";

    // Signature Algorithms
    public static final String SHA256_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.11";
    public static final String SHA384_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.12";
    public static final String SHA512_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.13";
    public static final String ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
    public static final String ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";
    public static final String ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4";

    private final String dottedString;
    private final byte[] encodedBytes;

    public Oid(String dottedString) {
        this.dottedString = Objects.requireNonNull(dottedString, "OID string must not be null");
        this.encodedBytes = encodeOid(dottedString);
    }

    public Oid(byte[] rawDerContent) {
        Objects.requireNonNull(rawDerContent, "DER content must not be null");
        this.encodedBytes = rawDerContent.clone();
        this.dottedString = decodeOid(rawDerContent);
    }

    public static Oid fromDotted(String dottedString) {
        return new Oid(dottedString);
    }

    public static Oid fromBytes(byte[] rawDerContent) {
        return new Oid(rawDerContent);
    }

    public String getDottedString() {
        return dottedString;
    }

    public byte[] getEncodedBytes() {
        return encodedBytes.clone();
    }

    /**
     * Decodes ASN.1 DER OID content bytes into a dotted decimal string per ITU-T X.690 §8.19.
     */
    public static String decodeOid(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException("Invalid OID encoding: empty byte array");
        }

        StringBuilder sb = new StringBuilder();

        // First byte contains first two components: node0 * 40 + node1
        int firstByte = bytes[0] & 0xFF;
        long node0 = firstByte / 40;
        long node1 = firstByte % 40;
        if (node0 > 2) {
            node1 += (node0 - 2) * 40;
            node0 = 2;
        }
        sb.append(node0).append('.').append(node1);

        BigInteger current = BigInteger.ZERO;
        for (int i = 1; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            current = current.shiftLeft(7).or(BigInteger.valueOf(b & 0x7F));
            if ((b & 0x80) == 0) {
                // Last byte of this sub-identifier
                sb.append('.').append(current);
                current = BigInteger.ZERO;
            }
        }

        return sb.toString();
    }

    /**
     * Encodes a dotted decimal string into ASN.1 DER OID content bytes per ITU-T X.690 §8.19.
     */
    public static byte[] encodeOid(String dotted) {
        String[] parts = dotted.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("OID must have at least two components: " + dotted);
        }

        long n0 = Long.parseLong(parts[0]);
        long n1 = Long.parseLong(parts[1]);
        if (n0 > 2 || (n0 < 2 && n1 >= 40)) {
            throw new IllegalArgumentException("Invalid first two OID components in: " + dotted);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((int) (n0 * 40 + n1));

        for (int i = 2; i < parts.length; i++) {
            BigInteger node = new BigInteger(parts[i]);
            if (node.signum() < 0) {
                throw new IllegalArgumentException("Negative OID component: " + parts[i]);
            }
            if (node.equals(BigInteger.ZERO)) {
                out.write(0);
            } else {
                List<Byte> stack = new ArrayList<>();
                boolean first = true;
                while (node.signum() > 0) {
                    int septet = node.and(BigInteger.valueOf(0x7F)).intValue();
                    if (!first) {
                        septet |= 0x80;
                    }
                    first = false;
                    stack.add((byte) septet);
                    node = node.shiftRight(7);
                }
                for (int j = stack.size() - 1; j >= 0; j--) {
                    out.write(stack.get(j));
                }
            }
        }
        return out.toByteArray();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Oid other)) return false;
        return dottedString.equals(other.dottedString);
    }

    @Override
    public int hashCode() {
        return dottedString.hashCode();
    }

    @Override
    public String toString() {
        return dottedString;
    }
}
