package com.kanak.pki.model;

import com.kanak.pki.asn1.Asn1Node;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * GeneralName choice conforming to RFC 5280 §4.2.1.6.
 */
public final class GeneralName {

    public enum Type {
        OTHER_NAME(0),
        RFC822_NAME(1),
        DNS_NAME(2),
        X400_ADDRESS(3),
        DIRECTORY_NAME(4),
        EDI_PARTY_NAME(5),
        URI(6),
        IP_ADDRESS(7),
        REGISTERED_ID(8);

        private final int tagNumber;

        Type(int tagNumber) {
            this.tagNumber = tagNumber;
        }

        public int getTagNumber() {
            return tagNumber;
        }

        public static Type fromTagNumber(int tagNum) {
            for (Type t : values()) {
                if (t.tagNumber == tagNum) return t;
            }
            throw new IllegalArgumentException("Unknown GeneralName context tag: " + tagNum);
        }
    }

    private final Type type;
    private final String value;
    private final byte[] rawValue;

    public GeneralName(Type type, String value, byte[] rawValue) {
        this.type = Objects.requireNonNull(type, "type must not be null");
        this.value = Objects.requireNonNull(value, "value must not be null");
        this.rawValue = rawValue != null ? rawValue.clone() : new byte[0];
    }

    public static GeneralName fromAsn1(Asn1Node node) {
        int tagNum = node.getTagNumber();
        Type type = Type.fromTagNumber(tagNum);
        byte[] content = node.getContentBytes();
        String value;

        switch (type) {
            case DNS_NAME, RFC822_NAME, URI ->
                    value = new String(content, StandardCharsets.US_ASCII);
            case IP_ADDRESS -> {
                try {
                    value = InetAddress.getByAddress(content).getHostAddress();
                } catch (UnknownHostException e) {
                    value = "invalid-ip";
                }
            }
            default -> value = "unsupported-general-name-" + type;
        }

        return new GeneralName(type, value, content);
    }

    public Type getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public byte[] getRawValue() {
        return rawValue.clone();
    }

    @Override
    public String toString() {
        return type + ":" + value;
    }
}
