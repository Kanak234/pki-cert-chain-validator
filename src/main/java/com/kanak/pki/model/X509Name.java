package com.kanak.pki.model;

import com.kanak.pki.asn1.Asn1Node;
import com.kanak.pki.asn1.Oid;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Parsed X.500 Distinguished Name (DN) conforming to RFC 5280 §4.1.2.4 and RFC 4514.
 */
public final class X509Name {

    public record Attribute(String oid, String value) {}

    private final List<Attribute> attributes;
    private final String canonicalString;
    private final byte[] rawDerBytes;

    public X509Name(List<Attribute> attributes, byte[] rawDerBytes) {
        this.attributes = Collections.unmodifiableList(new ArrayList<>(attributes));
        this.rawDerBytes = rawDerBytes != null ? rawDerBytes.clone() : new byte[0];
        this.canonicalString = buildCanonicalString(this.attributes);
    }

    public static X509Name fromAsn1(Asn1Node rdnSequenceNode) {
        Objects.requireNonNull(rdnSequenceNode, "rdnSequenceNode must not be null");
        List<Attribute> attrs = new ArrayList<>();

        // RDNSequence is a SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeAndValue)
        for (Asn1Node rdnSet : rdnSequenceNode.getChildren()) {
            for (Asn1Node atv : rdnSet.getChildren()) {
                if (atv.getChildCount() >= 2) {
                    String oid = atv.getChild(0).asOid().getDottedString();
                    String val = atv.getChild(1).asString();
                    attrs.add(new Attribute(oid, val));
                }
            }
        }
        return new X509Name(attrs, rdnSequenceNode.getRawEncodedBytes());
    }

    private static String buildCanonicalString(List<Attribute> attrs) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < attrs.size(); i++) {
            if (i > 0) sb.append(", ");
            Attribute a = attrs.get(i);
            sb.append(oidToAbbreviation(a.oid())).append('=').append(a.value());
        }
        return sb.toString();
    }

    public static String oidToAbbreviation(String oid) {
        return switch (oid) {
            case Oid.COMMON_NAME -> "CN";
            case Oid.ORGANIZATION_NAME -> "O";
            case Oid.ORGANIZATIONAL_UNIT -> "OU";
            case Oid.COUNTRY_NAME -> "C";
            case Oid.STATE_OR_PROVINCE -> "ST";
            case Oid.LOCALITY_NAME -> "L";
            case Oid.SURNAME -> "SN";
            case Oid.SERIAL_NUMBER -> "SERIALNUMBER";
            default -> oid;
        };
    }

    public Optional<String> getFirstValue(String oid) {
        for (Attribute attr : attributes) {
            if (attr.oid().equals(oid)) {
                return Optional.of(attr.value());
            }
        }
        return Optional.empty();
    }

    public Optional<String> getCommonName() {
        return getFirstValue(Oid.COMMON_NAME);
    }

    public List<Attribute> getAttributes() {
        return attributes;
    }

    public byte[] getRawDerBytes() {
        return rawDerBytes.clone();
    }

    public String getCanonicalString() {
        return canonicalString;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof X509Name other)) return false;
        // RFC 5280 name comparison: canonical string normalized case-insensitively
        return canonicalString.equalsIgnoreCase(other.canonicalString);
    }

    @Override
    public int hashCode() {
        return canonicalString.toLowerCase(Locale.ROOT).hashCode();
    }

    @Override
    public String toString() {
        return canonicalString;
    }
}
