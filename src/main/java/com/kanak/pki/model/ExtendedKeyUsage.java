package com.kanak.pki.model;

import com.kanak.pki.asn1.Asn1Node;
import com.kanak.pki.asn1.DerParser;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * ExtendedKeyUsage X.509 extension conforming to RFC 5280 §4.2.1.12.
 *
 * <pre>
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 * KeyPurposeId ::= OBJECT IDENTIFIER
 * </pre>
 */
public final class ExtendedKeyUsage {

    private final Set<String> keyPurposeOids;

    public ExtendedKeyUsage(Set<String> keyPurposeOids) {
        this.keyPurposeOids = Collections.unmodifiableSet(new HashSet<>(keyPurposeOids));
    }

    public static ExtendedKeyUsage fromExtensionValue(byte[] extnValueDer) {
        Asn1Node seq = DerParser.parse(extnValueDer);
        Set<String> oids = new HashSet<>();
        for (Asn1Node child : seq.getChildren()) {
            oids.add(child.asOid().getDottedString());
        }
        return new ExtendedKeyUsage(oids);
    }

    public Set<String> getKeyPurposeOids() {
        return keyPurposeOids;
    }

    public boolean hasPurpose(String oid) {
        return keyPurposeOids.contains(oid);
    }

    @Override
    public String toString() {
        return "ExtendedKeyUsage" + keyPurposeOids;
    }
}
