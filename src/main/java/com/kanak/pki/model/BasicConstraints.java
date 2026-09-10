package com.kanak.pki.model;

import com.kanak.pki.asn1.Asn1Node;
import com.kanak.pki.asn1.Asn1Tag;
import com.kanak.pki.asn1.DerParser;

import java.util.OptionalInt;

/**
 * BasicConstraints X.509 extension conforming to RFC 5280 §4.2.1.9.
 *
 * <pre>
 * BasicConstraints ::= SEQUENCE {
 *      cA                      BOOLEAN DEFAULT FALSE,
 *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 * </pre>
 */
public final class BasicConstraints {

    private final boolean ca;
    private final OptionalInt pathLenConstraint;

    public BasicConstraints(boolean ca, OptionalInt pathLenConstraint) {
        this.ca = ca;
        this.pathLenConstraint = pathLenConstraint;
    }

    public static BasicConstraints fromExtensionValue(byte[] extnValueDer) {
        Asn1Node seq = DerParser.parse(extnValueDer);
        boolean ca = false;
        OptionalInt pathLen = OptionalInt.empty();

        int childIdx = 0;
        if (childIdx < seq.getChildCount() && seq.getChild(childIdx).getTagNumber() == Asn1Tag.BOOLEAN) {
            ca = seq.getChild(childIdx).asBoolean();
            childIdx++;
        }

        if (childIdx < seq.getChildCount() && seq.getChild(childIdx).getTagNumber() == Asn1Tag.INTEGER) {
            pathLen = OptionalInt.of(seq.getChild(childIdx).asInt());
        }

        return new BasicConstraints(ca, pathLen);
    }

    public boolean isCa() {
        return ca;
    }

    public OptionalInt getPathLenConstraint() {
        return pathLenConstraint;
    }

    @Override
    public String toString() {
        return "BasicConstraints[ca=" + ca +
                (pathLenConstraint.isPresent() ? ", pathLen=" + pathLenConstraint.getAsInt() : "") + "]";
    }
}
