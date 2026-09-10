package com.kanak.pki.model;

import com.kanak.pki.asn1.Asn1Node;

import java.time.Instant;
import java.util.Objects;

/**
 * Certificate validity period conforming to RFC 5280 §4.1.2.5.
 */
public final class Validity {

    private final Instant notBefore;
    private final Instant notAfter;

    public Validity(Instant notBefore, Instant notAfter) {
        this.notBefore = Objects.requireNonNull(notBefore, "notBefore must not be null");
        this.notAfter = Objects.requireNonNull(notAfter, "notAfter must not be null");
        if (notAfter.isBefore(notBefore)) {
            throw new IllegalArgumentException("Validity notAfter (" + notAfter + ") is before notBefore (" + notBefore + ")");
        }
    }

    public static Validity fromAsn1(Asn1Node validityNode) {
        Objects.requireNonNull(validityNode, "validityNode must not be null");
        if (validityNode.getChildCount() < 2) {
            throw new IllegalArgumentException("Validity sequence must have at least 2 children (notBefore, notAfter)");
        }
        Instant notBefore = validityNode.getChild(0).asInstant();
        Instant notAfter = validityNode.getChild(1).asInstant();
        return new Validity(notBefore, notAfter);
    }

    public Instant getNotBefore() {
        return notBefore;
    }

    public Instant getNotAfter() {
        return notAfter;
    }

    /**
     * Checks if the given timestamp falls within the validity interval [notBefore, notAfter].
     */
    public boolean isValidAt(Instant timestamp) {
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        return !timestamp.isBefore(notBefore) && !timestamp.isAfter(notAfter);
    }

    @Override
    public String toString() {
        return "[" + notBefore + " to " + notAfter + "]";
    }
}
