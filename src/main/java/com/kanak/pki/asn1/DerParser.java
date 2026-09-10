package com.kanak.pki.asn1;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Strict, non-lenient ASN.1 Distinguished Encoding Rules (DER) parser conforming to ITU-T X.690 §10.
 */
public final class DerParser {

    public static final int MAX_RECURSION_DEPTH = 32;
    public static final int MAX_BUFFER_SIZE = 1024 * 1024; // 1 MB safety ceiling

    private DerParser() {
        // Utility class
    }

    /**
     * Parses a complete DER byte array into an ASN.1 syntax node hierarchy.
     */
    public static Asn1Node parse(byte[] derBytes) {
        Objects.requireNonNull(derBytes, "derBytes must not be null");
        if (derBytes.length == 0) {
            throw new IllegalArgumentException("Empty DER byte array");
        }
        if (derBytes.length > MAX_BUFFER_SIZE) {
            throw new IllegalArgumentException("DER buffer size " + derBytes.length + " exceeds maximum ceiling of " + MAX_BUFFER_SIZE + " bytes");
        }

        Asn1Node root = parseNode(derBytes, 0, derBytes.length, 0);
        if (root.getHeader().getTotalLength() != derBytes.length) {
            throw new IllegalArgumentException("Trailing unparsed bytes in DER buffer: root length " +
                    root.getHeader().getTotalLength() + " vs total buffer " + derBytes.length);
        }
        return root;
    }

    /**
     * Parses a sequence of concatenated ASN.1 DER nodes (e.g. within a constructed SEQUENCE or SET).
     */
    public static List<Asn1Node> parseSequence(byte[] buffer, int offset, int limit) {
        List<Asn1Node> nodes = new ArrayList<>();
        int current = offset;
        while (current < limit) {
            Asn1Node node = parseNode(buffer, current, limit, 0);
            nodes.add(node);
            current += node.getHeader().getTotalLength();
        }
        return nodes;
    }

    private static Asn1Node parseNode(byte[] buffer, int offset, int limit, int depth) {
        if (depth > MAX_RECURSION_DEPTH) {
            throw new IllegalStateException("Exceeded maximum ASN.1 nesting depth limit of " + MAX_RECURSION_DEPTH);
        }

        int startOffset = offset;
        Asn1Header header = Asn1Header.read(buffer, offset, limit);
        int contentOffset = startOffset + header.getHeaderLength();
        int contentEnd = contentOffset + header.getContentLength();

        byte[] rawBytes = Arrays.copyOfRange(buffer, startOffset, contentEnd);
        byte[] contentBytes = Arrays.copyOfRange(buffer, contentOffset, contentEnd);

        List<Asn1Node> children = new ArrayList<>();
        if (header.isConstructed()) {
            int childOffset = contentOffset;
            while (childOffset < contentEnd) {
                Asn1Node child = parseNode(buffer, childOffset, contentEnd, depth + 1);
                children.add(child);
                childOffset += child.getHeader().getTotalLength();
            }
        }

        return new Asn1Node(header, rawBytes, contentBytes, children);
    }
}
