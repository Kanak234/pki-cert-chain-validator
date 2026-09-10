package com.kanak.pki.model;

import com.kanak.pki.asn1.Asn1Node;
import com.kanak.pki.asn1.Oid;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * SubjectPublicKeyInfo structure conforming to RFC 5280 §4.1.2.7.
 */
public final class SubjectPublicKeyInfo {

    private final String algorithmOid;
    private final byte[] rawEncodedDer;
    private final byte[] publicKeyBits;
    private volatile PublicKey cachedPublicKey;

    public SubjectPublicKeyInfo(String algorithmOid, byte[] rawEncodedDer, byte[] publicKeyBits) {
        this.algorithmOid = Objects.requireNonNull(algorithmOid, "algorithmOid must not be null");
        this.rawEncodedDer = Objects.requireNonNull(rawEncodedDer, "rawEncodedDer must not be null").clone();
        this.publicKeyBits = Objects.requireNonNull(publicKeyBits, "publicKeyBits must not be null").clone();
    }

    public static SubjectPublicKeyInfo fromAsn1(Asn1Node spkiNode) {
        Objects.requireNonNull(spkiNode, "spkiNode must not be null");
        if (spkiNode.getChildCount() < 2) {
            throw new IllegalArgumentException("SubjectPublicKeyInfo must contain AlgorithmIdentifier and subjectPublicKey");
        }

        Asn1Node algId = spkiNode.getChild(0);
        String oid = algId.getChild(0).asOid().getDottedString();

        Asn1Node keyBitsNode = spkiNode.getChild(1);
        byte[] keyBits = keyBitsNode.asBitStringData();

        return new SubjectPublicKeyInfo(oid, spkiNode.getRawEncodedBytes(), keyBits);
    }

    public String getAlgorithmOid() {
        return algorithmOid;
    }

    public byte[] getRawEncodedDer() {
        return rawEncodedDer.clone();
    }

    public byte[] getPublicKeyBits() {
        return publicKeyBits.clone();
    }

    /**
     * Converts the SubjectPublicKeyInfo DER encoding to a standard java.security.PublicKey.
     */
    public PublicKey toPublicKey() {
        if (cachedPublicKey != null) {
            return cachedPublicKey;
        }

        X509EncodedKeySpec spec = new X509EncodedKeySpec(rawEncodedDer);
        String algorithmName = resolveAlgorithmName(algorithmOid);

        try {
            KeyFactory kf = KeyFactory.getInstance(algorithmName);
            cachedPublicKey = kf.generatePublic(spec);
            return cachedPublicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to instantiate public key for algorithm OID: " + algorithmOid, e);
        }
    }

    private static String resolveAlgorithmName(String oid) {
        return switch (oid) {
            case Oid.RSA_ENCRYPTION -> "RSA";
            case Oid.EC_PUBLIC_KEY -> "EC";
            default -> "RSA"; // Fallback attempt
        };
    }

    @Override
    public String toString() {
        return "SubjectPublicKeyInfo[algorithm=" + algorithmOid + ", keyLength=" + publicKeyBits.length + " bytes]";
    }
}
