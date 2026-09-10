package com.kanak.pki.model;

import com.kanak.pki.asn1.Asn1Node;
import com.kanak.pki.asn1.Asn1Tag;
import com.kanak.pki.asn1.DerParser;
import com.kanak.pki.asn1.Oid;
import com.kanak.pki.pem.PemReader;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable X.509 v3 Certificate conforming strictly to RFC 5280.
 */
public final class X509Certificate {

    private final byte[] rawDer;
    private final byte[] tbsDer;
    private final int version;
    private final BigInteger serialNumber;
    private final String signatureAlgorithmOid;
    private final X509Name issuer;
    private final Validity validity;
    private final X509Name subject;
    private final SubjectPublicKeyInfo subjectPublicKeyInfo;
    private final Extensions extensions;
    private final byte[] signatureValue;

    public X509Certificate(byte[] rawDer, byte[] tbsDer, int version, BigInteger serialNumber,
                           String signatureAlgorithmOid, X509Name issuer, Validity validity,
                           X509Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo,
                           Extensions extensions, byte[] signatureValue) {
        this.rawDer = rawDer.clone();
        this.tbsDer = tbsDer.clone();
        this.version = version;
        this.serialNumber = serialNumber;
        this.signatureAlgorithmOid = signatureAlgorithmOid;
        this.issuer = issuer;
        this.validity = validity;
        this.subject = subject;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.extensions = extensions;
        this.signatureValue = signatureValue.clone();
    }

    public static X509Certificate fromDer(byte[] derBytes) {
        Objects.requireNonNull(derBytes, "derBytes must not be null");
        Asn1Node root = DerParser.parse(derBytes);
        return fromAsn1(root);
    }

    public static List<X509Certificate> fromPem(String pemContent) {
        List<byte[]> blocks = PemReader.readBlocks(pemContent);
        return blocks.stream().map(X509Certificate::fromDer).toList();
    }

    public static X509Certificate fromAsn1(Asn1Node certNode) {
        if (certNode.getChildCount() < 3) {
            throw new IllegalArgumentException("Certificate SEQUENCE must contain tbsCertificate, signatureAlgorithm, signatureValue");
        }

        Asn1Node tbsNode = certNode.getChild(0);
        byte[] tbsDer = tbsNode.getRawEncodedBytes();

        int tbsIdx = 0;
        int version = 1;

        // Check for explicit [0] Version
        if (tbsNode.getChild(tbsIdx).getTagClass() == Asn1Tag.CLASS_CONTEXT_SPECIFIC &&
            tbsNode.getChild(tbsIdx).getTagNumber() == 0) {
            version = tbsNode.getChild(tbsIdx).getChild(0).asInt() + 1;
            tbsIdx++;
        }

        BigInteger serialNumber = tbsNode.getChild(tbsIdx++).asBigInteger();

        // Signature Algorithm inside TBSCertificate
        Asn1Node tbsSigAlg = tbsNode.getChild(tbsIdx++);
        String sigAlgOid = tbsSigAlg.getChild(0).asOid().getDottedString();

        X509Name issuer = X509Name.fromAsn1(tbsNode.getChild(tbsIdx++));
        Validity validity = Validity.fromAsn1(tbsNode.getChild(tbsIdx++));
        X509Name subject = X509Name.fromAsn1(tbsNode.getChild(tbsIdx++));
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.fromAsn1(tbsNode.getChild(tbsIdx++));

        Extensions extensions = new Extensions(Collections.emptyMap());

        // Process remaining optional fields in TBS
        while (tbsIdx < tbsNode.getChildCount()) {
            Asn1Node opt = tbsNode.getChild(tbsIdx++);
            if (opt.getTagClass() == Asn1Tag.CLASS_CONTEXT_SPECIFIC && opt.getTagNumber() == 3) {
                // Extensions [3] EXPLICIT Extensions
                extensions = Extensions.fromAsn1(opt.getChild(0));
            }
        }

        // Outer signature
        byte[] signatureBytes = certNode.getChild(2).asBitStringData();

        return new X509Certificate(certNode.getRawEncodedBytes(), tbsDer, version, serialNumber,
                sigAlgOid, issuer, validity, subject, spki, extensions, signatureBytes);
    }

    public byte[] getRawDer() { return rawDer.clone(); }
    public byte[] getTbsDer() { return tbsDer.clone(); }
    public int getVersion() { return version; }
    public BigInteger getSerialNumber() { return serialNumber; }
    public String getSignatureAlgorithmOid() { return signatureAlgorithmOid; }
    public X509Name getIssuer() { return issuer; }
    public Validity getValidity() { return validity; }
    public X509Name getSubject() { return subject; }
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() { return subjectPublicKeyInfo; }
    public Extensions getExtensions() { return extensions; }
    public byte[] getSignatureValue() { return signatureValue.clone(); }

    public PublicKey getPublicKey() {
        return subjectPublicKeyInfo.toPublicKey();
    }

    public boolean isSelfIssued() {
        return issuer.equals(subject);
    }

    public boolean isSelfSigned() {
        if (!isSelfIssued()) return false;
        try {
            return verifySignature(getPublicKey());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verifies the cryptographic signature on this certificate using the issuer's public key.
     */
    public boolean verifySignature(PublicKey issuerPublicKey) {
        Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");
        String jcaAlg = resolveJcaSignatureAlgorithm(signatureAlgorithmOid);
        try {
            Signature signature = Signature.getInstance(jcaAlg);
            signature.initVerify(issuerPublicKey);
            signature.update(tbsDer);
            return signature.verify(signatureValue);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static String resolveJcaSignatureAlgorithm(String oid) {
        return switch (oid) {
            case Oid.SHA256_WITH_RSA_ENCRYPTION -> "SHA256withRSA";
            case Oid.SHA384_WITH_RSA_ENCRYPTION -> "SHA384withRSA";
            case Oid.SHA512_WITH_RSA_ENCRYPTION -> "SHA512withRSA";
            case Oid.ECDSA_WITH_SHA256 -> "SHA256withECDSA";
            case Oid.ECDSA_WITH_SHA384 -> "SHA384withECDSA";
            case Oid.ECDSA_WITH_SHA512 -> "SHA512withECDSA";
            default -> throw new IllegalArgumentException("Unsupported signature algorithm OID: " + oid);
        };
    }

    public String getSha256Fingerprint() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(rawDer);
            return HexFormat.ofDelimiter(":").formatHex(digest).toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof X509Certificate other)) return false;
        return java.util.Arrays.equals(rawDer, other.rawDer);
    }

    @Override
    public int hashCode() {
        return java.util.Arrays.hashCode(rawDer);
    }

    @Override
    public String toString() {
        return "Certificate[v" + version + ", Subject: " + subject.getCanonicalString() +
                ", Serial: " + serialNumber.toString(16) + "]";
    }
}
