package com.kanak.pki;

import com.kanak.pki.asn1.Asn1Tag;
import com.kanak.pki.asn1.DerWriter;
import com.kanak.pki.asn1.Oid;
import com.kanak.pki.model.X509Certificate;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * Programmatic X.509 v3 test certificate factory generating real cryptographic keypairs
 * and DER bitstreams for rigorous RFC 5280 verification.
 */
public final class TestCertificateGenerator {

    public static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    public static byte[] buildName(String cn, String org, String country) {
        List<byte[]> rdns = new ArrayList<>();
        if (country != null) {
            rdns.add(DerWriter.set(DerWriter.sequence(DerWriter.oid(Oid.COUNTRY_NAME), DerWriter.printableString(country))));
        }
        if (org != null) {
            rdns.add(DerWriter.set(DerWriter.sequence(DerWriter.oid(Oid.ORGANIZATION_NAME), DerWriter.utf8String(org))));
        }
        if (cn != null) {
            rdns.add(DerWriter.set(DerWriter.sequence(DerWriter.oid(Oid.COMMON_NAME), DerWriter.utf8String(cn))));
        }
        return DerWriter.sequence(rdns.toArray(new byte[0][]));
    }

    public static byte[] buildValidity(Instant notBefore, Instant notAfter) {
        return DerWriter.sequence(
                DerWriter.utcTime(notBefore),
                DerWriter.utcTime(notAfter)
        );
    }

    public static byte[] buildAlgorithmId(String oid) {
        return DerWriter.sequence(
                DerWriter.oid(oid),
                DerWriter.nullVal()
        );
    }

    public static byte[] buildBasicConstraintsExtension(boolean isCa, Integer pathLen, boolean critical) {
        byte[] value;
        if (pathLen != null) {
            value = DerWriter.sequence(DerWriter.booleanVal(isCa), DerWriter.integer(pathLen));
        } else {
            value = DerWriter.sequence(DerWriter.booleanVal(isCa));
        }
        return DerWriter.sequence(
                DerWriter.oid(Oid.BASIC_CONSTRAINTS),
                DerWriter.booleanVal(critical),
                DerWriter.octetString(value)
        );
    }

    public static byte[] buildKeyUsageExtension(boolean[] bits, boolean critical) {
        byte[] bitBytes = new byte[2];
        for (int i = 0; i < 9; i++) {
            if (i < bits.length && bits[i]) {
                int byteIdx = i / 8;
                int bitIdx = 7 - (i % 8);
                bitBytes[byteIdx] |= (byte) (1 << bitIdx);
            }
        }
        int unusedBits = 7; // for 9 bits, second byte uses 1 bit -> 7 unused bits
        byte[] bitString = DerWriter.bitString(bitBytes, unusedBits);
        return DerWriter.sequence(
                DerWriter.oid(Oid.KEY_USAGE),
                DerWriter.booleanVal(critical),
                DerWriter.octetString(bitString)
        );
    }

    public static byte[] buildEkuExtension(List<String> purposeOids, boolean critical) {
        List<byte[]> oids = new ArrayList<>();
        for (String p : purposeOids) {
            oids.add(DerWriter.oid(p));
        }
        byte[] seq = DerWriter.sequence(oids.toArray(new byte[0][]));
        return DerWriter.sequence(
                DerWriter.oid(Oid.EXTENDED_KEY_USAGE),
                DerWriter.booleanVal(critical),
                DerWriter.octetString(seq)
        );
    }

    public static byte[] buildSanExtension(List<String> dnsNames, boolean critical) {
        List<byte[]> gns = new ArrayList<>();
        for (String dns : dnsNames) {
            gns.add(DerWriter.contextImplicit(2, dns.getBytes(java.nio.charset.StandardCharsets.US_ASCII), false));
        }
        byte[] seq = DerWriter.sequence(gns.toArray(new byte[0][]));
        return DerWriter.sequence(
                DerWriter.oid(Oid.SUBJECT_ALTERNATIVE_NAME),
                DerWriter.booleanVal(critical),
                DerWriter.octetString(seq)
        );
    }

    public static byte[] buildCustomCriticalExtension(String oid, byte[] rawValue) {
        return DerWriter.sequence(
                DerWriter.oid(oid),
                DerWriter.booleanVal(true),
                DerWriter.octetString(rawValue)
        );
    }

    public static X509Certificate issueCertificate(
            BigInteger serialNumber,
            String subjectCn,
            String issuerCn,
            PublicKey subjectPublicKey,
            PrivateKey issuerPrivateKey,
            String sigAlgOid,
            Instant notBefore,
            Instant notAfter,
            List<byte[]> extensionDerList
    ) throws Exception {

        byte[] versionNode = DerWriter.contextExplicit(0, DerWriter.integer(2)); // v3 = 2
        byte[] serialNode = DerWriter.integer(serialNumber);
        byte[] sigAlgNode = buildAlgorithmId(sigAlgOid);
        byte[] issuerNode = buildName(issuerCn, "Test PKI Org", "US");
        byte[] validityNode = buildValidity(notBefore, notAfter);
        byte[] subjectNode = buildName(subjectCn, "Test PKI Org", "US");
        byte[] spkiNode = subjectPublicKey.getEncoded(); // Standard X.509 SubjectPublicKeyInfo DER

        ByteArrayOutputStream tbsStream = new ByteArrayOutputStream();
        tbsStream.write(versionNode);
        tbsStream.write(serialNode);
        tbsStream.write(sigAlgNode);
        tbsStream.write(issuerNode);
        tbsStream.write(validityNode);
        tbsStream.write(subjectNode);
        tbsStream.write(spkiNode);

        if (extensionDerList != null && !extensionDerList.isEmpty()) {
            byte[] extSeq = DerWriter.sequence(extensionDerList.toArray(new byte[0][]));
            byte[] extExplicit = DerWriter.contextExplicit(3, extSeq);
            tbsStream.write(extExplicit);
        }

        byte[] tbsCertificate = DerWriter.sequence(tbsStream.toByteArray());

        // Sign TBSCertificate
        String jcaAlg = X509Certificate.resolveJcaSignatureAlgorithm(sigAlgOid);
        Signature sig = Signature.getInstance(jcaAlg);
        sig.initSign(issuerPrivateKey);
        sig.update(tbsCertificate);
        byte[] signatureBytes = sig.sign();

        byte[] sigBitString = DerWriter.bitString(signatureBytes, 0);

        byte[] certDer = DerWriter.sequence(
                tbsCertificate,
                sigAlgNode,
                sigBitString
        );

        return X509Certificate.fromDer(certDer);
    }
}
