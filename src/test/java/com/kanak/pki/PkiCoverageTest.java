package com.kanak.pki;

import com.kanak.pki.asn1.*;
import com.kanak.pki.cli.ValidatorCli;
import com.kanak.pki.model.*;
import com.kanak.pki.path.*;
import com.kanak.pki.pem.PemReader;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PkiCoverageTest {

    @Test
    void testValidationResultDiagnostics() {
        ValidationStep step1 = new ValidationStep("SignatureVerification", true, "CN=Leaf", "Signature verified");
        ValidationStep step2 = new ValidationStep("ValidityCheck", false, "CN=Leaf", "Certificate expired");
        List<ValidationStep> steps = List.of(step1, step2);

        ValidationResult res = ValidationResult.failure(ValidationStatus.EXPIRED, steps, "Certificate is expired");
        assertThat(res.getStatus()).isEqualTo(ValidationStatus.EXPIRED);
        assertThat(res.isValid()).isFalse();
        assertThat(res.getAuditLog()).hasSize(2);
        assertThat(res.getMessage()).isEqualTo("Certificate is expired");

        String json = res.toJson();
        assertThat(json).contains("\"valid\": false");
        assertThat(json).contains("\"status\": \"EXPIRED\"");
        assertThat(json).contains("SignatureVerification");

        String pretty = res.toPrettyString();
        assertThat(pretty).contains("RFC 5280 Path Validation Outcome: EXPIRED");
        assertThat(pretty).contains("Signature verified");

        assertThat(res.toString()).contains("EXPIRED");

        ValidationResult successRes = ValidationResult.success(List.of(step1));
        assertThat(successRes.isValid()).isTrue();
        assertThat(successRes.getStatus()).isEqualTo(ValidationStatus.VALID);
    }

    @Test
    void testTrustStoreOperations() throws Exception {
        TrustStore empty = TrustStore.createEmpty();
        assertThat(empty.isEmpty()).isTrue();
        assertThat(empty.size()).isZero();
        assertThat(empty.getAnchors()).isEmpty();

        KeyPair key1 = TestCertificateGenerator.generateRsaKeyPair();
        KeyPair key2 = TestCertificateGenerator.generateRsaKeyPair();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        X509Certificate cert1 = TestCertificateGenerator.issueCertificate(
                BigInteger.ONE, "Anchor1", "Anchor1", key1.getPublic(), key1.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION, now.minus(5, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS), List.of()
        );

        X509Certificate cert2 = TestCertificateGenerator.issueCertificate(
                BigInteger.TWO, "Anchor2", "Anchor2", key2.getPublic(), key2.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION, now.minus(5, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS), List.of()
        );

        TrustStore ts = new TrustStore();
        assertThat(ts.findTrustAnchor(cert1)).isEmpty();

        ts.addTrustAnchor(cert1);
        assertThat(ts.size()).isEqualTo(1);
        assertThat(ts.isEmpty()).isFalse();
        assertThat(ts.findTrustAnchor(cert1)).isPresent();

        ts.addAll(List.of(cert2));
        assertThat(ts.size()).isEqualTo(2);

        TrustStore fromArray = TrustStore.of(cert1, cert2);
        assertThat(fromArray.size()).isEqualTo(2);
    }

    @Test
    void testValidationContextBuilder() {
        ValidationContext ctx = ValidationContext.builder()
                .validationTime(Instant.EPOCH)
                .targetHostname("example.com")
                .requireKeyPurpose(Oid.EKU_SERVER_AUTH)
                .maxPathLength(5)
                .allowSelfSignedLeaf(true)
                .build();

        assertThat(ctx.getValidationTime()).isEqualTo(Instant.EPOCH);
        assertThat(ctx.getTargetHostname()).contains("example.com");
        assertThat(ctx.getRequiredKeyPurposes()).contains(Oid.EKU_SERVER_AUTH);
        assertThat(ctx.getMaxPathLength()).isEqualTo(5);
        assertThat(ctx.isAllowSelfSignedLeaf()).isTrue();
    }

    @Test
    void testPemReader() throws Exception {
        String pem = """
                -----BEGIN CERTIFICATE-----
                AQIDBAU=
                -----END CERTIFICATE-----
                """;
        List<byte[]> blocks = PemReader.readBlocks(pem);
        assertThat(blocks).hasSize(1);
        assertThat(blocks.get(0)).containsExactly(1, 2, 3, 4, 5);

        String multiPem = """
                # Comment line
                -----BEGIN CERTIFICATE-----
                Proc-Type: 4,ENCRYPTED
                AQID
                -----END CERTIFICATE-----
                Some text
                -----BEGIN CERTIFICATE-----
                BAUG
                -----END CERTIFICATE-----
                """;
        List<byte[]> multiBlocks = PemReader.readBlocks(multiPem);
        assertThat(multiBlocks).hasSize(2);

        try (InputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8))) {
            assertThat(PemReader.readBlocks(in)).hasSize(1);
        }
    }

    @Test
    void testOidOperations() {
        Oid oid = Oid.fromDotted("1.2.840.113549.1.1.11");
        assertThat(oid.getDottedString()).isEqualTo("1.2.840.113549.1.1.11");
        assertThat(oid.toString()).isEqualTo("1.2.840.113549.1.1.11");

        Oid fromBytes = Oid.fromBytes(oid.getEncodedBytes());
        assertThat(fromBytes).isEqualTo(oid);
        assertThat(fromBytes.hashCode()).isEqualTo(oid.hashCode());

        Oid root0 = new Oid("0.9.2342");
        assertThat(new Oid(root0.getEncodedBytes()).getDottedString()).isEqualTo("0.9.2342");

        Oid largeNode = new Oid("2.16.123456789.0");
        assertThat(new Oid(largeNode.getEncodedBytes()).getDottedString()).isEqualTo("2.16.123456789.0");

        assertThatThrownBy(() -> new Oid("1"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Oid("3.1"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Oid.decodeOid(new byte[0]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testAsn1AndDerWriter() {
        byte[] boolTrue = DerWriter.booleanVal(true);
        byte[] boolFalse = DerWriter.booleanVal(false);
        byte[] intBig = DerWriter.integer(BigInteger.valueOf(128));
        byte[] intLong = DerWriter.integer(-1L);
        byte[] nullDer = DerWriter.nullVal();
        byte[] oidDer = DerWriter.oid("2.5.4.3");
        byte[] printStr = DerWriter.printableString("Hello");
        byte[] utf8Str = DerWriter.utf8String("World");
        byte[] ia5Str = DerWriter.ia5String("Test");
        byte[] utcDer = DerWriter.utcTime(Instant.ofEpochSecond(1700000000L));
        byte[] genDer = DerWriter.generalizedTime(Instant.ofEpochSecond(1700000000L));
        byte[] bitDer = DerWriter.bitString(new byte[]{(byte) 0x80}, 7);
        byte[] octDer = DerWriter.octetString(new byte[]{1, 2, 3});
        byte[] setDer = DerWriter.set(boolTrue, intBig);
        byte[] ctxExp = DerWriter.contextExplicit(0, boolTrue);
        byte[] ctxImp = DerWriter.contextImplicit(1, octDer, false);

        byte[] seq = DerWriter.sequence(
                boolTrue, boolFalse, intBig, intLong, nullDer, oidDer,
                printStr, utf8Str, ia5Str, utcDer, genDer, bitDer, octDer,
                setDer, ctxExp, ctxImp
        );

        Asn1Node rootNode = DerParser.parse(seq);
        assertThat(rootNode.isConstructed()).isTrue();
        assertThat(rootNode.getChildren()).isNotEmpty();

        Asn1Node bNode = rootNode.getChildren().get(0);
        assertThat(bNode.asBoolean()).isTrue();
        assertThat(bNode.toString()).isNotEmpty();
    }

    @Test
    void testModelTypesAndKeyUsage() {
        boolean[] bits = new boolean[]{true, true, true, true, true, true, true, true, true};
        KeyUsage ku = new KeyUsage(bits);
        assertThat(ku.isDigitalSignature()).isTrue();
        assertThat(ku.isNonRepudiation()).isTrue();
        assertThat(ku.isKeyEncipherment()).isTrue();
        assertThat(ku.isDataEncipherment()).isTrue();
        assertThat(ku.isKeyAgreement()).isTrue();
        assertThat(ku.isKeyCertSign()).isTrue();
        assertThat(ku.isCrlSign()).isTrue();
        assertThat(ku.isEncipherOnly()).isTrue();
        assertThat(ku.isDecipherOnly()).isTrue();
        assertThat(ku.isSet(KeyUsage.DIGITAL_SIGNATURE)).isTrue();
        assertThat(ku.isSet(-1)).isFalse();
        assertThat(ku.isSet(100)).isFalse();
        assertThat(ku.toString()).contains("digitalSignature");

        BasicConstraints bc = new BasicConstraints(true, java.util.OptionalInt.of(3));
        assertThat(bc.isCa()).isTrue();
        assertThat(bc.getPathLenConstraint()).hasValue(3);
        assertThat(bc.toString()).contains("ca=true");

        GeneralName gnDns = new GeneralName(GeneralName.Type.DNS_NAME, "example.com", "example.com".getBytes(StandardCharsets.US_ASCII));
        assertThat(gnDns.getType()).isEqualTo(GeneralName.Type.DNS_NAME);
        assertThat(gnDns.getValue()).isEqualTo("example.com");
        assertThat(gnDns.getRawValue()).isNotEmpty();
        assertThat(gnDns.toString()).contains("example.com");

        GeneralNames gns = new GeneralNames(List.of(gnDns));
        assertThat(gns.matchesHostname("example.com")).isTrue();
        assertThat(gns.matchesHostname("other.com")).isFalse();
        assertThat(gns.getNames()).hasSize(1);
        assertThat(gns.toString()).contains("example.com");
    }

    @Test
    void testCliHelp() {
        ValidatorCli.main(new String[]{"--help"});
    }

    @Test
    void testAsn1NodeMethodsAndEdgeCases() {
        // Asn1Node getters
        byte[] intBytes = DerWriter.integer(42);
        Asn1Node intNode = DerParser.parse(intBytes);
        assertThat(intNode.asInt()).isEqualTo(42);
        assertThat(intNode.getTag()).isEqualTo(Asn1Tag.INTEGER);
        assertThat(intNode.getTagClass()).isEqualTo(Asn1Tag.CLASS_UNIVERSAL);
        assertThat(intNode.getTagNumber()).isEqualTo(Asn1Tag.INTEGER);
        assertThat(intNode.getChildCount()).isZero();
        assertThat(intNode.getRawEncodedBytes()).isNotEmpty();
        assertThat(intNode.getContentBytes()).isNotEmpty();
        assertThat(intNode.getHeader().getTotalLength()).isEqualTo(intBytes.length);

        assertThatThrownBy(() -> intNode.getChild(0))
                .isInstanceOf(IndexOutOfBoundsException.class);
        assertThatThrownBy(() -> intNode.getChild(-1))
                .isInstanceOf(IndexOutOfBoundsException.class);

        // Children search
        byte[] seqBytes = DerWriter.sequence(intBytes, DerWriter.booleanVal(true));
        Asn1Node seqNode = DerParser.parse(seqBytes);
        assertThat(seqNode.getChildCount()).isEqualTo(2);
        assertThat(seqNode.getChild(0).asInt()).isEqualTo(42);
        assertThat(seqNode.findChild(Asn1Tag.INTEGER)).isPresent();
        assertThat(seqNode.findChild(Asn1Tag.NULL)).isEmpty();
        assertThat(seqNode.findChildByTagNumber(Asn1Tag.BOOLEAN)).isPresent();
        assertThat(seqNode.findChildByTagNumber(99)).isEmpty();

        // String types
        byte[] utf8 = DerWriter.utf8String("hello utf8");
        assertThat(DerParser.parse(utf8).asString()).isEqualTo("hello utf8");

        byte[] printable = DerWriter.printableString("hello printable");
        assertThat(DerParser.parse(printable).asString()).isEqualTo("hello printable");

        byte[] ia5 = DerWriter.ia5String("hello ia5");
        assertThat(DerParser.parse(ia5).asString()).isEqualTo("hello ia5");

        byte[] teletex = DerWriter.tlv(Asn1Tag.TELETEX_STRING, "hello teletex".getBytes(StandardCharsets.US_ASCII));
        assertThat(DerParser.parse(teletex).asString()).isEqualTo("hello teletex");

        byte[] otherStr = DerWriter.tlv(0x1B, "hello other".getBytes(StandardCharsets.UTF_8));
        assertThat(DerParser.parse(otherStr).asString()).isEqualTo("hello other");

        // Time types
        // UTCTime: year >= 50 -> 19YY, year < 50 -> 20YY
        byte[] utc1980 = DerWriter.tlv(Asn1Tag.UTC_TIME, "800101120000Z".getBytes(StandardCharsets.US_ASCII));
        Asn1Node utcNode1980 = DerParser.parse(utc1980);
        assertThat(utcNode1980.asInstant()).isEqualTo(Instant.parse("1980-01-01T12:00:00Z"));

        byte[] utc2030 = DerWriter.tlv(Asn1Tag.UTC_TIME, "300101120000Z".getBytes(StandardCharsets.US_ASCII));
        Asn1Node utcNode2030 = DerParser.parse(utc2030);
        assertThat(utcNode2030.asInstant()).isEqualTo(Instant.parse("2030-01-01T12:00:00Z"));

        // UTCTime malformed: short or no Z
        byte[] badUtc1 = DerWriter.tlv(Asn1Tag.UTC_TIME, "800101".getBytes(StandardCharsets.US_ASCII));
        assertThatThrownBy(() -> DerParser.parse(badUtc1).asInstant())
                .isInstanceOf(IllegalArgumentException.class);

        byte[] badUtc2 = DerWriter.tlv(Asn1Tag.UTC_TIME, "800101120000X".getBytes(StandardCharsets.US_ASCII));
        assertThatThrownBy(() -> DerParser.parse(badUtc2).asInstant())
                .isInstanceOf(IllegalArgumentException.class);

        // GeneralizedTime without fractional seconds
        byte[] genPlain = DerWriter.tlv(Asn1Tag.GENERALIZED_TIME, "20260911120000Z".getBytes(StandardCharsets.US_ASCII));
        assertThat(DerParser.parse(genPlain).asInstant()).isEqualTo(Instant.parse("2026-09-11T12:00:00Z"));

        // GeneralizedTime with fractional seconds
        byte[] genFrac = DerWriter.tlv(Asn1Tag.GENERALIZED_TIME, "20260911120000.123Z".getBytes(StandardCharsets.US_ASCII));
        assertThat(DerParser.parse(genFrac).asInstant()).isEqualTo(Instant.parse("2026-09-11T12:00:00.123Z"));

        // GeneralizedTime without Z
        byte[] genBad = DerWriter.tlv(Asn1Tag.GENERALIZED_TIME, "20260911120000".getBytes(StandardCharsets.US_ASCII));
        assertThatThrownBy(() -> DerParser.parse(genBad).asInstant())
                .isInstanceOf(IllegalArgumentException.class);

        // Non-time node calling asInstant()
        assertThatThrownBy(intNode::asInstant)
                .isInstanceOf(IllegalStateException.class);

        // Bit string edge cases
        byte[] emptyBitStr = DerWriter.tlv(Asn1Tag.BIT_STRING, new byte[0]);
        Asn1Node emptyBitNode = DerParser.parse(emptyBitStr);
        assertThat(emptyBitNode.asBitStringData()).isEmpty();
        assertThat(emptyBitNode.getBitStringUnusedBits()).isZero();

        byte[] normalBitStr = DerWriter.bitString(new byte[]{(byte) 0b11000000}, 6);
        Asn1Node normalBitNode = DerParser.parse(normalBitStr);
        assertThat(normalBitNode.getBitStringUnusedBits()).isEqualTo(6);
        assertThat(normalBitNode.asBitStringData()).containsExactly((byte) 0b11000000);

        // Invalid unused bits > 7
        byte[] badUnused = new byte[]{Asn1Tag.BIT_STRING, 2, 8, 0x00};
        assertThatThrownBy(() -> DerParser.parse(badUnused).asBitStringData())
                .isInstanceOf(IllegalStateException.class);

        // Length 1 but unused bits != 0
        byte[] badLen1 = new byte[]{Asn1Tag.BIT_STRING, 1, 3};
        assertThatThrownBy(() -> DerParser.parse(badLen1).asBitStringData())
                .isInstanceOf(IllegalStateException.class);

        // Trailing non-zero unused bits
        byte[] badTrailing = new byte[]{Asn1Tag.BIT_STRING, 2, 4, 0x0F};
        assertThatThrownBy(() -> DerParser.parse(badTrailing).asBitStringData())
                .isInstanceOf(IllegalStateException.class);

        // Boolean length != 1
        byte[] badBoolLen = new byte[]{Asn1Tag.BOOLEAN, 2, 0, 0};
        assertThatThrownBy(() -> DerParser.parse(badBoolLen).asBoolean())
                .isInstanceOf(IllegalStateException.class);

        // Integer length 0
        byte[] badIntZero = new byte[]{Asn1Tag.INTEGER, 0};
        assertThatThrownBy(() -> DerParser.parse(badIntZero).asBigInteger())
                .isInstanceOf(IllegalStateException.class);

        // Superfluous leading 0xFF
        byte[] badIntFF = new byte[]{Asn1Tag.INTEGER, 2, (byte) 0xFF, (byte) 0x80};
        assertThatThrownBy(() -> DerParser.parse(badIntFF).asBigInteger())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void testDerParserAndHeaderEdgeCases() {
        // Empty bytes
        assertThatThrownBy(() -> DerParser.parse(new byte[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Empty DER byte array");

        // Null bytes
        assertThatThrownBy(() -> DerParser.parse(null))
                .isInstanceOf(NullPointerException.class);

        // Max buffer ceiling
        assertThatThrownBy(() -> DerParser.parse(new byte[DerParser.MAX_BUFFER_SIZE + 1]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exceeds maximum ceiling");

        // Trailing unparsed bytes
        byte[] withTrailing = new byte[]{Asn1Tag.BOOLEAN, 1, (byte) 0xFF, 0x00};
        assertThatThrownBy(() -> DerParser.parse(withTrailing))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Trailing unparsed bytes");

        // Parse sequence
        byte[] b1 = DerWriter.booleanVal(true);
        byte[] b2 = DerWriter.booleanVal(false);
        byte[] joined = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, joined, 0, b1.length);
        System.arraycopy(b2, 0, joined, b1.length, b2.length);

        List<Asn1Node> seqNodes = DerParser.parseSequence(joined, 0, joined.length);
        assertThat(seqNodes).hasSize(2);
        assertThat(seqNodes.get(0).asBoolean()).isTrue();
        assertThat(seqNodes.get(1).asBoolean()).isFalse();

        // DerWriter multi-byte lengths
        byte[] mediumPayload = new byte[300];
        byte[] mediumDer = DerWriter.tlv(Asn1Tag.OCTET_STRING, mediumPayload);
        Asn1Node mediumNode = DerParser.parse(mediumDer);
        assertThat(mediumNode.getContentBytes()).hasSize(300);

        // Asn1Header high-tag-number form: tag byte 0x1F followed by tag numbers
        byte[] highTagDer = new byte[]{0x1F, (byte) 0x81, 0x01, 0x01, 0x00}; // Tag 129, length 1, content 0
        Asn1Node highTagNode = DerParser.parse(highTagDer);
        assertThat(highTagNode.getTagNumber()).isEqualTo(129);

        // Truncated high tag number
        byte[] truncHighTag = new byte[]{0x1F, (byte) 0x81};
        assertThatThrownBy(() -> DerParser.parse(truncHighTag))
                .isInstanceOf(IllegalArgumentException.class);

        // Truncated header before length
        byte[] truncHeader = new byte[]{0x02};
        assertThatThrownBy(() -> DerParser.parse(truncHeader))
                .isInstanceOf(IllegalArgumentException.class);

        // Illegal number of length bytes (5 bytes)
        byte[] illegalLenBytes = new byte[]{0x04, (byte) 0x85, 1, 2, 3, 4, 5, 0};
        assertThatThrownBy(() -> DerParser.parse(illegalLenBytes))
                .isInstanceOf(IllegalArgumentException.class);

        // Leading 0x00 in long form length
        byte[] leadingZeroLen = new byte[]{0x04, (byte) 0x82, 0x00, 0x05, 1, 2, 3, 4, 5};
        assertThatThrownBy(() -> DerParser.parse(leadingZeroLen))
                .isInstanceOf(IllegalArgumentException.class);

        // Content length exceeds buffer boundary
        byte[] exceedsBuf = new byte[]{0x04, 0x05, 1, 2};
        assertThatThrownBy(() -> DerParser.parse(exceedsBuf))
                .isInstanceOf(IllegalArgumentException.class);

        // Truncated length octets in long form
        byte[] truncLen = new byte[]{0x04, (byte) 0x82, 0x01};
        assertThatThrownBy(() -> DerParser.parse(truncLen))
                .isInstanceOf(IllegalArgumentException.class);

        // Asn1Tag helper functions
        assertThat(Asn1Tag.isConstructed(Asn1Tag.TAG_SEQUENCE)).isTrue();
        assertThat(Asn1Tag.isConstructed(Asn1Tag.INTEGER)).isFalse();
        assertThat(Asn1Tag.getTagClass(Asn1Tag.INTEGER)).isEqualTo(Asn1Tag.CLASS_UNIVERSAL);
        assertThat(Asn1Tag.getTagNumber(Asn1Tag.INTEGER)).isEqualTo(2);
    }
}
