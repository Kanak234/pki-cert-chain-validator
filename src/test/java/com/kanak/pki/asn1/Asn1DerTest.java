package com.kanak.pki.asn1;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Asn1DerTest {

    @Test
    @DisplayName("Should encode and parse ASN.1 BOOLEAN correctly per ITU-T X.690")
    void testBooleanEncoding() {
        byte[] trueDer = DerWriter.booleanVal(true);
        byte[] falseDer = DerWriter.booleanVal(false);

        Asn1Node nodeTrue = DerParser.parse(trueDer);
        assertThat(nodeTrue.asBoolean()).isTrue();

        Asn1Node nodeFalse = DerParser.parse(falseDer);
        assertThat(nodeFalse.asBoolean()).isFalse();

        // Strict DER: any byte other than 0x00 or 0xFF must be rejected
        byte[] invalidDer = new byte[]{0x01, 0x01, 0x7F};
        Asn1Node invalidNode = DerParser.parse(invalidDer);
        assertThatThrownBy(invalidNode::asBoolean)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Invalid DER BOOLEAN encoding");
    }

    @Test
    @DisplayName("Should encode and parse ASN.1 INTEGER and reject non-minimal encodings")
    void testIntegerEncoding() {
        byte[] intDer = DerWriter.integer(123456789L);
        Asn1Node node = DerParser.parse(intDer);
        assertThat(node.asBigInteger()).isEqualTo(BigInteger.valueOf(123456789L));

        // Negative integer
        byte[] negDer = DerWriter.integer(-42L);
        Asn1Node negNode = DerParser.parse(negDer);
        assertThat(negNode.asBigInteger()).isEqualTo(BigInteger.valueOf(-42L));

        // Non-minimal integer: leading 0x00 when bit 8 is not set
        byte[] nonMinimal = new byte[]{0x02, 0x02, 0x00, 0x7F};
        Asn1Node nonMinimalNode = DerParser.parse(nonMinimal);
        assertThatThrownBy(nonMinimalNode::asBigInteger)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("superfluous leading zero byte");
    }

    @Test
    @DisplayName("Should reject indefinite length encoding in DER (ITU-T X.690 §10.1)")
    void testIndefiniteLengthRejection() {
        // Tag 0x30 (SEQUENCE), Length 0x80 (Indefinite)
        byte[] indefinite = new byte[]{0x30, (byte) 0x80, 0x00, 0x00};
        assertThatThrownBy(() -> DerParser.parse(indefinite))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Indefinite length encoding is strictly prohibited in DER");
    }

    @Test
    @DisplayName("Should reject non-minimal length octets")
    void testNonMinimalLengthOctets() {
        // Encoding length 10 using long form (0x81, 0x0A) when short form (0x0A) is required
        byte[] nonMinimal = new byte[]{0x04, (byte) 0x81, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        assertThatThrownBy(() -> DerParser.parse(nonMinimal))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Non-minimal DER length encoding");
    }

    @Test
    @DisplayName("Should encode and decode standard Object Identifiers (OIDs)")
    void testOidEncodingDecoding() {
        String[] testOids = {
                "2.5.4.3",              // Common Name
                "1.2.840.113549.1.1.11", // SHA256withRSA
                "2.5.29.19",            // BasicConstraints
                "1.3.6.1.5.5.7.3.1"     // serverAuth
        };

        for (String oidStr : testOids) {
            byte[] encoded = DerWriter.oid(oidStr);
            Asn1Node node = DerParser.parse(encoded);
            assertThat(node.asOid().getDottedString()).isEqualTo(oidStr);
        }
    }

    @Test
    @DisplayName("Should parse UTCTime and GeneralizedTime conforming to RFC 5280")
    void testTimeParsing() {
        Instant now = Instant.parse("2026-09-11T00:00:00Z");

        byte[] utcDer = DerWriter.utcTime(now);
        Asn1Node utcNode = DerParser.parse(utcDer);
        assertThat(utcNode.asInstant()).isEqualTo(now);

        byte[] genDer = DerWriter.generalizedTime(now);
        Asn1Node genNode = DerParser.parse(genDer);
        assertThat(genNode.asInstant()).isEqualTo(now);
    }
}
