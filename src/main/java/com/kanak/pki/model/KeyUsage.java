package com.kanak.pki.model;

import com.kanak.pki.asn1.Asn1Node;
import com.kanak.pki.asn1.DerParser;

/**
 * KeyUsage X.509 extension conforming to RFC 5280 §4.2.1.3.
 *
 * <pre>
 * KeyUsage ::= BIT STRING {
 *      digitalSignature        (0),
 *      nonRepudiation          (1),
 *      keyEncipherment         (2),
 *      dataEncipherment        (3),
 *      keyAgreement            (4),
 *      keyCertSign             (5),
 *      cRLSign                 (6),
 *      encipherOnly            (7),
 *      decipherOnly            (8) }
 * </pre>
 */
public final class KeyUsage {

    public static final int DIGITAL_SIGNATURE = 0;
    public static final int NON_REPUDIATION   = 1;
    public static final int KEY_ENCIPHERMENT  = 2;
    public static final int DATA_ENCIPHERMENT = 3;
    public static final int KEY_AGREEMENT     = 4;
    public static final int KEY_CERT_SIGN     = 5;
    public static final int CRL_SIGN          = 6;
    public static final int ENCIPHER_ONLY     = 7;
    public static final int DECIPHER_ONLY     = 8;

    private final boolean[] bits = new boolean[9];

    public KeyUsage(boolean[] bits) {
        if (bits != null) {
            System.arraycopy(bits, 0, this.bits, 0, Math.min(bits.length, this.bits.length));
        }
    }

    public static KeyUsage fromExtensionValue(byte[] extnValueDer) {
        Asn1Node node = DerParser.parse(extnValueDer);
        byte[] data = node.asBitStringData();
        boolean[] bits = new boolean[9];

        for (int i = 0; i < 9; i++) {
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);
            if (byteIndex < data.length) {
                bits[i] = ((data[byteIndex] >> bitIndex) & 1) == 1;
            }
        }
        return new KeyUsage(bits);
    }

    public boolean isSet(int bitIndex) {
        if (bitIndex < 0 || bitIndex >= bits.length) return false;
        return bits[bitIndex];
    }

    public boolean isDigitalSignature() { return isSet(DIGITAL_SIGNATURE); }
    public boolean isNonRepudiation()   { return isSet(NON_REPUDIATION); }
    public boolean isKeyEncipherment()  { return isSet(KEY_ENCIPHERMENT); }
    public boolean isDataEncipherment() { return isSet(DATA_ENCIPHERMENT); }
    public boolean isKeyAgreement()     { return isSet(KEY_AGREEMENT); }
    public boolean isKeyCertSign()      { return isSet(KEY_CERT_SIGN); }
    public boolean isCrlSign()          { return isSet(CRL_SIGN); }
    public boolean isEncipherOnly()     { return isSet(ENCIPHER_ONLY); }
    public boolean isDecipherOnly()     { return isSet(DECIPHER_ONLY); }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("KeyUsage[");
        boolean first = true;
        if (isDigitalSignature()) { sb.append("digitalSignature"); first = false; }
        if (isKeyEncipherment()) { if (!first) sb.append(", "); sb.append("keyEncipherment"); first = false; }
        if (isKeyCertSign()) { if (!first) sb.append(", "); sb.append("keyCertSign"); first = false; }
        if (isCrlSign()) { if (!first) sb.append(", "); sb.append("cRLSign"); first = false; }
        sb.append(']');
        return sb.toString();
    }
}
