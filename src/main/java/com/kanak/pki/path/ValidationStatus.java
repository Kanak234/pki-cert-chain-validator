package com.kanak.pki.path;

/**
 * Diagnostic status codes for RFC 5280 certification path validation outcomes.
 */
public enum ValidationStatus {
    VALID("Certification path successfully verified to trusted anchor"),
    EMPTY_PATH("Certification path is empty"),
    UNTRUSTED_ROOT("Trust anchor not found in configured trust store"),
    EXPIRED("Certificate validity period has expired"),
    NOT_YET_VALID("Certificate validity period is in the future"),
    SIGNATURE_VERIFICATION_FAILED("Cryptographic signature verification failed"),
    NAME_CHAINING_FAILURE("Issuer Distinguished Name does not match parent Subject DN"),
    BASIC_CONSTRAINTS_VIOLATION("Intermediate certificate lacks isCA=true BasicConstraints"),
    PATH_LENGTH_EXCEEDED("Certification path exceeds intermediate CA pathLenConstraint"),
    KEY_USAGE_MISMATCH("Required KeyUsage flag is missing"),
    EXTENDED_KEY_USAGE_MISMATCH("Required ExtendedKeyUsage purpose OID is missing"),
    CRITICAL_EXTENSION_UNHANDLED("Certificate contains an unrecognized critical extension"),
    HOSTNAME_MISMATCH("Target hostname does not match leaf Subject Alternative Names or CN"),
    MALFORMED_CERTIFICATE("Certificate data is corrupt or violates DER encoding rules");

    private final String description;

    ValidationStatus(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public boolean isValid() {
        return this == VALID;
    }
}
