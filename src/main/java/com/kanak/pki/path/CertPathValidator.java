package com.kanak.pki.path;

import com.kanak.pki.asn1.Oid;
import com.kanak.pki.model.BasicConstraints;
import com.kanak.pki.model.ExtendedKeyUsage;
import com.kanak.pki.model.Extensions;
import com.kanak.pki.model.GeneralNames;
import com.kanak.pki.model.KeyUsage;
import com.kanak.pki.model.X509Certificate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Pure-Java RFC 5280 Certification Path Validation state machine.
 */
public final class CertPathValidator {

    private static final Set<String> RECOGNIZED_CRITICAL_EXTENSIONS = Set.of(
            Oid.BASIC_CONSTRAINTS,
            Oid.KEY_USAGE,
            Oid.EXTENDED_KEY_USAGE,
            Oid.SUBJECT_ALTERNATIVE_NAME,
            Oid.SUBJECT_KEY_IDENTIFIER,
            Oid.AUTHORITY_KEY_IDENTIFIER
    );

    private final TrustStore trustStore;

    public CertPathValidator(TrustStore trustStore) {
        this.trustStore = Objects.requireNonNull(trustStore, "trustStore must not be null");
    }

    /**
     * Validates a certification path from leaf to root against the configured TrustStore.
     */
    public ValidationResult validate(List<X509Certificate> certs, ValidationContext context) {
        List<ValidationStep> auditLog = new ArrayList<>();

        if (certs == null || certs.isEmpty()) {
            auditLog.add(ValidationStep.fail("Path Initialization", "N/A", "Certificate path is empty"));
            return ValidationResult.failure(ValidationStatus.EMPTY_PATH, auditLog, "Path is empty");
        }

        // Order the chain from leaf to root
        List<X509Certificate> chain = orderChain(certs);
        auditLog.add(ValidationStep.pass("Path Construction", chain.get(0).getSubject().getCanonicalString(),
                "Constructed valid linear path of length " + chain.size() + " from leaf to root"));

        if (chain.size() > context.getMaxPathLength()) {
            auditLog.add(ValidationStep.fail("Max Path Length", chain.get(0).getSubject().getCanonicalString(),
                    "Chain length " + chain.size() + " exceeds configured ceiling of " + context.getMaxPathLength()));
            return ValidationResult.failure(ValidationStatus.PATH_LENGTH_EXCEEDED, auditLog, "Chain exceeds maxPathLength");
        }

        X509Certificate rootCert = chain.get(chain.size() - 1);
        Optional<X509Certificate> trustAnchor = trustStore.findTrustAnchor(rootCert);

        if (trustAnchor.isEmpty()) {
            // Check self-signed leaf exception if single cert and explicitly allowed
            if (chain.size() == 1 && context.isAllowSelfSignedLeaf() && rootCert.isSelfSigned()) {
                auditLog.add(ValidationStep.pass("Trust Anchor Grounding", rootCert.getSubject().getCanonicalString(),
                        "Self-signed leaf certificate accepted per context override"));
            } else {
                auditLog.add(ValidationStep.fail("Trust Anchor Grounding", rootCert.getSubject().getCanonicalString(),
                        "Root certificate not found in configured trust store"));
                return ValidationResult.failure(ValidationStatus.UNTRUSTED_ROOT, auditLog,
                        "Root certificate not found in trust store: " + rootCert.getSubject());
            }
        } else {
            auditLog.add(ValidationStep.pass("Trust Anchor Grounding", rootCert.getSubject().getCanonicalString(),
                    "Root anchor successfully matched in trust store"));
        }

        Instant validationTime = context.getValidationTime();

        // 1. Check validity periods and critical extensions for ALL certificates in the path
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate cert = chain.get(i);
            String role = (i == 0) ? "Leaf" : (i == chain.size() - 1 ? "Root Anchor" : "Intermediate CA");
            String subjectStr = cert.getSubject().getCanonicalString();

            // Temporal validity
            if (validationTime.isBefore(cert.getValidity().getNotBefore())) {
                auditLog.add(ValidationStep.fail("Temporal Validity (" + role + ")", subjectStr,
                        "Certificate is not yet valid at " + validationTime + " (notBefore: " + cert.getValidity().getNotBefore() + ")"));
                return ValidationResult.failure(ValidationStatus.NOT_YET_VALID, auditLog,
                        role + " certificate is not yet valid: " + cert.getSubject());
            }
            if (validationTime.isAfter(cert.getValidity().getNotAfter())) {
                auditLog.add(ValidationStep.fail("Temporal Validity (" + role + ")", subjectStr,
                        "Certificate expired at " + cert.getValidity().getNotAfter() + " (validationTime: " + validationTime + ")"));
                return ValidationResult.failure(ValidationStatus.EXPIRED, auditLog,
                        role + " certificate has expired: " + cert.getSubject());
            }
            auditLog.add(ValidationStep.pass("Temporal Validity (" + role + ")", subjectStr,
                    "Current time " + validationTime + " is within valid interval " + cert.getValidity()));

            // Unrecognized Critical Extensions (RFC 5280 §4.2)
            for (String critOid : cert.getExtensions().getCriticalExtensionOids()) {
                if (!RECOGNIZED_CRITICAL_EXTENSIONS.contains(critOid)) {
                    auditLog.add(ValidationStep.fail("Critical Extension (" + role + ")", subjectStr,
                            "Unrecognized critical extension encountered: OID " + critOid));
                    return ValidationResult.failure(ValidationStatus.CRITICAL_EXTENSION_UNHANDLED, auditLog,
                            "Unrecognized critical extension OID: " + critOid);
                }
            }
            auditLog.add(ValidationStep.pass("Critical Extensions (" + role + ")", subjectStr,
                    "All critical extensions are fully recognized"));
        }

        // 2. Chaining and Signature Verification (from leaf to root)
        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate child = chain.get(i);
            X509Certificate parent = chain.get(i + 1);

            // Name chaining check
            if (!child.getIssuer().equals(parent.getSubject())) {
                auditLog.add(ValidationStep.fail("Name Chaining", child.getSubject().getCanonicalString(),
                        "Issuer DN [" + child.getIssuer() + "] does not match parent Subject DN [" + parent.getSubject() + "]"));
                return ValidationResult.failure(ValidationStatus.NAME_CHAINING_FAILURE, auditLog,
                        "Name chaining mismatch between " + child.getSubject() + " and " + parent.getSubject());
            }
            auditLog.add(ValidationStep.pass("Name Chaining", child.getSubject().getCanonicalString(),
                    "Issuer DN matches parent Subject DN [" + parent.getSubject() + "]"));

            // Cryptographic signature check
            boolean sigValid = child.verifySignature(parent.getPublicKey());
            if (!sigValid) {
                auditLog.add(ValidationStep.fail("Signature Verification", child.getSubject().getCanonicalString(),
                        "Cryptographic signature verification failed using parent public key"));
                return ValidationResult.failure(ValidationStatus.SIGNATURE_VERIFICATION_FAILED, auditLog,
                        "Signature verification failed for: " + child.getSubject());
            }
            auditLog.add(ValidationStep.pass("Signature Verification", child.getSubject().getCanonicalString(),
                    "Cryptographic signature verified with algorithm " + child.getSignatureAlgorithmOid()));
        }

        // 3. Intermediate CA Constraints (i = 1 to chain.size() - 2)
        for (int i = 1; i < chain.size() - 1; i++) {
            X509Certificate intermediate = chain.get(i);
            String subDn = intermediate.getSubject().getCanonicalString();

            // BasicConstraints: must assert isCA = true
            Optional<BasicConstraints> bcOpt = intermediate.getExtensions().getBasicConstraints();
            if (bcOpt.isEmpty() || !bcOpt.get().isCa()) {
                auditLog.add(ValidationStep.fail("BasicConstraints CA Check", subDn,
                        "Intermediate certificate does not assert isCA=true BasicConstraints"));
                return ValidationResult.failure(ValidationStatus.BASIC_CONSTRAINTS_VIOLATION, auditLog,
                        "Intermediate lacking isCA=true: " + intermediate.getSubject());
            }
            auditLog.add(ValidationStep.pass("BasicConstraints CA Check", subDn,
                    "Intermediate certificate asserts isCA=true"));

            // PathLenConstraint check (RFC 5280 §4.2.1.9)
            if (bcOpt.get().getPathLenConstraint().isPresent()) {
                int maxIntermediatesBelow = bcOpt.get().getPathLenConstraint().getAsInt();
                int actualIntermediatesBelow = i - 1;
                if (actualIntermediatesBelow > maxIntermediatesBelow) {
                    auditLog.add(ValidationStep.fail("Path Length Constraint", subDn,
                            "Actual intermediates below (" + actualIntermediatesBelow + ") exceeds constraint (" + maxIntermediatesBelow + ")"));
                    return ValidationResult.failure(ValidationStatus.PATH_LENGTH_EXCEEDED, auditLog,
                            "Path length constraint exceeded at intermediate: " + intermediate.getSubject());
                }
                auditLog.add(ValidationStep.pass("Path Length Constraint", subDn,
                        "Intermediates below (" + actualIntermediatesBelow + ") within limit (" + maxIntermediatesBelow + ")"));
            }

            // KeyUsage check: keyCertSign must be set if KeyUsage extension present
            Optional<KeyUsage> kuOpt = intermediate.getExtensions().getKeyUsage();
            if (kuOpt.isPresent() && !kuOpt.get().isKeyCertSign()) {
                auditLog.add(ValidationStep.fail("KeyUsage Check", subDn,
                        "Intermediate CA certificate does not have keyCertSign bit asserted"));
                return ValidationResult.failure(ValidationStatus.KEY_USAGE_MISMATCH, auditLog,
                        "Intermediate CA lacking keyCertSign: " + intermediate.getSubject());
            }
            auditLog.add(ValidationStep.pass("KeyUsage Check", subDn,
                    "Intermediate CA has keyCertSign asserted (or KeyUsage omitted)"));
        }

        // 4. Leaf Certificate Constraints
        X509Certificate leaf = chain.get(0);
        String leafDn = leaf.getSubject().getCanonicalString();

        // ExtendedKeyUsage requirement checks
        if (!context.getRequiredKeyPurposes().isEmpty()) {
            Optional<ExtendedKeyUsage> ekuOpt = leaf.getExtensions().getExtendedKeyUsage();
            if (ekuOpt.isEmpty()) {
                auditLog.add(ValidationStep.fail("ExtendedKeyUsage Purpose", leafDn,
                        "Leaf certificate lacks ExtendedKeyUsage extension for required purposes: " + context.getRequiredKeyPurposes()));
                return ValidationResult.failure(ValidationStatus.EXTENDED_KEY_USAGE_MISMATCH, auditLog,
                        "Leaf missing required ExtendedKeyUsage: " + context.getRequiredKeyPurposes());
            }
            for (String requiredPurpose : context.getRequiredKeyPurposes()) {
                if (!ekuOpt.get().hasPurpose(requiredPurpose)) {
                    auditLog.add(ValidationStep.fail("ExtendedKeyUsage Purpose", leafDn,
                            "Leaf certificate missing required purpose OID: " + requiredPurpose));
                    return ValidationResult.failure(ValidationStatus.EXTENDED_KEY_USAGE_MISMATCH, auditLog,
                            "Leaf missing required purpose: " + requiredPurpose);
                }
            }
            auditLog.add(ValidationStep.pass("ExtendedKeyUsage Purpose", leafDn,
                    "All required key purposes verified: " + context.getRequiredKeyPurposes()));
        }

        // Target Hostname Verification
        if (context.getTargetHostname().isPresent()) {
            String targetHost = context.getTargetHostname().get();
            boolean hostMatched = false;

            Optional<GeneralNames> sanOpt = leaf.getExtensions().getSubjectAlternativeNames();
            if (sanOpt.isPresent()) {
                hostMatched = sanOpt.get().matchesHostname(targetHost);
            } else {
                // Fallback to CN
                Optional<String> cn = leaf.getSubject().getCommonName();
                if (cn.isPresent()) {
                    hostMatched = GeneralNames.matchPattern(targetHost, cn.get());
                }
            }

            if (!hostMatched) {
                auditLog.add(ValidationStep.fail("Hostname Matching", leafDn,
                        "Target hostname '" + targetHost + "' does not match leaf SANs or Common Name"));
                return ValidationResult.failure(ValidationStatus.HOSTNAME_MISMATCH, auditLog,
                        "Target hostname '" + targetHost + "' does not match leaf certificate");
            }
            auditLog.add(ValidationStep.pass("Hostname Matching", leafDn,
                    "Target hostname '" + targetHost + "' matches leaf certificate"));
        }

        return ValidationResult.success(auditLog);
    }

    /**
     * Orders an arbitrary list of certificates into a linear path from leaf (index 0) to root.
     */
    public static List<X509Certificate> orderChain(List<X509Certificate> certs) {
        if (certs.size() <= 1) {
            return new ArrayList<>(certs);
        }

        // Find the leaf certificate: a certificate whose subject is NOT an issuer of any other cert in the set
        Set<X509Certificate> remaining = new HashSet<>(certs);
        X509Certificate leaf = null;

        for (X509Certificate candidate : certs) {
            boolean isIssuerOfAnother = false;
            for (X509Certificate other : certs) {
                if (!candidate.equals(other) && other.getIssuer().equals(candidate.getSubject())) {
                    isIssuerOfAnother = true;
                    break;
                }
            }
            if (!isIssuerOfAnother) {
                leaf = candidate;
                break;
            }
        }

        if (leaf == null) {
            // Default to first certificate in original list
            leaf = certs.get(0);
        }

        List<X509Certificate> ordered = new ArrayList<>();
        ordered.add(leaf);
        remaining.remove(leaf);

        X509Certificate current = leaf;
        while (!remaining.isEmpty()) {
            X509Certificate parent = null;
            for (X509Certificate candidate : remaining) {
                if (current.getIssuer().equals(candidate.getSubject())) {
                    parent = candidate;
                    break;
                }
            }
            if (parent == null) {
                break; // Remaining certs do not chain
            }
            ordered.add(parent);
            remaining.remove(parent);
            if (parent.isSelfIssued()) {
                break; // Reached self-issued root
            }
            current = parent;
        }

        // Append any unlinked certificates if present
        ordered.addAll(remaining);
        return ordered;
    }
}
