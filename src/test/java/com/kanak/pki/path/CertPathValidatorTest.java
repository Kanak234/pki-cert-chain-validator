package com.kanak.pki.path;

import com.kanak.pki.TestCertificateGenerator;
import com.kanak.pki.asn1.Oid;
import com.kanak.pki.model.KeyUsage;
import com.kanak.pki.model.X509Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CertPathValidatorTest {

    private KeyPair rootKey;
    private KeyPair intermediateKey;
    private KeyPair leafKey;

    private Instant baseTime;
    private Instant notBefore;
    private Instant notAfter;

    private X509Certificate rootCert;
    private X509Certificate intermediateCert;
    private X509Certificate leafCert;

    private TrustStore trustStore;
    private CertPathValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        rootKey = TestCertificateGenerator.generateRsaKeyPair();
        intermediateKey = TestCertificateGenerator.generateRsaKeyPair();
        leafKey = TestCertificateGenerator.generateRsaKeyPair();

        baseTime = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        notBefore = baseTime.minus(10, ChronoUnit.DAYS);
        notAfter = baseTime.plus(30, ChronoUnit.DAYS);

        // 1. Root CA (Self-signed, CA=true)
        byte[] rootBc = TestCertificateGenerator.buildBasicConstraintsExtension(true, null, true);
        boolean[] rootKuBits = new boolean[9];
        rootKuBits[KeyUsage.KEY_CERT_SIGN] = true;
        rootKuBits[KeyUsage.CRL_SIGN] = true;
        byte[] rootKu = TestCertificateGenerator.buildKeyUsageExtension(rootKuBits, true);

        rootCert = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(1),
                "Acme Root CA",
                "Acme Root CA",
                rootKey.getPublic(),
                rootKey.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore,
                notAfter,
                List.of(rootBc, rootKu)
        );

        // 2. Intermediate CA (Signed by Root, CA=true, pathLen=1)
        byte[] intBc = TestCertificateGenerator.buildBasicConstraintsExtension(true, 1, true);
        boolean[] intKuBits = new boolean[9];
        intKuBits[KeyUsage.KEY_CERT_SIGN] = true;
        intKuBits[KeyUsage.CRL_SIGN] = true;
        byte[] intKu = TestCertificateGenerator.buildKeyUsageExtension(intKuBits, true);

        intermediateCert = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(2),
                "Acme Intermediate CA",
                "Acme Root CA",
                intermediateKey.getPublic(),
                rootKey.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore,
                notAfter,
                List.of(intBc, intKu)
        );

        // 3. Leaf Certificate (Signed by Intermediate, CA=false, digitalSignature, serverAuth, SAN)
        byte[] leafBc = TestCertificateGenerator.buildBasicConstraintsExtension(false, null, false);
        boolean[] leafKuBits = new boolean[9];
        leafKuBits[KeyUsage.DIGITAL_SIGNATURE] = true;
        leafKuBits[KeyUsage.KEY_ENCIPHERMENT] = true;
        byte[] leafKu = TestCertificateGenerator.buildKeyUsageExtension(leafKuBits, true);
        byte[] leafEku = TestCertificateGenerator.buildEkuExtension(List.of(Oid.EKU_SERVER_AUTH), false);
        byte[] leafSan = TestCertificateGenerator.buildSanExtension(List.of("api.example.com", "*.internal.net"), false);

        leafCert = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(3),
                "api.example.com",
                "Acme Intermediate CA",
                leafKey.getPublic(),
                intermediateKey.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore,
                notAfter,
                List.of(leafBc, leafKu, leafEku, leafSan)
        );

        trustStore = TrustStore.of(rootCert);
        validator = new CertPathValidator(trustStore);
    }

    @Test
    @DisplayName("Should validate valid 3-tier certificate chain successfully")
    void testValidPath() {
        ValidationContext ctx = ValidationContext.builder()
                .validationTime(baseTime)
                .targetHostname("api.example.com")
                .requireKeyPurpose(Oid.EKU_SERVER_AUTH)
                .build();

        ValidationResult result = validator.validate(List.of(leafCert, intermediateCert, rootCert), ctx);
        assertThat(result.isValid()).isTrue();
        assertThat(result.getStatus()).isEqualTo(ValidationStatus.VALID);
    }

    @Test
    @DisplayName("Should validate wildcard SAN hostname matching")
    void testWildcardHostnameMatching() {
        ValidationContext ctx = ValidationContext.builder()
                .validationTime(baseTime)
                .targetHostname("node1.internal.net")
                .build();

        ValidationResult result = validator.validate(List.of(leafCert, intermediateCert, rootCert), ctx);
        assertThat(result.isValid()).isTrue();
        assertThat(result.getStatus()).isEqualTo(ValidationStatus.VALID);
    }

    @Test
    @DisplayName("Should fail with HOSTNAME_MISMATCH when hostname does not match SAN")
    void testHostnameMismatch() {
        ValidationContext ctx = ValidationContext.builder()
                .validationTime(baseTime)
                .targetHostname("evil.attacker.com")
                .build();

        ValidationResult result = validator.validate(List.of(leafCert, intermediateCert, rootCert), ctx);
        assertThat(result.isValid()).isFalse();
        assertThat(result.getStatus()).isEqualTo(ValidationStatus.HOSTNAME_MISMATCH);
    }

    @Test
    @DisplayName("Should fail with UNTRUSTED_ROOT when root CA is missing from trust store")
    void testUntrustedRoot() {
        TrustStore emptyStore = TrustStore.createEmpty();
        CertPathValidator unanchoredValidator = new CertPathValidator(emptyStore);

        ValidationContext ctx = ValidationContext.builder()
                .validationTime(baseTime)
                .build();

        ValidationResult result = unanchoredValidator.validate(List.of(leafCert, intermediateCert, rootCert), ctx);
        assertThat(result.isValid()).isFalse();
        assertThat(result.getStatus()).isEqualTo(ValidationStatus.UNTRUSTED_ROOT);
    }

    @Test
    @DisplayName("Should fail with EXPIRED when validation time is after notAfter")
    void testExpiredCertificate() {
        Instant expiredTime = notAfter.plus(5, ChronoUnit.DAYS);
        ValidationContext ctx = ValidationContext.builder()
                .validationTime(expiredTime)
                .build();

        ValidationResult result = validator.validate(List.of(leafCert, intermediateCert, rootCert), ctx);
        assertThat(result.isValid()).isFalse();
        assertThat(result.getStatus()).isEqualTo(ValidationStatus.EXPIRED);
    }

    @Test
    @DisplayName("Should fail with NOT_YET_VALID when validation time is before notBefore")
    void testNotYetValidCertificate() {
        Instant futureTime = notBefore.minus(5, ChronoUnit.DAYS);
        ValidationContext ctx = ValidationContext.builder()
                .validationTime(futureTime)
                .build();

        ValidationResult result = validator.validate(List.of(leafCert, intermediateCert, rootCert), ctx);
        assertThat(result.isValid()).isFalse();
        assertThat(result.getStatus()).isEqualTo(ValidationStatus.NOT_YET_VALID);
    }

    @Test
    @DisplayName("Should fail with SIGNATURE_VERIFICATION_FAILED when signature was created with wrong key")
    void testTamperedSignature() throws Exception {
        KeyPair rogueKey = TestCertificateGenerator.generateRsaKeyPair();

        // Intermediate signed by rogue key instead of root key
        X509Certificate tamperedIntermediate = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(2),
                "Acme Intermediate CA",
                "Acme Root CA",
                intermediateKey.getPublic(),
                rogueKey.getPrivate(), // Invalid signer
                Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore,
                notAfter,
                List.of(TestCertificateGenerator.buildBasicConstraintsExtension(true, 1, true))
        );

        ValidationContext ctx = ValidationContext.builder().validationTime(baseTime).build();
        ValidationResult result = validator.validate(List.of(leafCert, tamperedIntermediate, rootCert), ctx);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getStatus()).isEqualTo(ValidationStatus.SIGNATURE_VERIFICATION_FAILED);
    }

    @Test
    @DisplayName("Should fail with BASIC_CONSTRAINTS_VIOLATION when intermediate is not a CA")
    void testIntermediateNotCa() throws Exception {
        byte[] notCaBc = TestCertificateGenerator.buildBasicConstraintsExtension(false, null, true);
        boolean[] intKuBits = new boolean[9];
        intKuBits[KeyUsage.KEY_CERT_SIGN] = true;
        byte[] intKu = TestCertificateGenerator.buildKeyUsageExtension(intKuBits, true);

        X509Certificate badIntermediate = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(2),
                "Acme Intermediate CA",
                "Acme Root CA",
                intermediateKey.getPublic(),
                rootKey.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore,
                notAfter,
                List.of(notCaBc, intKu)
        );

        ValidationContext ctx = ValidationContext.builder().validationTime(baseTime).build();
        ValidationResult result = validator.validate(List.of(leafCert, badIntermediate, rootCert), ctx);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getStatus()).isEqualTo(ValidationStatus.BASIC_CONSTRAINTS_VIOLATION);
    }

    @Test
    @DisplayName("Should fail with PATH_LENGTH_EXCEEDED when intermediate pathLenConstraint is violated")
    void testPathLengthExceeded() throws Exception {
        // Intermediate 1 has pathLen = 0 (can sign leaf, but cannot sign another intermediate)
        byte[] intBc0 = TestCertificateGenerator.buildBasicConstraintsExtension(true, 0, true);
        boolean[] kuBits = new boolean[9];
        kuBits[KeyUsage.KEY_CERT_SIGN] = true;
        byte[] ku = TestCertificateGenerator.buildKeyUsageExtension(kuBits, true);

        X509Certificate int1 = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(20),
                "Acme Intermediate 1",
                "Acme Root CA",
                intermediateKey.getPublic(),
                rootKey.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore,
                notAfter,
                List.of(intBc0, ku)
        );

        KeyPair subIntKey = TestCertificateGenerator.generateRsaKeyPair();
        X509Certificate subInt = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(21),
                "Acme Sub-Intermediate",
                "Acme Intermediate 1",
                subIntKey.getPublic(),
                intermediateKey.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore,
                notAfter,
                List.of(TestCertificateGenerator.buildBasicConstraintsExtension(true, null, true), ku)
        );

        X509Certificate deepLeaf = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(22),
                "sub.example.com",
                "Acme Sub-Intermediate",
                leafKey.getPublic(),
                subIntKey.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore,
                notAfter,
                List.of(TestCertificateGenerator.buildBasicConstraintsExtension(false, null, false))
        );

        ValidationContext ctx = ValidationContext.builder().validationTime(baseTime).build();
        ValidationResult result = validator.validate(List.of(deepLeaf, subInt, int1, rootCert), ctx);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getStatus()).isEqualTo(ValidationStatus.PATH_LENGTH_EXCEEDED);
    }

    @Test
    @DisplayName("Should fail with CRITICAL_EXTENSION_UNHANDLED when unrecognized critical extension is present")
    void testUnrecognizedCriticalExtension() throws Exception {
        byte[] unknownCritExt = TestCertificateGenerator.buildCustomCriticalExtension("1.2.3.4.5.6.7.8.9", new byte[]{0x05, 0x00});

        X509Certificate certWithUnknownCrit = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(99),
                "crit.example.com",
                "Acme Intermediate CA",
                leafKey.getPublic(),
                intermediateKey.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore,
                notAfter,
                List.of(unknownCritExt)
        );

        ValidationContext ctx = ValidationContext.builder().validationTime(baseTime).build();
        ValidationResult result = validator.validate(List.of(certWithUnknownCrit, intermediateCert, rootCert), ctx);

        assertThat(result.isValid()).isFalse();
        assertThat(result.getStatus()).isEqualTo(ValidationStatus.CRITICAL_EXTENSION_UNHANDLED);
    }

    @Test
    @DisplayName("Should handle unordered certificate lists correctly via automatic chain ordering")
    void testUnorderedChainOrdering() {
        ValidationContext ctx = ValidationContext.builder().validationTime(baseTime).build();

        // Pass in reverse order: Root -> Intermediate -> Leaf
        ValidationResult result1 = validator.validate(List.of(rootCert, intermediateCert, leafCert), ctx);
        assertThat(result1.isValid()).isTrue();

        // Pass in random order: Intermediate -> Leaf -> Root
        ValidationResult result2 = validator.validate(List.of(intermediateCert, leafCert, rootCert), ctx);
        assertThat(result2.isValid()).isTrue();
    }
}
