package com.kanak.pki;

import com.kanak.pki.asn1.Oid;
import com.kanak.pki.model.KeyUsage;
import com.kanak.pki.model.X509Certificate;
import com.kanak.pki.path.CertPathValidator;
import com.kanak.pki.path.TrustStore;
import com.kanak.pki.path.ValidationContext;
import com.kanak.pki.path.ValidationResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class BenchmarkTest {

    @Test
    @DisplayName("Measure throughput of RFC 5280 path validation on pre-generated chains")
    void measurePathValidationThroughput() throws Exception {
        KeyPair rootKey = TestCertificateGenerator.generateRsaKeyPair();
        KeyPair intKey = TestCertificateGenerator.generateRsaKeyPair();
        KeyPair leafKey = TestCertificateGenerator.generateRsaKeyPair();

        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant notBefore = now.minus(10, ChronoUnit.DAYS);
        Instant notAfter = now.plus(30, ChronoUnit.DAYS);

        byte[] rootBc = TestCertificateGenerator.buildBasicConstraintsExtension(true, null, true);
        boolean[] kuBits = new boolean[9];
        kuBits[KeyUsage.KEY_CERT_SIGN] = true;
        byte[] ku = TestCertificateGenerator.buildKeyUsageExtension(kuBits, true);

        X509Certificate root = TestCertificateGenerator.issueCertificate(
                BigInteger.ONE, "Benchmark Root CA", "Benchmark Root CA",
                rootKey.getPublic(), rootKey.getPrivate(), Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore, notAfter, List.of(rootBc, ku)
        );

        byte[] intBc = TestCertificateGenerator.buildBasicConstraintsExtension(true, 1, true);
        X509Certificate intermediate = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(2), "Benchmark Intermediate CA", "Benchmark Root CA",
                intKey.getPublic(), rootKey.getPrivate(), Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore, notAfter, List.of(intBc, ku)
        );

        byte[] leafBc = TestCertificateGenerator.buildBasicConstraintsExtension(false, null, false);
        boolean[] leafKuBits = new boolean[9];
        leafKuBits[KeyUsage.DIGITAL_SIGNATURE] = true;
        byte[] leafKu = TestCertificateGenerator.buildKeyUsageExtension(leafKuBits, true);
        byte[] leafSan = TestCertificateGenerator.buildSanExtension(List.of("bench.example.com"), false);

        X509Certificate leaf = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(3), "bench.example.com", "Benchmark Intermediate CA",
                leafKey.getPublic(), intKey.getPrivate(), Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore, notAfter, List.of(leafBc, leafKu, leafSan)
        );

        TrustStore trustStore = TrustStore.of(root);
        CertPathValidator validator = new CertPathValidator(trustStore);
        ValidationContext ctx = ValidationContext.builder()
                .validationTime(now)
                .targetHostname("bench.example.com")
                .build();

        List<X509Certificate> chain = List.of(leaf, intermediate, root);

        // Warmup (100 iterations)
        for (int i = 0; i < 100; i++) {
            ValidationResult res = validator.validate(chain, ctx);
            assertThat(res.isValid()).isTrue();
        }

        // Timed benchmark: 2,000 iterations
        int iterations = 2000;
        long startNanos = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            ValidationResult res = validator.validate(chain, ctx);
            if (!res.isValid()) {
                throw new IllegalStateException("Validation unexpectedly failed in benchmark loop");
            }
        }
        long elapsedNanos = System.nanoTime() - startNanos;

        double totalSeconds = elapsedNanos / 1_000_000_000.0;
        double throughput = iterations / totalSeconds;
        double latencyUs = (elapsedNanos / (double) iterations) / 1000.0;

        System.out.println("=== PKI Validation Performance Benchmark ===");
        System.out.printf("Iterations:      %d chains%n", iterations);
        System.out.printf("Elapsed Time:    %.4f s%n", totalSeconds);
        System.out.printf("Throughput:      %.1f chains/sec%n", throughput);
        System.out.printf("Mean Latency:    %.2f us/chain (%.3f ms)%n", latencyUs, latencyUs / 1000.0);
        System.out.println("============================================");
    }
}
