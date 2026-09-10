package com.kanak.pki.model;

import com.kanak.pki.TestCertificateGenerator;
import com.kanak.pki.asn1.Oid;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateParserTest {

    @Test
    @DisplayName("Should parse and verify self-signed X.509 v3 RSA certificate")
    void testSelfSignedCertificateParsing() throws Exception {
        KeyPair kp = TestCertificateGenerator.generateRsaKeyPair();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant notBefore = now.minus(1, ChronoUnit.DAYS);
        Instant notAfter = now.plus(365, ChronoUnit.DAYS);

        byte[] bcExt = TestCertificateGenerator.buildBasicConstraintsExtension(true, null, true);
        boolean[] keyUsageBits = new boolean[9];
        keyUsageBits[KeyUsage.KEY_CERT_SIGN] = true;
        keyUsageBits[KeyUsage.CRL_SIGN] = true;
        byte[] kuExt = TestCertificateGenerator.buildKeyUsageExtension(keyUsageBits, true);

        X509Certificate cert = TestCertificateGenerator.issueCertificate(
                BigInteger.valueOf(1001),
                "Root CA",
                "Root CA",
                kp.getPublic(),
                kp.getPrivate(),
                Oid.SHA256_WITH_RSA_ENCRYPTION,
                notBefore,
                notAfter,
                List.of(bcExt, kuExt)
        );

        assertThat(cert.getVersion()).isEqualTo(3);
        assertThat(cert.getSerialNumber()).isEqualTo(BigInteger.valueOf(1001));
        assertThat(cert.getSubject().getCommonName()).contains("Root CA");
        assertThat(cert.getIssuer().getCommonName()).contains("Root CA");
        assertThat(cert.isSelfIssued()).isTrue();
        assertThat(cert.isSelfSigned()).isTrue();
        assertThat(cert.verifySignature(kp.getPublic())).isTrue();

        assertThat(cert.getExtensions().getBasicConstraints()).isPresent();
        assertThat(cert.getExtensions().getBasicConstraints().get().isCa()).isTrue();

        assertThat(cert.getExtensions().getKeyUsage()).isPresent();
        assertThat(cert.getExtensions().getKeyUsage().get().isKeyCertSign()).isTrue();
        assertThat(cert.getExtensions().getKeyUsage().get().isCrlSign()).isTrue();
        assertThat(cert.getExtensions().getKeyUsage().get().isDigitalSignature()).isFalse();
    }
}
