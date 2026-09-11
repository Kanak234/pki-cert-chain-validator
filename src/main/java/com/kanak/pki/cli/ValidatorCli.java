package com.kanak.pki.cli;

import com.kanak.pki.asn1.Oid;
import com.kanak.pki.model.X509Certificate;
import com.kanak.pki.path.CertPathValidator;
import com.kanak.pki.path.TrustStore;
import com.kanak.pki.path.ValidationContext;
import com.kanak.pki.path.ValidationResult;
import com.kanak.pki.pem.PemReader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line interface for the pure-Java RFC 5280 X.509 Certification Path Validator.
 */
public final class ValidatorCli {

    public static void main(String[] args) {
        if (args.length == 0 || hasOption(args, "-h", "--help")) {
            printHelp();
            return;
        }

        String certPath = getOption(args, "--cert");
        String chainPath = getOption(args, "--chain");
        String trustStorePath = getOption(args, "--trust-store");
        String host = getOption(args, "--host");
        String purpose = getOption(args, "--purpose");
        String timeStr = getOption(args, "--time");
        String maxPathStr = getOption(args, "--max-path-len");
        boolean allowSelfSigned = hasOption(args, "--allow-self-signed");
        boolean jsonOutput = hasOption(args, "--json", "-j");

        if (certPath == null) {
            System.err.println("Error: Missing required argument --cert <file>");
            System.exit(2);
        }

        try {
            List<X509Certificate> certList = new ArrayList<>();
            certList.addAll(loadCertificates(certPath));

            if (chainPath != null) {
                certList.addAll(loadCertificates(chainPath));
            }

            TrustStore trustStore = new TrustStore();
            if (trustStorePath != null) {
                trustStore.addAll(loadCertificates(trustStorePath));
            }

            ValidationContext.Builder ctxBuilder = ValidationContext.builder();
            if (host != null) ctxBuilder.targetHostname(host);
            if (purpose != null) {
                String oid = resolvePurposeOid(purpose);
                ctxBuilder.requireKeyPurpose(oid);
            }
            if (timeStr != null) ctxBuilder.validationTime(Instant.parse(timeStr));
            if (maxPathStr != null) ctxBuilder.maxPathLength(Integer.parseInt(maxPathStr));
            ctxBuilder.allowSelfSignedLeaf(allowSelfSigned);

            ValidationContext context = ctxBuilder.build();
            CertPathValidator validator = new CertPathValidator(trustStore);
            ValidationResult result = validator.validate(certList, context);

            if (jsonOutput) {
                System.out.println(result.toJson());
            } else {
                System.out.println(result.toPrettyString());
            }

            System.exit(result.isValid() ? 0 : 1);

        } catch (Exception e) {
            System.err.println("Execution Error: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(2);
        }
    }

    private static List<X509Certificate> loadCertificates(String pathStr) throws IOException {
        Path path = Paths.get(pathStr);
        byte[] rawBytes = Files.readAllBytes(path);
        String text = new String(rawBytes);

        if (text.contains("-----BEGIN ")) {
            List<byte[]> blocks = PemReader.readBlocks(text);
            return blocks.stream().map(X509Certificate::fromDer).toList();
        } else {
            return List.of(X509Certificate.fromDer(rawBytes));
        }
    }

    private static String resolvePurposeOid(String purpose) {
        return switch (purpose.toLowerCase()) {
            case "serverauth", "server_auth" -> Oid.EKU_SERVER_AUTH;
            case "clientauth", "client_auth" -> Oid.EKU_CLIENT_AUTH;
            case "codesigning", "code_signing" -> Oid.EKU_CODE_SIGNING;
            case "emailprotection", "email_protection" -> Oid.EKU_EMAIL_PROTECTION;
            default -> purpose;
        };
    }

    private static boolean hasOption(String[] args, String... flags) {
        for (String arg : args) {
            for (String flag : flags) {
                if (arg.equalsIgnoreCase(flag)) return true;
            }
        }
        return false;
    }

    private static String getOption(String[] args, String option) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equalsIgnoreCase(option)) {
                return args[i + 1];
            }
        }
        return null;
    }

    private static void printHelp() {
        System.out.println("""
            PKI Certificate Chain Validator (RFC 5280)
            Usage: java -jar pki-cert-chain-validator.jar [options]

            Required Options:
              --cert <file>           Path to leaf certificate (PEM or DER)

            Validation Options:
              --chain <file>          Path to intermediate CA bundle (PEM or DER)
              --trust-store <file>    Path to trusted root CA certificates (PEM or KeyStore)
              --host <hostname>       Expected target hostname (verifies against SAN / CN)
              --purpose <name|oid>    Required EKU purpose (e.g. serverAuth, clientAuth)
              --time <iso-timestamp>  Validation timestamp (ISO-8601, e.g. 2026-09-11T00:00:00Z)
              --max-path-len <n>      Maximum allowable chain depth (default: 10)
              --allow-self-signed     Accept self-signed leaf certificates without trust store
              -j, --json              Output results in structured JSON format
              -h, --help              Show this help message
            """);
    }
}
