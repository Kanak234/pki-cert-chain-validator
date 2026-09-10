# Implementation Plan — `pki-cert-chain-validator`

## Tasks & Milestones

- [x] **Phase 1: Project Setup & Maven Architecture**
  - [x] Configure `pom.xml` with Java 21, strict compiler flags, JUnit 5, and AssertJ.
  - [x] Configure `.gitignore`, `LICENSE` (MIT), `.env.example`.

- [x] **Phase 2: ASN.1 DER Parser Implementation**
  - [x] Implement `Asn1Tag.java` and `Oid.java` with standard PKIX OID definitions.
  - [x] Implement `Asn1Header.java` and `Asn1Node.java` representing the syntax tree.
  - [x] Implement `DerParser.java` with strict ITU-T X.690 length and definite-form validation.
  - [x] Implement unit tests for ASN.1 DER parser covering primitive, constructed, and malformed inputs.

- [x] **Phase 3: PEM Decoding & X.509 v3 Object Model**
  - [x] Implement `PemReader.java` parsing RFC 7468 blocks (`CERTIFICATE`, `TRUSTED CERTIFICATE`).
  - [x] Implement `X509Name.java`, `Validity.java`, `SubjectPublicKeyInfo.java`.
  - [x] Implement standard extensions: `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`, `GeneralName`, `GeneralNames`.
  - [x] Implement `X509Certificate.java` parsing the complete certificate structure from DER.
  - [x] Implement unit tests for certificate parsing.

- [x] **Phase 4: RFC 5280 Path Validation Engine**
  - [x] Implement `TrustStore.java` with preloaded and custom root anchor management.
  - [x] Implement `ValidationContext.java`, `ValidationStep.java`, `ValidationResult.java`, and `ValidationStatus.java`.
  - [x] Implement `CertPathValidator.java` with temporal checks, signature verification, chaining, path length constraints, key usage, and SAN matching.
  - [x] Implement synthetic test certificate generator for deterministic end-to-end testing of valid and anomalous conditions.

- [x] **Phase 5: CLI Application & Packaging**
  - [x] Implement `ValidatorCli.java` with CLI options, JSON output, and exit status codes.
  - [x] Implement multi-stage `Dockerfile` and `.dockerignore`.
  - [x] Implement `.github/workflows/ci.yml`.

- [x] **Phase 6: Verification, Documentation & Release**
  - [x] Execute complete test suite and measure execution benchmarks.
  - [x] Write `docs/EXPLAIN.md` covering all 6 mandatory sections.
  - [x] Write `README.md` with architecture diagram, measured benchmarks, and CLI examples.
  - [x] Write `CHANGELOG.md`.
  - [x] Commit cleanly with conventional commits, tag `v1.0.0`, and publish to GitHub.
