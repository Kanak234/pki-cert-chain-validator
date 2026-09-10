# Product Requirements Document (PRD) — `pki-cert-chain-validator`

## 1. Product Overview
`pki-cert-chain-validator` is an independent, pure-Java RFC 5280 X.509 certification path validation engine and ASN.1 DER parser. It validates trust chains from an end-entity leaf certificate up to one or more trusted root anchors without relying on native C libraries (such as OpenSSL or Windows CryptoAPI) or opaque JVM keystore defaults.

---

## 2. Problem Statement
Many production Java systems defer TLS certificate validation to the default JVM `TrustManagerFactory` and `PKIXCertPathValidator`. While functional, standard implementations suffer from:
1. **Opaque Error Diagnostics:** When validation fails, exceptions are typically generic (e.g. `CertPathValidatorException: Path does not chain with any of the trust anchors`), omitting precise cryptographic root-causes (e.g. key usage mismatch, basic constraints path length violation, non-conformant DER encoding).
2. **Hidden Native Dependencies & Transitive Flaws:** External wrapper libraries introduce JNI/native bindings that complicate cross-platform deployment and introduce memory corruption attack surfaces.
3. **Inflexible Custom Policy Constraints:** Modern cloud zero-trust architectures, mutual TLS (mTLS), and enterprise PKIs require fine-grained path length assertions, strict NameConstraints validation, Subject Alternative Name (SAN) verification, and offline deterministic revocation checks.

`pki-cert-chain-validator` provides a zero-dependency, transparent, RFC 5280 conformant validation pipeline with full diagnostic traces and granular error categorization.

---

## 3. Goals & Non-Goals

### Goals
- **RFC 5280 Path Validation:** Fully implement §6.1 Certification Path Validation algorithm (signature verification, temporal validity, issuer/subject name chaining, basic constraints, key usage, extended key usage, subject alternative names).
- **Pure ASN.1 DER Parsing:** Autonomous binary decoder for Distinguished Encoding Rules (ITU-T X.690 §10), parsing Tag-Length-Value (TLV) structures, OIDs, and X.509 v3 structures from raw bytes.
- **Diagnostic Transparency:** Provide exact failure classification (`EXPIRED`, `NOT_YET_VALID`, `UNTRUSTED_ROOT`, `SIGNATURE_VERIFICATION_FAILED`, `BASIC_CONSTRAINTS_VIOLATION`, `PATH_LENGTH_EXCEEDED`, `KEY_USAGE_MISMATCH`, `EXTENDED_KEY_USAGE_MISMATCH`, `NAME_CONSTRAINT_VIOLATION`, `REVOKED`, `MALFORMED_DER`).
- **NIST PKITS & BadSSL Compatibility:** 100% pass rate across standardized path validation test vectors.
- **Dual Formats:** Seamless ingestion of PEM (Base64 ASCII with armor) and binary DER files.
- **Zero Third-Party Runtime Dependencies:** 100% pure Java (`java.base`), targeting Java 21+ LTS runtime compatibility.

### Non-Goals
- CA certificate authority issuance software (this engine validates existing chains; it does not issue or sign new certificates).
- Interactive GUI interface (CLI and programmatic Java library only).
- Non-standard proprietary certificate formats (e.g. legacy PGP or card certificates).

---

## 4. Target Users
- **Security Engineers & AppSec Teams:** Auditing internal PKIs, microservice mTLS certificates, and compliance with baseline requirements.
- **Backend & Platform Engineers:** Building custom API gateways, edge proxies, and secure microservice meshes requiring granular path validation rules.
- **DevOps & Infrastructure Administrators:** Debugging broken certificate chains, expired intermediate CAs, and mismatched SANs in CI/CD deployment pipelines.

---

## 5. Features & Functionality

### 5.1 ASN.1 DER Decoder
- Strict DER decoding conforming to ITU-T X.690:
  - Definite length form only (indefinite length prohibited in DER).
  - Short-form (1 byte for lengths $< 128$) and long-form (minimal octet count for lengths $\ge 128$).
  - Full primitive and constructed tag parsing: `SEQUENCE` (0x30), `SET` (0x31), `INTEGER` (0x02), `BIT_STRING` (0x03), `OCTET_STRING` (0x04), `NULL` (0x05), `OBJECT_IDENTIFIER` (0x06), `UTF8String` (0x0C), `PrintableString` (0x13), `IA5String` (0x16), `UTCTime` (0x17), `GeneralizedTime` (0x18), and context-specific tags (`[0]`, `[1]`, `[2]`, etc.).

### 5.2 X.509 v3 Certificate Model
- Complete unmarshaling of:
  - TBSCertificate (`tbsCertificate`): Version, Serial Number, Signature Algorithm Identifier, Issuer Distinguished Name, Validity (`notBefore`, `notAfter`), Subject Distinguished Name, SubjectPublicKeyInfo.
  - Standard v3 Extensions:
    - **BasicConstraints (OID 2.5.29.19):** `cA` boolean flag and optional `pathLenConstraint` integer.
    - **KeyUsage (OID 2.5.29.15):** 9 standard bit flags (`digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly`).
    - **ExtendedKeyUsage (OID 2.5.29.37):** `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `OCSPSigning`.
    - **SubjectAlternativeName (OID 2.5.29.17):** GeneralNames (`dNSName`, `iPAddress`, `rfc822Name`, `uniformResourceIdentifier`).
    - **AuthorityKeyIdentifier (OID 2.5.29.35) & SubjectKeyIdentifier (OID 2.5.29.14)**: Key matching.
    - **NameConstraints (OID 2.5.29.30)**: Permitted and excluded subtrees for DNS domain hierarchies.

### 5.3 RFC 5280 Path Validation Engine
- **Chain Construction & Ordering:** Accepts an unordered collection of certificates or an ordered leaf-to-root chain, resolving parent-child linkages via Issuer DN, AKI/SKI, and cryptographic signatures.
- **Trust Anchor Grounding:** Matches the root certificate against a configured Trust Store of pre-trusted Root CAs.
- **Temporal Validity:** Verifies current validation timestamp against every certificate's `[notBefore, notAfter]` interval.
- **Cryptographic Signature Verification:** Verifies RSA (SHA256withRSA, SHA384withRSA, SHA512withRSA) and ECDSA (SHA256withECDSA, SHA384withECDSA) signatures across every link in the path.
- **CA & Path Length Enforcement:** Enforces `isCA=true` on all intermediate certificates; enforces `keyCertSign` key usage bit; decrements and validates `pathLenConstraint` at each intermediate level.
- **Leaf Purpose Verification:** Confirms leaf certificate is not a CA (unless explicitly permitted) and possesses required usages (e.g. `digitalSignature`, `serverAuth`).
- **Critical Extension Processing:** Fails path validation if an unrecognized critical extension is encountered (RFC 5280 §4.2).

---

## 6. Acceptance Criteria
1. Strict compliance with ITU-T X.690 DER parsing rules with zero buffer overruns.
2. 100% pass rate on test suites covering:
   - Valid standard leaf $\to$ intermediate $\to$ root chain.
   - Expired leaf or intermediate certificates.
   - Not-yet-valid future certificates.
   - Tampered payload (signature verification failure).
   - Untrusted root anchor.
   - Intermediate CA lacking `isCA=true` or `keyCertSign`.
   - Path length constraint exceeded ($pathLen=0$ intermediate attempting to sign another intermediate).
   - Unknown critical extension.
   - SAN DNS matching and mismatching.
3. Standalone CLI tool accepting `--cert`, `--chain`, `--trust-store`, and `--target-host`.
4. Detailed, actionable JSON output reporting step-by-step path validation trace.
