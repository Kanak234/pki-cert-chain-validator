# Technical Requirements Document (TRD) — `pki-cert-chain-validator`

## 1. Technical Overview & Architecture

`pki-cert-chain-validator` is built as an independent, modular Java library and CLI tool. It does not use `javax.net.ssl` or standard `CertPathValidator` classes, ensuring complete visibility and deterministic enforcement of RFC 5280 rules.

```text
┌───────────────────────────────────────────────────────────┐
│                      Input Streams                        │
│                 (PEM Armored or Raw DER)                  │
└─────────────────────────────┬─────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────┐
│              PEM Reader (Base64 Decoding)                 │
└─────────────────────────────┬─────────────────────────────┘
                              │ DER Byte Arrays
                              ▼
┌───────────────────────────────────────────────────────────┐
│                   ASN.1 DER Parser                        │
│           (Strict ITU-T X.690 §10 TLV Decoder)            │
└─────────────────────────────┬─────────────────────────────┘
                              │ ASN.1 Syntax Tree
                              ▼
┌───────────────────────────────────────────────────────────┐
│                 X.509 v3 Object Model                     │
│    (TBSCertificate, Extensions, SubjectPublicKeyInfo)     │
└─────────────────────────────┬─────────────────────────────┘
                              │ Parsed Certificate Chain
                              ▼
┌───────────────────────────────────────────────────────────┐
│           RFC 5280 Path Validation Engine                 │
│  - Chaining & Trust Anchor Match                          │
│  - Validity Temporal Boundaries                           │
│  - Cryptographic Signature Verification                   │
│  - BasicConstraints & PathLen Enforcement                 │
│  - KeyUsage & ExtendedKeyUsage Verification               │
│  - Critical Extension Processing                          │
│  - SAN / Hostname Matching                                │
└─────────────────────────────┬─────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────┐
│              ValidationResult & Trace Log                 │
│               (Structured JSON / Human)                   │
└───────────────────────────────────────────────────────────┘
```

---

## 2. Technology Stack & Environment

- **Language:** Java (JDK 21 LTS baseline, compatible with OpenJDK 21 to 25+).
- **Build System:** Apache Maven 3.9+ with `pom.xml`.
- **Runtime Dependencies:** 0 external runtime dependencies (100% pure Java `java.base`).
- **Test Dependencies:**
  - `org.junit.jupiter:junit-jupiter:5.10.2`
  - `org.assertj:assertj-core:3.25.3`
- **Compiler Configuration:** Java release level `21` (`<maven.compiler.release>21</maven.compiler.release>`), with `-Xlint:all` and `-Werror`.

---

## 3. Package & Module Design

```text
com.kanak.pki
├── asn1
│   ├── Asn1Tag.java           # Universal, Constructed, and Context-Specific tag constants
│   ├── Asn1Header.java        # Tag, constructed bit, class, and parsed length
│   ├── Asn1Node.java          # In-memory ASN.1 syntax node with recursive child access
│   ├── DerParser.java         # Strict, non-lenient ITU-T X.690 DER decoder
│   └── Oid.java               # Object Identifier representation and dotted-decimal formatting
├── model
│   ├── X509Certificate.java   # Complete immutable representation of an X.509 v3 certificate
│   ├── X509Name.java          # Distinguished Name (DN) parser (CN, O, OU, C, ST, L, etc.)
│   ├── Validity.java          # notBefore and notAfter temporal validity interval
│   ├── SubjectPublicKeyInfo.java # Public key algorithm OID, parameters, and key bytes
│   ├── Extensions.java        # Registry of parsed and unparsed X.509 v3 extensions
│   ├── BasicConstraints.java  # isCA flag and pathLenConstraint integer
│   ├── KeyUsage.java          # 9 RFC 5280 key usage flags
│   ├── ExtendedKeyUsage.java  # Standard key purpose OIDs (serverAuth, clientAuth, etc.)
│   ├── GeneralName.java       # GeneralName union (DNS, IP, Email, URI)
│   └── GeneralNames.java      # Collection of GeneralNames for SAN / NameConstraints
├── path
│   ├── CertPathValidator.java # Core RFC 5280 path validation state machine
│   ├── ValidationContext.java # Configuration parameters (validation time, target hostname, required usages)
│   ├── ValidationResult.java  # Comprehensive validation outcome with diagnostic steps
│   ├── ValidationStatus.java  # Success/failure status codes
│   ├── TrustStore.java        # In-memory repository of trusted Root CA certificates
│   └── ValidationStep.java    # Individual step audit log record
├── pem
│   └── PemReader.java         # RFC 7468 PEM file decoder and block extractor
└── cli
    └── ValidatorCli.java      # Command-line interface with JSON and human-readable output
```

---

## 4. ASN.1 DER Parser Specifications

### 4.1 Strict ITU-T X.690 Conformance
1. **Definite Length:** Indefinite length encodings (`0x80 ... 0x00 0x00`) are rejected as non-conformant DER.
2. **Minimal Length Octets:** Short form must be used for lengths $0 \le L \le 127$. For long form ($L \ge 128$), the length octets must use the minimum number of bytes without leading zeros.
3. **Boolean Encoding:** Booleans must be encoded as `0x00` (false) or `0xFF` (true). Any other value is rejected.
4. **Integer Encodings:** Integers must be encoded in two's complement form using minimum octets (no unnecessary leading `0x00` or `0xFF` bytes).
5. **Bit Strings:** Unused bits indicator ($0 \le B \le 7$) must be valid; trailing unused bits in the final byte must be zero.

---

## 5. RFC 5280 Path Validation Algorithm

### 5.1 Verification Checklist for Certificate $C_i$ (from Leaf $C_0$ to Root $C_n$):
1. **Signature Verification:** $C_i$'s signature must be verified using the public key from issuer certificate $C_{i+1}$.
2. **Temporal Window:** $\text{ValidationTime} \in [C_i.\text{notBefore}, C_i.\text{notAfter}]$.
3. **Chaining Link:** $C_i.\text{issuerDN} = C_{i+1}.\text{subjectDN}$.
4. **Authority/Subject Key Identifier Matching:** If present, $C_i.\text{AKI} = C_{i+1}.\text{SKI}$.
5. **BasicConstraints on Intermediate ($i > 0$):**
   - Must be present and marked critical (or processed).
   - `isCA` must be `true`.
   - `pathLenConstraint` must be $\ge (i - 1)$.
6. **KeyUsage on Intermediate ($i > 0$):**
   - If KeyUsage extension is present, `keyCertSign` bit must be set.
7. **Critical Extension Processing:**
   - If $C_i$ contains any critical extension not recognized by the validator, path validation fails immediately.
8. **Trust Anchor Termination:**
   - The root certificate $C_n$ must match a certificate present in the configured `TrustStore` (by exact byte comparison or Subject DN + Public Key).
9. **Target Hostname / SAN Verification (Leaf $C_0$):**
   - If a target hostname is specified, it must match either the `dNSName` entries in the SAN extension or, if SAN is absent, the Common Name (CN) in Subject DN. Supports standard wildcard syntax (`*.example.com`).

---

## 6. Security & Performance Constraints

- **Memory Safety:** Parser prevents deep recursion overflow attacks by capping ASN.1 nesting depth at 32 levels.
- **Maximum Buffer Size:** Rejects certificate inputs exceeding 1 MB to prevent Denial-of-Service via memory exhaustion.
- **Constant Cache Overhead:** No dynamic class loading or reflection during parsing.
- **Thread Safety:** All parsed `X509Certificate`, `Asn1Node`, and `ValidationResult` instances are strictly immutable.
