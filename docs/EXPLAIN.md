# Technical Architecture & Engineering Deep-Dive: PKI Certificate Chain Validator

An independent, pure-Java RFC 5280 X.509 certification path validation engine and strict ITU-T X.690 ASN.1 DER parser built with zero third-party runtime dependencies.

---

## 1. High-School / ELI5 Explanation (5 Lines)

1. When you connect to a secure website like your bank, the server presents a digital passport called an SSL/TLS certificate.
2. Because anyone could forge a certificate, the website's certificate must be digitally signed by an intermediate Authority, which is in turn signed by a trusted Root Certificate Authority pre-installed on your computer.
3. This software is an independent, pure-Java digital detective that inspects this entire "chain of trust" link by link without relying on opaque operating system defaults.
4. It reads the raw binary code (ASN.1 DER) of each certificate, checks that mathematical signatures are authentic, verifies that dates have not expired, and ensures intermediate authorities are actually authorized to sign other certificates.
5. If a single rule is violated—such as a forged signature, an expired date, or an unauthorized intermediate—the engine immediately halts, isolates the exact issue, and outputs a clear diagnostic report.

---

## 2. Module-by-Module Walkthrough

### 2.1 ASN.1 DER Parsing Engine (`com.kanak.pki.asn1`)
ASN.1 (Abstract Syntax Notation One) with Distinguished Encoding Rules (DER, ITU-T X.690 §10) is the foundational binary representation of all X.509 digital certificates.
- **`Asn1Tag`:** Defines tag classes (Universal, Application, Context-Specific, Private) and universal type tags (`BOOLEAN`, `INTEGER`, `BIT_STRING`, `OCTET_STRING`, `NULL`, `OBJECT_IDENTIFIER`, `UTF8String`, `PrintableString`, `UTCTime`, `GeneralizedTime`, `SEQUENCE`, `SET`).
- **`Oid`:** Represents Object Identifiers. Implements ITU-T X.690 §8.19 base-128 variable-length 7-bit septet encoding/decoding, translating binary byte streams into dotted decimal notation (e.g. `2.5.4.3` for Common Name, `2.5.29.19` for BasicConstraints).
- **`Asn1Header`:** Parses the tag octets and length octets. Enforces strict DER rules:
  - Indefinite length (`0x80`) is strictly forbidden.
  - Short form must be used for lengths $0 \le L \le 127$.
  - Long form must use minimal octets (no leading `0x00`).
- **`Asn1Node`:** Immutable in-memory representation of an ASN.1 syntax node. Maintains raw encoded bytes, slice content bytes, and child nodes. Exposes typed accessor methods (`asBoolean()`, `asBigInteger()`, `asOid()`, `asString()`, `asBitStringData()`, `asInstant()`).
- **`DerParser`:** Strict, non-lenient recursive descent parser. Limits maximum recursion depth to 32 to prevent stack overflow attacks and caps total input buffer size at 1 MB.
- **`DerWriter`:** Clean serialization utility generating compliant DER encodings, used for testing and synthetic certificate generation.

### 2.2 PEM Armoring Reader (`com.kanak.pki.pem`)
- **`PemReader`:** Decodes RFC 7468 ASCII armor blocks (`-----BEGIN CERTIFICATE-----` ... `-----END CERTIFICATE-----`). Extracts Base64-encoded strings, strips whitespace and comments, and returns binary DER byte arrays.

### 2.3 X.509 v3 Domain Model (`com.kanak.pki.model`)
- **`X509Name`:** Parses RDNSequence (Relative Distinguished Names). Extracts common attributes (CN, O, OU, C, ST, L) and formats standard RFC 4514 canonical strings. Provides case-insensitive equality per RFC 5280.
- **`Validity`:** Encapsulates `notBefore` and `notAfter` timestamps as `java.time.Instant`. Handles UTCTime (YYMMDDHHMMSSZ with 50-year century pivot) and GeneralizedTime (YYYYMMDDHHMMSSZ). Evaluates whether a given instant falls within the valid range.
- **`SubjectPublicKeyInfo`:** Parses algorithm OID and raw public key bits. Integrates with standard Java Cryptography Architecture (`KeyFactory`) to generate immutable `java.security.PublicKey` instances (RSA and EC).
- **`BasicConstraints`:** Parses RFC 5280 §4.2.1.9 extension, extracting `isCA` boolean and optional `pathLenConstraint`.
- **`KeyUsage`:** Decodes 9 standard RFC 5280 §4.2.1.3 bit flags (`digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly`).
- **`ExtendedKeyUsage`:** Parses RFC 5280 §4.2.1.12 purpose OIDs (`serverAuth`, `clientAuth`, `codeSigning`, etc.).
- **`GeneralName` & `GeneralNames`:** Parses Subject Alternative Name (SAN) structures (`dNSName`, `iPAddress`, `rfc822Name`, `uniformResourceIdentifier`). Implements RFC 6125 wildcard matching (`*.example.com`).
- **`Extensions`:** Registry of all certificate extensions. Distinguishes critical extensions and provides lazy-loaded typed accessors.
- **`X509Certificate`:** Immutable top-level certificate model. Stores full raw DER, isolated `tbsCertificate` byte slice, serial number, signature algorithm OID, signature bytes, and provides `verifySignature(PublicKey issuerPublicKey)` using Java `Signature`.

### 2.4 RFC 5280 Path Validation Engine (`com.kanak.pki.path`)
- **`TrustStore`:** In-memory repository of trusted Root CA certificates. Supports exact DER byte matching or Subject DN + Public Key equality.
- **`ValidationContext`:** Immutable configuration container specifying validation timestamp, target hostname, required EKU purposes, maximum allowable path length, and self-signed leaf overrides.
- **`ValidationStatus`:** Comprehensive failure and success classification enum.
- **`ValidationStep`:** Detailed record capturing each step executed in the verification pipeline.
- **`ValidationResult`:** Full evaluation result providing `isValid()`, status code, formatted text summary, and structured JSON output.
- **`CertPathValidator`:** Core state machine implementing the RFC 5280 §6.1 certification path validation algorithm.

### 2.5 Command-Line Interface (`com.kanak.pki.cli`)
- **`ValidatorCli`:** Production CLI supporting `--cert`, `--chain`, `--trust-store`, `--host`, `--purpose`, `--time`, `--max-path-len`, `--json`, and returning standard exit codes (0 for valid, 1 for invalid, 2 for syntax/IO errors).

---

## 3. Key Technical Decisions & Trade-Offs

| Decision | Chosen Approach | Alternative Considered | Engineering Rationale |
| :--- | :--- | :--- | :--- |
| **Zero Runtime Dependencies** | 100% pure Java (`java.base`) | BouncyCastle / Jackson / Commons-IO | Completely eliminates transitive dependency vulnerabilities, licensing conflicts, and supply-chain attack vectors. |
| **Signature Verification Slice** | Isolate original `tbsCertificate` DER slice during parsing | Re-encode AST back to DER before verification | Re-encoding can introduce subtle canonicalization discrepancies (e.g. integer padding, set ordering) that invalidate cryptographic signatures. Preserving the exact wire bytes guarantees cryptographic integrity. |
| **ASN.1 Parser Rigor** | Strict DER enforcement (indefinite lengths and non-minimal octets rejected) | Lenient BER / CER parser | Standard PKI guidelines (RFC 5280 §4.1) mandate strict DER. Lenient parsers are vulnerable to signature malleability and certificate substitution attacks. |
| **Path Organization** | Automatic topological chain sorter | Enforce strict user-specified order | In real TLS handshakes, servers frequently transmit intermediate certificates out of order or include extraneous trust anchors. Automatic sorting guarantees robustness. |
| **Diagnostic Model** | Complete audit trail log with granular failure enums | Fail-fast generic exception throwing | Enables security auditors and DevOps engineers to inspect exactly which certificate, extension, or signature failed and why. |

---

## 4. The Hardest Engineering Challenge: DER TBSCertificate Byte Isolation

### Problem Statement
In X.509 certificate verification, the issuer CA signs the `tbsCertificate` (To-Be-Signed Certificate) structure:
$$\text{Signature} = \text{Sign}_{K_{\text{issuer}}^{-1}}\left( \text{SHA256}(\text{DER}(\text{TBSCertificate})) \right)$$
When validating the signature, the verifier computes:
$$\text{Verify}_{K_{\text{issuer}}}\left( \text{SHA256}(\text{DER}(\text{TBSCertificate})), \text{SignatureValue} \right)$$
If a parser deserializes `TBSCertificate` into object fields (version, serialNumber, issuer, subject, validity, spki, extensions) and later re-serializes those fields into bytes to pass to `Signature.update()`, signature verification will almost certainly fail:
1. **Integer Encoding Nuances:** Large serial numbers or version fields might have optional leading zeros in non-strict encoders.
2. **SET OF Ordering:** Distinguished Name attributes in RDNSequence are sets; DER requires lexicographical sorting by tag and octet value. Any difference in set ordering changes the SHA-256 hash.
3. **Default Value Omission:** In ASN.1 DER, default values (such as `version v1 (0)` or `critical BOOLEAN FALSE`) must be omitted. If an encoder includes them, the hash changes.

### Step-by-Step Resolution
1. **Preserve Wire Slices:** During the initial parsing pass in `DerParser`, when `Asn1Header.read()` encounters the `TBSCertificate` sequence (the first child of the outer `Certificate` sequence), we record the exact starting offset and total length ($start \dots start + totalLength$).
2. **Extract Wire Array:** We copy this slice directly into `X509Certificate.tbsDer`.
3. **Cryptographic Feed:** When `X509Certificate.verifySignature()` is invoked:
   ```java
   Signature sig = Signature.getInstance(jcaAlg);
   sig.initVerify(issuerPublicKey);
   sig.update(tbsDer); // Exact original wire bytes!
   return sig.verify(signatureValue);
   ```
4. This guarantees zero byte drift and 100% mathematical fidelity across all standard RSA and ECDSA signatures.

---

## 5. 15 Technical Interview Questions & Answers

#### Q1: What is the fundamental difference between ASN.1 BER and DER?
**Answer:** BER (Basic Encoding Rules) allows multiple equivalent representations for the same data (e.g. indefinite lengths using `0x80 ... 0x00 0x00`, primitive or constructed string encodings, arbitrary set ordering). DER (Distinguished Encoding Rules) is a strict subset of BER that enforces a unique, canonical binary encoding for any data structure. This canonicity is essential for digital signatures, ensuring that the signer and verifier hash the exact same byte stream.

#### Q2: What is the significance of the `pathLenConstraint` field in the BasicConstraints extension?
**Answer:** `pathLenConstraint` specifies the maximum number of non-self-issued intermediate CA certificates that may follow this certificate in a valid certification path. For example, if an intermediate CA has `pathLenConstraint = 0`, it can only issue end-entity (leaf) certificates and cannot issue subordinate intermediate CAs.

#### Q3: Why does RFC 5280 mandate rejecting certificates with unrecognized critical extensions?
**Answer:** A critical extension indicates that the certificate issuer created a condition or constraint that fundamentally affects the validity or interpretation of the certificate (e.g. specialized key usage restrictions, policy constraints, or biometric bindings). If a relying party cannot process a critical rule, accepting the certificate risks authorizing an invalid or insecure operation.

#### Q4: What is the difference between KeyUsage and ExtendedKeyUsage?
**Answer:** `KeyUsage` defines low-level cryptographic operations permitted for the public key (e.g. `digitalSignature`, `keyEncipherment`, `keyCertSign`, `cRLSign`). `ExtendedKeyUsage` (EKU) defines higher-level application purposes for which the certificate may be used, specified via OIDs (e.g. `serverAuth` for TLS web servers, `clientAuth` for mTLS, `codeSigning` for executable verification).

#### Q5: How does this validator prevent Denial-of-Service via deeply nested ASN.1 structures?
**Answer:** The `DerParser` enforces a hard recursion limit (`MAX_RECURSION_DEPTH = 32`) and an overall input size cap (`MAX_BUFFER_SIZE = 1 MB`). Any attempt to feed maliciously crafted recursive sequences triggers an immediate `IllegalStateException` without exhausting JVM thread stack space.

#### Q6: How does the validator handle the century ambiguity in ASN.1 UTCTime?
**Answer:** RFC 5280 §4.1.2.5.1 specifies a 50-year sliding window: if the two-digit year $YY \ge 50$, the year is interpreted as $19YY$; if $YY < 50$, it is interpreted as $20YY$. GeneralizedTime uses four-digit years ($YYYY$) and is mandatory for dates in year 2050 or later.

#### Q7: Why must an intermediate CA assert `keyCertSign` in its KeyUsage extension?
**Answer:** An intermediate CA's primary role is issuing certificates. RFC 5280 §4.2.1.3 specifies that if the KeyUsage extension is present on a CA certificate, the `keyCertSign` bit must be asserted to authorize signing public key certificates. If missing, the certificate cannot legally vouch for child certificates.

#### Q8: What are Subject Alternative Names (SANs) and why are they preferred over the Common Name (CN)?
**Answer:** The Common Name (CN) is a legacy X.500 attribute limited to a single text string. SAN (RFC 5280 §4.2.1.6) supports multiple typed identities (DNS names, IPv4/IPv6 addresses, URIs, email addresses) and enables multi-domain and wildcard certificates. Modern TLS standards (RFC 6125 and CA/Browser Forum Baseline Requirements) require relying parties to match against SAN DNS names and ignore CN when SAN is present.

#### Q9: What is NameConstraints (OID 2.5.29.30) and when is it used?
**Answer:** `NameConstraints` is an extension applied to intermediate CAs that restricts the namespace for all subsequent certificates in the path. It defines permitted and excluded subtrees (e.g. permitting only `*.corp.internal`), preventing a compromised intermediate CA from issuing unauthorized certificates for public domains like `google.com`.

#### Q10: How does the validator detect self-issued vs. self-signed certificates?
**Answer:** A certificate is *self-issued* if its Issuer DN matches its Subject DN. A certificate is *self-signed* if it is self-issued AND its signature verifies successfully using its own internal public key. Self-issued certificates are exempt from `pathLenConstraint` intermediate counting under RFC 5280 §4.2.1.9.

#### Q11: What is the Authority Key Identifier (AKI) extension and how does it assist path building?
**Answer:** AKI (OID 2.5.29.35) contains the SHA-1 or SHA-256 key identifier of the parent CA's public key. When multiple CAs share the same Distinguished Name (e.g. during root key roll-overs), AKI allows the validator to unambiguously match the child certificate to the exact parent key rather than searching across all candidates.

#### Q12: How does the engine verify ECDSA signatures without native OpenSSL?
**Answer:** The engine uses standard Java Cryptography Architecture primitives (`KeyFactory.getInstance("EC")` with `X509EncodedKeySpec`, and `Signature.getInstance("SHA256withECDSA")`). The raw public key bits and ASN.1 DER algorithm identifiers are extracted directly by our parser and passed cleanly to the JVM's hardware-accelerated crypto providers.

#### Q13: What does the strict DER minimal length encoding rule entail?
**Answer:** Under ITU-T X.690 §10.1, if a length is between 0 and 127, it must be encoded in a single short-form octet. Long-form encoding is forbidden for values $< 128$. For values $\ge 128$, the length must be encoded in the minimum number of octets, and the first octet of the multi-byte length must not be `0x00`.

#### Q14: How does wildcard hostname verification handle multi-level subdomains?
**Answer:** Per RFC 6125, a wildcard pattern like `*.example.com` matches single-level subdomains such as `api.example.com` or `mail.example.com`, but does NOT match multi-level subdomains like `dev.api.example.com` and does NOT match the apex domain `example.com`.

#### Q15: Why is this validator designed with an immutable domain model?
**Answer:** In multi-threaded enterprise proxies and gateways, certificates and validation contexts are shared across concurrent worker threads. Immutable certificates and results eliminate race conditions, eliminate the need for synchronization locks, and allow high-throughput concurrent path validation.

---

## 6. Limitations, Known Edge Cases, and Future Work

1. **Online Revocation (OCSP & CRL):** The current release focuses on deterministic, offline RFC 5280 path validation. Adding an asynchronous HTTP client for live OCSP stapling and CRL distribution point parsing is scheduled for v1.1.0.
2. **NameConstraints Subtree Masking:** Full RFC 5280 §4.2.1.10 CIDR IP address subtree masking is partially implemented; complete RFC 822 and directory name subtree matching will be finalized.
3. **Policy Tree Processing:** Complex RFC 5280 §6.1.4 certificate policy graph mapping and explicit policy indicator pruning will be expanded in future releases.
