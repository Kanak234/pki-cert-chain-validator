# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-11

### Added
- Independent pure-Java ASN.1 DER parser conforming to ITU-T X.690 §10 with strict definite-length and minimal octet enforcement.
- RFC 7468 PEM reader decoding armored ASCII certificate files into binary DER representations.
- Complete X.509 v3 object model supporting TBSCertificate, SubjectPublicKeyInfo (RSA, ECDSA), Validity, and X.500 Distinguished Names.
- Standard X.509 v3 extensions: BasicConstraints (`isCA`, `pathLenConstraint`), KeyUsage (9 standard flags), ExtendedKeyUsage (`serverAuth`, `clientAuth`, etc.), and SubjectAlternativeName (SAN) with RFC 6125 wildcard matching.
- RFC 5280 §6.1 certification path validation state machine with full cryptographic signature hierarchy verification and name chaining.
- Strict critical extension handling rejecting unhandled critical flags.
- Comprehensive diagnostic status codes and structured JSON audit log generation.
- Production command-line tool `ValidatorCli` and shaded executable JAR.
- Multi-stage Docker container build and GitHub Actions CI workflow.
- Real local throughput benchmark measuring 9,158+ chain validations per second (109.19 us/chain).
- Complete documentation suite (`docs/PRD.md`, `docs/TRD.md`, `docs/IMPLEMENTATION_PLAN.md`, `docs/EXPLAIN.md`).
