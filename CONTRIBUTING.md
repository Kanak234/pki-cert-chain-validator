# Contributing to PKI Certificate Chain Validator

Thank you for your interest in contributing! This project implements strict RFC 5280 X.509 certification path validation with pure Java and zero third-party runtime dependencies.

## Standards and Guidelines

### 1. Code Standards
- **Java Standard:** Java 21 LTS syntax and features.
- **Runtime Dependencies:** Zero external runtime dependencies. Only standard `java.base` and standard cryptographic providers.
- **Strict Compiler Settings:** Compilation enforces `-Xlint:all` and `-Werror`. Code must compile without warnings.

### 2. Testing & Coverage
- All pull requests must include comprehensive automated tests using JUnit 5 and AssertJ.
- JaCoCo enforces a minimum **80% line coverage** check across all core packages (`com.kanak.pki.asn1`, `com.kanak.pki.model`, `com.kanak.pki.path`).
- Tests must be strictly deterministic and must not make network calls.

### 3. Local Verification
Before submitting a PR, execute the complete verification suite:
```bash
mvn clean verify
```

### 4. Pull Request Process
1. Create a feature branch off `master`.
2. Ensure your commit messages adhere to the [Conventional Commits](https://www.conventionalcommits.org/) format (e.g. `feat:`, `fix:`, `docs:`, `test:`, `chore:`).
3. Open a Pull Request against `master`. All GitHub Actions CI checks must pass before merging.
