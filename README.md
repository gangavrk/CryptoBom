# cryptobom

Developer-first cryptographic discovery for the post-quantum transition — **"Snyk for cryptography."**

`cryptobom` scans your source code for cryptographic usage, flags quantum-vulnerable and
weak/deprecated algorithms and common misuse, and emits a CycloneDX **CBOM**
(Cryptography Bill of Materials).

> **Status:** Phase 1, pre-MVP. This is an early end-to-end slice: a Go CLI that scans
> **Java** source and emits a CBOM and a terminal report. Python and Go analyzers,
> SARIF output, and a GitHub Action are planned next.

## What it detects today (Java)

| Category | Examples |
|---|---|
| Quantum-vulnerable | RSA, ECDSA, ECDH, DSA, DH key generation / signatures / agreement |
| Weak / deprecated | MD5, SHA-1, DES, 3DES (DESede), RC4 |
| Misuse | ECB mode on block ciphers |

Detection is precise by design: it matches the standard JCA factory calls
(`Cipher`, `MessageDigest`, `KeyPairGenerator`, `Signature`, `KeyAgreement`,
`KeyGenerator`) with string-literal algorithm arguments. We favor **zero false
positives over completeness**.

## Build

```sh
go build -o cryptobom ./cmd/cryptobom
```

> Requires a C toolchain — the Java parser uses tree-sitter via cgo.

## Usage

```sh
# Human-readable terminal report (default)
cryptobom scan ./path/to/java/project

# Emit a CycloneDX CBOM (JSON) to stdout
cryptobom scan --format cbom ./path/to/java/project > cbom.json
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
