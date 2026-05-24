# cryptobom

Developer-first cryptographic discovery for the post-quantum transition — **"Snyk for cryptography."**

`cryptobom` scans your source code for cryptographic usage, flags quantum-vulnerable and
weak/deprecated algorithms and common misuse, and emits a CycloneDX **CBOM**
(Cryptography Bill of Materials).

> **Status:** Phase 1, pre-MVP. This is an early end-to-end slice: a Go CLI that scans
> **Java** source and emits a CBOM, a SARIF report, and a terminal report. Python and Go
> analyzers and a GitHub Action are planned next.

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

# Emit SARIF 2.1.0 for IDEs / GitHub code scanning
cryptobom scan --format sarif ./path/to/java/project > results.sarif

# One scan, both artifacts: a developer report on screen plus files on disk
cryptobom scan --sarif results.sarif --cbom cbom.json ./path/to/java/project
```

`--cbom` and `--sarif` write to files independently of `--format` (which controls
stdout). The SARIF report carries the actionable problems for developers; the CBOM
is the full cryptographic inventory for tracking and compliance.

## GitHub Action

`cryptobom` ships as a container action ([action.yml](action.yml)). It scans your
repo and writes a SARIF report (for code scanning) and a CBOM (as a build artifact).

```yaml
permissions:
  contents: read
  security-events: write # to upload SARIF

steps:
  - uses: actions/checkout@v4
  - id: cryptobom
    uses: cryptobom/cryptobom@v1 # not yet published; this repo dogfoods it via `uses: ./`
    with:
      path: .                       # default
      sarif-file: cryptobom.sarif   # default
      cbom-file: cryptobom.cbom.json # default
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.cryptobom.outputs.sarif-file }}
```

**Inputs:** `path`, `sarif-file`, `cbom-file`.
**Outputs:** `sarif-file`, `cbom-file` (the written paths).

See [.github/workflows/scan.yml](.github/workflows/scan.yml) for the working
example this repo runs against its own `testdata/`.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
