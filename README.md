# cryptobom

Developer-first cryptographic discovery for the post-quantum transition — **"Snyk for cryptography."**

`cryptobom` scans your source code for cryptographic usage, flags quantum-vulnerable and
weak/deprecated algorithms and common misuse, and emits a CycloneDX **CBOM**
(Cryptography Bill of Materials).

> **Status:** Phase 1, pre-MVP. This is an early end-to-end slice: a Go CLI that scans
> **Java**, **Python**, and **Go** source and emits a CBOM, a SARIF report, and a terminal
> report. Findings from all languages merge into one CBOM.

## What it detects today (Java, Python & Go)

| Category | Examples |
|---|---|
| Quantum-vulnerable | RSA, ECDSA, Ed25519, ECDH, DSA, DH key generation / signatures / agreement |
| Weak / deprecated | MD5, SHA-1, DES, 3DES (DESede), RC4; undersized keys/curves (RSA-1024, P-192) |
| Misuse | ECB mode on block ciphers; hardcoded keys; static IVs/nonces |

Detection is precise by design. We favor **zero false positives over completeness**:

- **Java** — the standard JCA factory calls (`Cipher`, `MessageDigest`,
  `KeyPairGenerator`, `Signature`, `KeyAgreement`, `KeyGenerator`) with string-literal
  algorithm arguments.
- **Python** — qualified calls from the two dominant libraries: pyca/cryptography
  (`hashes.SHA1()`, `modes.ECB()`, `rsa.generate_private_key()`, …) and pycryptodome
  (`hashlib.md5()`, `AES.new(key, AES.MODE_ECB)`, `RSA.generate()`, …).
- **Go** — standard-library crypto packages resolved through imports
  (`crypto/md5`, `crypto/des`, `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, …).
  No ECB rule — Go's stdlib deliberately omits ECB.

Unqualified or non-literal calls (e.g. `hashlib.new(var)`) are left alone rather than
guessed at.

**Key parameters.** When a key size or curve is given in the same call —
`rsa.generate_private_key(key_size=2048)`, `RSA.generate(2048)`,
`rsa.GenerateKey(rand.Reader, 2048)`, `ecdsa.GenerateKey(elliptic.P256(), …)` — it is
recorded in the CBOM (`parameterSetIdentifier`, `ellipticCurve`, `classicalSecurityLevel`)
and the asset is named accordingly (e.g. `RSA-2048`). Classically weak parameters
(< 112-bit security, e.g. RSA-1024 or P-192) raise an additional finding on top of the
quantum-vulnerability one. (Java key sizes live on a separate `.initialize(n)` call and
need dataflow we don't do yet.)

**Misuse.** Hardcoded keys and static IVs/nonces are flagged only when a *literal* is
passed where a key/IV is expected — `new SecretKeySpec("…".getBytes(), "AES")`,
`AES.new(b"…", …)`, `aes.NewCipher([]byte("…"))`, `new IvParameterSpec("…".getBytes())`,
`cipher.NewCBCEncrypter(block, []byte("…"))` — so a key/IV held in a variable is never
flagged. Weak-PRNG and non-constant-time-comparison detection are deliberately deferred:
they need taint/dataflow to flag precisely, and a context-free rule would be noisy.

## Build

```sh
go build -o cryptobom ./cmd/cryptobom
```

> Requires a C toolchain — the language parsers use tree-sitter via cgo.

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
