# cryptobom

Developer-first cryptographic discovery for the post-quantum transition — **"Snyk for cryptography."**

`cryptobom` scans your source code for cryptographic usage, flags quantum-vulnerable and
weak/deprecated algorithms and common misuse, and emits a CycloneDX **CBOM**
(Cryptography Bill of Materials).

> **Status:** Phase 1, pre-MVP. This is an early end-to-end slice: a Go CLI that scans
> **Java**, **Python**, **Go**, **Kotlin**, and **C#** source and emits a CBOM, a SARIF
> report, and a terminal report. Findings from all languages merge into one CBOM.

## What it detects today (Java, Python, Go, Kotlin & C#)

| Category | Examples |
|---|---|
| Quantum-vulnerable | RSA, ECDSA, Ed25519, ECDH, DSA, DH key generation / signatures / agreement |
| Weak / deprecated | MD5, SHA-1, DES, 3DES (DESede), RC4; undersized keys/curves (RSA-1024, P-192) |
| Misuse | ECB mode on block ciphers; hardcoded keys; static IVs/nonces; key/IV from a non-cryptographic PRNG |

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
- **Kotlin** — the same JCA APIs as Java (`Cipher.getInstance(…)`,
  `KeyPairGenerator`, `SecretKeySpec(…)`, …), reusing the Java rule set. Byte keys
  come from `"literal".toByteArray()` and constructors omit `new`.
- **C# / .NET** — type-based: `System.Security.Cryptography` types resolve to the
  algorithm (`MD5.Create()`, `RSA.Create(2048)`, `new DESCryptoServiceProvider()`),
  `CipherMode.ECB` is the ECB signal, and hardcoded/weak-PRNG keys are caught on
  `.Key`/`.IV` property assignments.

Unqualified or non-literal calls (e.g. `hashlib.new(var)`) are left alone rather than
guessed at.

**Key parameters.** When a key size or curve is given in the same call —
`rsa.generate_private_key(key_size=2048)`, `RSA.generate(2048)`,
`rsa.GenerateKey(rand.Reader, 2048)`, `ecdsa.GenerateKey(elliptic.P256(), …)` — it is
recorded in the CBOM (`parameterSetIdentifier`, `ellipticCurve`, `classicalSecurityLevel`)
and the asset is named accordingly (e.g. `RSA-2048`). Classically weak parameters
(< 112-bit security, e.g. RSA-1024 or P-192) raise an additional finding on top of the
quantum-vulnerability one. For **Java**, the size lives on a separate `kpg.initialize(n)`
call; a lightweight intra-procedural dataflow pass links it back to the `getInstance`.

**Misuse.** Hardcoded keys and static IVs/nonces are flagged only when a *literal* is
passed where a key/IV is expected — `new SecretKeySpec("…".getBytes(), "AES")`,
`AES.new(b"…", …)`, `aes.NewCipher([]byte("…"))`, `new IvParameterSpec("…".getBytes())`,
`cipher.NewCBCEncrypter(block, []byte("…"))` — so a key/IV held in a variable is never
flagged.

A value drawn from a non-cryptographic PRNG is flagged *only when it reaches a key/IV
sink* — a lightweight per-function dataflow pass tracks the tainted variable. Requiring
the crypto sink keeps it precise: ordinary non-crypto random use never triggers, and the
secure RNG is never flagged. Sources and sinks per language:

- **Java** — `java.util.Random` via `random.nextBytes(buf)` into `new SecretKeySpec(buf, …)`
  / `new IvParameterSpec(buf)`. `SecureRandom` is never flagged.
- **Go** — `math/rand` via `rand.Read(buf)` into `aes/des/rc4.NewCipher(buf)` or a
  `crypto/cipher` IV. `crypto/rand` is never flagged.
- **Python** — the `random` module (e.g. `random.randbytes()`) into `AES.new(buf, …)` /
  `algorithms.AES(buf)` / `modes.CBC(buf)`. `secrets` / `os.urandom` are never flagged.
- **Kotlin** — `Random()` via `nextBytes(buf)` into `SecretKeySpec(buf, …)` /
  `IvParameterSpec(buf)`. `SecureRandom` is never flagged. (Key sizes likewise link
  `KeyPairGenerator.getInstance(…)` to a later `initialize(n)`.)
- **C#** — `System.Random` via `NextBytes(buf)` into a `.Key`/`.IV` assignment.
  `RandomNumberGenerator` is never flagged. (Key sizes come from `Create(n)` / the
  constructor argument.)

Non-constant-time comparison detection is not done yet (it needs MAC-source taint, the
highest false-positive risk).

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

## Releases

Pushing a version tag runs [.github/workflows/release.yml](.github/workflows/release.yml):

```sh
git tag v0.1.0 && git push origin v0.1.0
```

It builds platform binaries on native runners (cgo can't be cleanly
cross-compiled), attaches them with `checksums.txt` to a GitHub Release, and
pushes a versioned container image to GHCR (`ghcr.io/<owner>/cryptobom:<tag>` and
`:latest`). The binary and image report the tag via `cryptobom version`.

Current matrix: `linux/amd64`, `darwin/amd64`, `darwin/arm64`. (Windows and
`linux/arm64` can be added as matrix entries when needed.)

## License

Apache License 2.0 — see [LICENSE](LICENSE).
