# cryptobom

Developer-first cryptographic discovery for the post-quantum transition — **"Snyk for cryptography."**

`cryptobom` scans your source code for cryptographic usage, flags quantum-vulnerable and
weak/deprecated algorithms and common misuse, and emits a CycloneDX **CBOM**
(Cryptography Bill of Materials).

> **Status:** Phase 1, pre-MVP. This is an early end-to-end slice: a Go CLI that scans
> **Java**, **Python**, **Go**, **Kotlin**, **C#**, **JavaScript/TypeScript**, and
> **C/C++** source — plus certificate/key files and infra config (Spring Boot, nginx,
> Apache, Kubernetes) — and emits a CBOM, a SARIF report, and a terminal report.
> Findings from all inputs merge into one CBOM.

## What it detects today (7 languages + config)

| Category | Examples |
|---|---|
| Quantum-vulnerable | RSA, ECDSA, Ed25519, ECDH, DSA, DH key generation / signatures / agreement |
| Weak / deprecated | MD5, SHA-1, DES, 3DES (DESede), RC4; undersized keys/curves (RSA-1024, P-192) |
| Misuse | ECB mode on block ciphers; hardcoded keys; static IVs/nonces; key/IV from a non-cryptographic PRNG; non-constant-time MAC/digest comparison |
| Protocols & TLS config | SSL 2/3 and TLS 1.0/1.1 (broken/deprecated); weak cipher suites (RC4, 3DES, NULL, EXPORT, anon). Detected across every form a TLS version takes — see below |
| Certificates & key material | Committed private keys and keystores (`.pem`/`.key`/`.p12`/`.jks`, SSH keys); X.509 certificates parsed for SHA-1/MD5 signatures, RSA-1024/undersized or quantum-vulnerable keys, and expiry |
| Post-quantum (quantum-safe) | ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC (+ pre-standard Kyber/Dilithium/SPHINCS+/Falcon and hybrids) — inventoried as **positive** assets to track migration progress |

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
- **JavaScript / TypeScript** — the Node.js `crypto` module
  (`createHash("md5")`, `createCipheriv("aes-128-ecb", …)`, `generateKeyPair("rsa", …)`)
  and crypto-js (`CryptoJS.MD5(…)`, `CryptoJS.DES`, `CryptoJS.mode.ECB`). Parses `.js`,
  `.mjs`, `.cjs`, `.jsx`, `.ts`, and `.tsx`.
- **C / C++** — OpenSSL: the function-name-encoded API (`MD5(…)`, `EVP_des_ede3_cbc()`,
  `EVP_aes_128_ecb()`, `RSA_generate_key_ex()`), the 3.0 fetch API
  (`EVP_MD_fetch(…, "MD5", …)`), TLS method constructors (`SSLv3_method()`), and version
  constants (`TLS1_1_VERSION`). Parses `.c/.h/.cpp/.cc/.cxx/.hpp/.hh`.
- **Post-quantum algorithms** — when a NIST PQC algorithm (or a pre-standard / library
  name) is already in use, it's inventoried as **quantum-safe** rather than flagged, so
  the tool measures migration *progress*, not just debt. Recognized via JCA
  `getInstance("ML-KEM"/"Dilithium"/…)` (Java/Kotlin), `oqs.KeyEncapsulation(…)` (Python),
  `crypto/mlkem` & CIRCL import paths (Go), and `MLKem`/`MLDsa`/`SlhDsa` (.NET 9, C#).
- **Certificate & key files** — `.pem/.crt/.cer/.der`, PKCS#12 (`.p12/.pfx`), JKS, `.key`,
  and SSH keys are scanned as files. Private keys and keystores in the repo are flagged
  (committed key material), and X.509 certificates are parsed (`crypto/x509`) to surface
  weak signatures (SHA-1/MD5), undersized/quantum-vulnerable keys, and expiry. These
  populate the CycloneDX `certificate` and `related-crypto-material` asset types — so all
  four CBOM asset types (algorithm, protocol, certificate, related-crypto-material) are
  now emitted.
- **Infra & framework config** — TLS versions are usually configured outside code, so
  these are parsed too: **Spring Boot** (`application.properties`/`.yml`:
  `server.ssl.protocol`/`enabled-protocols`/`ciphers`), **nginx** (`ssl_protocols`),
  **Apache** (`SSLProtocol`, honoring its `+`/`-` enable/disable semantics),
  **Kubernetes / Istio / ingress** YAML (`minProtocolVersion`, `tls-min-version`, …), and
  **Terraform** (`.tf`: `minimum_protocol_version`, AWS ELB/CloudFront `ssl_policy` names,
  and KMS `customer_master_key_spec` like `RSA_2048` → quantum-vulnerable).
  Deprecated protocols and weak cipher suites are flagged with their line number; TLS
  1.2/1.3 are inventoried as CycloneDX `protocol` assets.

**TLS versions in every form.** A TLS/SSL version is written differently per platform;
all of these are now recognized and mapped to the same protocol assets:

- String literal — `SSLContext.getInstance("TLSv1.1")` (Java/Kotlin), config values.
- Method call — `setEnabledProtocols(…)` / `setProtocols(…)` string arrays (Java/Kotlin).
- Named constants/enums — `tls.VersionTLS10` (Go), `ssl.PROTOCOL_TLSv1` /
  `ssl.TLSVersion.TLSv1_2` (Python), `SslProtocols.Tls11` (C#).

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

**Non-constant-time comparison.** A MAC/digest compared with a variable-time
comparison is a timing side-channel. The same taint approach applies: a value is
tagged as a MAC/digest at its source (`mac.doFinal()`/`md.digest()` in Java/Kotlin,
`hmac.new(...).digest()` in Python, `hmac.New().Sum()`/`sha256.Sum256` in Go,
`hmac.ComputeHash()` in C#), and a comparison is only flagged when an operand is
tagged — so ordinary equality checks are never touched. The constant-time forms are
recognized and never flagged: `MessageDigest.isEqual`, `hmac.compare_digest`,
`subtle.ConstantTimeCompare`/`hmac.Equal`, `CryptographicOperations.FixedTimeEquals`.

Non-constant-time comparison detection is not done yet (it needs MAC-source taint, the
highest false-positive risk).

## Install & run (macOS)

**Prerequisites.** A C toolchain is required — the language parsers use tree-sitter via
cgo. On macOS that means the Xcode Command Line Tools and Go:

```sh
xcode-select --install        # provides clang (cgo)
brew install go               # Go 1.26+
```

**Build the binary:**

```sh
git clone <repo-url> cryptobom && cd cryptobom
go build -o cryptobom ./cmd/cryptobom
```

This produces a `cryptobom` binary in the current directory. You can run it right away
without installing — from the repo directory:

```sh
./cryptobom scan .            # scan the current directory
./cryptobom version
```

**Put it on your `PATH`** so `cryptobom` works from anywhere (pick one):

```sh
# Option A — copy into /usr/local/bin (commonly already on PATH; needs sudo)
sudo cp cryptobom /usr/local/bin/cryptobom

# Option B — go install, then add the Go bin dir to PATH (zsh)
go install ./cmd/cryptobom
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

**Verify:**

```sh
cryptobom version            # prints the version
cryptobom scan /path/to/repo
```

> If you see `zsh: command not found: cryptobom`, the binary isn't on your `PATH` —
> use `./cryptobom` from the repo, or complete an install option above.

> Apple Silicon and Intel both work; the binary is built natively for your machine.
> A prebuilt binary and container image are also published per release (see
> [Releases](#releases)).

## Usage

```sh
# Human-readable terminal report (default)
cryptobom scan ./path/to/java/project

# Test code (test/ dirs, *_test.go, *Test.java, …) is skipped by default.
# Include it with --include-tests; those findings are tagged with the "test"
# scope (a [test] marker in the terminal, cryptobom:scope=test in the CBOM, and
# properties.scope=test in SARIF) so they can be filtered.
cryptobom scan --include-tests ./path/to/java/project

# Emit a CycloneDX CBOM (JSON) to stdout
cryptobom scan --format cbom ./path/to/java/project > cbom.json

# Emit SARIF 2.1.0 for IDEs / GitHub code scanning
cryptobom scan --format sarif ./path/to/java/project > results.sarif

# CI gate: fail the build (exit 2) on any high+ finding
cryptobom scan --fail-on high ./src

# Baseline: record current findings, then surface only NEW ones on later scans
cryptobom scan --write-baseline .cryptobom-baseline.json ./src
cryptobom scan --baseline .cryptobom-baseline.json --fail-on medium ./src

# One scan, both artifacts: a developer report on screen plus files on disk
cryptobom scan --sarif results.sarif --cbom cbom.json ./path/to/java/project
```

`--cbom` and `--sarif` write to files independently of `--format` (which controls
stdout). The SARIF report carries the actionable problems for developers; the CBOM
is the full cryptographic inventory for tracking and compliance.

## CI gating & noise control

- **`--fail-on <severity>`** (`critical`/`high`/`medium`/`low`) makes `cryptobom`
  exit **2** when any reported finding is at or above that severity, so it can gate a
  PR. Exit codes: `0` clean, `2` threshold met, `1` operational error.
- **`--baseline <file>`** ignores findings already recorded in the file, surfacing only
  *new* ones. Generate the file with **`--write-baseline <file>`**. Fingerprints exclude
  line numbers, so findings survive unrelated edits.
- **Inline suppression:** add `cryptobom:ignore` in a comment on the finding's line, or
  a comment-only line directly above it. Scope it to specific rules with
  `cryptobom:ignore[CB-WEAK-MD5,CB-MISUSE-ECB]`.

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
