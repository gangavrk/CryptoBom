# cryptobom

Developer-first cryptographic discovery for the post-quantum transition — **"Snyk for cryptography."**

`cryptobom` scans your source code for cryptographic usage, flags quantum-vulnerable and
weak/deprecated algorithms and common misuse, and emits a CycloneDX **CBOM**
(Cryptography Bill of Materials).

> **Status:** Phase 1, pre-MVP. This is an early end-to-end slice: a Go CLI that scans
> **Java**, **Python**, **Go**, **Kotlin**, **C#**, **JavaScript/TypeScript**, and
> **C/C++** source — plus certificate/key files and infra config (Spring Boot, nginx,
> Apache, Kubernetes, Terraform) — and emits a CBOM, a SARIF report, and a terminal report.
> Findings from all inputs merge into one CBOM.

## What it detects today (7 languages + config)

| Category | Examples |
|---|---|
| Quantum-vulnerable | RSA, ECDSA, Ed25519, ECDH, DSA, DH key generation / signatures / agreement |
| Weak / deprecated | MD5, SHA-1, DES, 3DES (DESede), RC4; HMAC over a broken hash (HMAC-MD5); undersized keys/curves (RSA-1024, P-192) |
| Misuse | ECB mode on block ciphers (incl. the JCE default when no mode is given); RSA PKCS#1 v1.5 *encryption* padding (Bleichenbacher); hardcoded keys; static IVs/nonces; key/IV from a non-cryptographic PRNG; non-constant-time MAC/digest comparison |
| Protocols & TLS config | SSL 2/3 and TLS 1.0/1.1 (broken/deprecated); weak cipher suites (RC4, 3DES, NULL, EXPORT, anon). Detected across every form a TLS version takes — see below |
| Certificates & key material | Committed private keys and keystores (`.pem`/`.key`/`.p12`/`.jks`, SSH keys); X.509 certificates parsed for SHA-1/MD5 signatures, RSA-1024/undersized or quantum-vulnerable keys, and expiry |
| Post-quantum (quantum-safe) | ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC, FrodoKEM, Classic-McEliece, BIKE, XMSS/LMS (+ pre-standard Kyber/Dilithium/SPHINCS+/Falcon and hybrids) — inventoried as **positive** assets to track migration progress |

Detection is precise by design. We favor **zero false positives over completeness**:

- **Java** — the standard JCA factory calls (`Cipher`, `MessageDigest`,
  `KeyPairGenerator`, `Signature`, `KeyAgreement`, `KeyGenerator`, `Mac`) with
  string-literal algorithm arguments.
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

**Padding, default mode, and weak MACs.** Three further precise checks:

- **Default ECB.** A JCA block cipher requested with no mode — `Cipher.getInstance("AES")` —
  is flagged, because the JCE silently defaults to ECB. This is JCA-specific (Java/Kotlin);
  Go and Python pass a bare algorithm name with no such default, so they're never affected.
- **RSA PKCS#1 v1.5 encryption padding.** `rsa.EncryptPKCS1v15` (Go),
  `Cipher.getInstance("RSA/ECB/PKCS1Padding")` (Java/Kotlin), and pycryptodome's
  `PKCS1_v1_5` cipher are flagged as Bleichenbacher/ROBOT-vulnerable. RSA *signatures*
  (PKCS#1 v1.5 is standard there) and RSA-OAEP are deliberately not flagged.
- **Weak MAC.** A MAC over a broken hash (HMAC-MD5/MD4/MD2) is flagged via the JCA `Mac`
  factory (Java/Kotlin) and the .NET `HMACMD5` type; HMAC-SHA* is not flagged.

## Rule provenance & trust

Every rule carries a verifiable basis, so a finding isn't just the tool's say-so. The
provenance, citations, and compliance profiles live in a single data file
([internal/rules/rulepack.yaml](internal/rules/rulepack.yaml)) — embedded into the binary
and schema-validated at load — so the policy is reviewable at a glance and a cryptographer
can vet it without reading Go. Each rule records:

- a **CWE** weakness class (e.g. `CWE-327`),
- the **standard's status** — `finalized`, `draft`, or `guidance` — so you know whether
  it rests on a settled standard,
- **citations** to the authority (NIST FIPS 203/204/205, NSA CNSA 2.0, NIST SP 800-131A /
  800-57 / 800-52, IETF RFC 8996/7568, OWASP, …) with URLs,
- and the **rule-pack version** (`RulePackVersion`), stamped on every report.

This flows into all three outputs:

- **SARIF** — each rule gets a `helpUri`, a `help` block listing its citations, a
  `standardStatus` property, and `external/cwe/cwe-NNN` tags (rendered by code-scanning
  UIs). The run records `properties.rulepackVersion`.
- **CBOM** — each component gets `externalReferences` (the standards) plus
  `cryptobom:cwe` / `cryptobom:standardStatus` properties; the BOM metadata records the
  rule-pack version.
- **terminal** — the CWE is shown on each finding and the rule-pack version in the footer.

The rule-pack is open source and reviewed via pull request, so its change history is the
audit trail. Tests fail the build if any rule ships without provenance
(`TestEveryRuleHasProvenance`) or if the rule-pack file is malformed
(`TestRulepackValidates`). Severity, titles, and remediation stay in Go on purpose:
they're often computed at detection time (a rule's severity can vary by context, and
many titles are built from runtime values), so they belong with the detection logic
rather than in the data file.

## Compliance profiles

`--profile <name>` classifies every finding against a named standard. It's a **lens over
the findings already detected** — it adds no detection of its own, so it can't introduce
false positives. Each finding is tagged `violation`, `not-applicable`, or `compliant`,
and the standard's view of severity is applied (e.g. CNSA 2.0 raises quantum-vulnerable
crypto to **critical**). The full inventory is preserved.

| Profile | Standard | What it treats as a violation |
|---|---|---|
| `cnsa-2.0` | NSA CNSA 2.0 | Quantum-vulnerable public-key crypto (RSA, ECDSA, ECDH, DH, EdDSA) — **must migrate to PQC** — plus all weak/deprecated algorithms and misuse. |
| `fips-140-3` | NIST FIPS 140-3 | Non-approved/legacy primitives (MD5, DES, RC4, …), undersized keys, weak protocols, and misuse. Classical RSA/ECDSA stay **approved** — reported `not-applicable`, not a violation. |
| `dora` | EU DORA (Reg. 2022/2554) | Broken/deprecated algorithms, weak protocols, and misuse. Quantum-vulnerable crypto is surfaced as a risk but not yet a mandated violation. |

The defining difference is how each standard treats classical public-key crypto: CNSA 2.0
mandates the post-quantum migration, while FIPS 140-3 and DORA still permit RSA/ECDSA today.

```sh
# Classify findings against CNSA 2.0 in the terminal report
cryptobom scan --profile cnsa-2.0 ./src

# Gate a build only on violations of the standard. Under FIPS 140-3 a repo that
# uses RSA-2048 (approved, quantum-vulnerable) does NOT fail; broken algorithms do.
cryptobom scan --profile fips-140-3 --fail-on high ./src
```

The active profile and per-finding compliance status flow into all three outputs: the
terminal tags each finding and counts violations; the CBOM records `cryptobom:profile`
on the BOM and `cryptobom:compliance` on each component; SARIF records `profile` on the
run and `compliance` on each result.

**Without `--profile` (the default),** there's no compliance classification at all: every
finding is reported at its intrinsic severity, nothing is tagged
`violation`/`not-applicable`/`compliant`, the `cryptobom:profile`/`cryptobom:compliance`
and SARIF `profile`/`compliance` fields are omitted, and `--fail-on` gates on raw
severity. The practical effect is that the standard-specific nuance disappears — e.g. a
quantum-vulnerable RSA-2048 keygen is `high` and **will** trip `--fail-on high`, whereas
under `--profile fips-140-3` it's `not-applicable` and passes the gate. So the default is
the honest "show me all cryptographic risk" view; reach for a profile only when you need
to answer "are we compliant with *this* standard."

## Install & run (macOS)

**Homebrew (prebuilt binary).** Install without a toolchain:

```sh
brew install gangavrk/tap/cryptobom   # or: brew tap gangavrk/tap && brew install cryptobom
cryptobom version
```

The formula ships the prebuilt binary from the release (no build step), so the C
toolchain below is only needed for building from source. The tap is fed automatically
by the release workflow — see [packaging/homebrew/cryptobom.rb](packaging/homebrew/cryptobom.rb)
and [Releases](#releases).

**Install script (Linux & macOS).** A one-liner that downloads the right prebuilt
binary, verifies its checksum, and installs it ([install.sh](install.sh)):

```sh
curl -fsSL https://raw.githubusercontent.com/gangavrk/CryptoBom/main/install.sh | sh
```

Override behavior with env vars: `CRYPTOBOM_VERSION` (a tag, default latest),
`CRYPTOBOM_INSTALL_DIR` (default `/usr/local/bin`, else `~/.local/bin`), and
`CRYPTOBOM_REPO`. Supports linux/amd64, darwin/amd64, and darwin/arm64 (the release
matrix); other platforms should build from source.

### Build from source

**Prerequisites.** A C toolchain is required — the language parsers use tree-sitter via
cgo. On macOS that means the Xcode Command Line Tools and Go:

```sh
xcode-select --install        # provides clang (cgo)
brew install go               # Go 1.26+
```

**Build the binary:**

```sh
git clone https://github.com/gangavrk/CryptoBom.git cryptobom && cd cryptobom
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

# Classify findings against a compliance standard (see "Compliance profiles")
cryptobom scan --profile cnsa-2.0 ./src

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
  - uses: actions/checkout@v6
  - id: cryptobom
    uses: gangavrk/CryptoBom@v1 # not yet published; this repo dogfoods it via `uses: ./`
    with:
      path: .                       # default
      sarif-file: cryptobom.sarif   # default
      cbom-file: cryptobom.cbom.json # default
      profile: ""                   # optional: cnsa-2.0 | fips-140-3 | dora
  - uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: ${{ steps.cryptobom.outputs.sarif-file }}
```

**Inputs:** `path`, `sarif-file`, `cbom-file`, `profile`.
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
pushes a versioned container image to GHCR (`ghcr.io/gangavrk/cryptobom:<tag>` and
`:latest`). The binary and image report the tag via `cryptobom version`.

Current matrix: `linux/amd64`, `darwin/amd64`, `darwin/arm64`. (Windows and
`linux/arm64` can be added as matrix entries when needed.)

**Homebrew tap.** The `homebrew` job renders
[packaging/homebrew/cryptobom.rb](packaging/homebrew/cryptobom.rb) from the release
tarballs (version + per-platform `sha256`) and pushes it to your tap. Enable it with
two repo settings: a secret `HOMEBREW_TAP_TOKEN` (a PAT with push access to the tap
repo) and a variable `HOMEBREW_TAP_REPO` (e.g. `gangavrk/homebrew-tap`). The tap repo
must be named `homebrew-<name>` so `brew tap gangavrk/<name>` resolves to it. Until
both are set the job still runs as a dry run (renders the formula, doesn't push), so
releases never fail for want of a configured tap.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
