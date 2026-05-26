package rules

import "strings"

// Inventory rules record strong/neutral cryptographic assets so the CBOM is a
// complete bill of materials, not just a list of problems. They are always
// severity=info / category=inventory, so they never gate a build, never appear
// in SARIF's problem list, and add no developer-workflow noise — they only
// enrich the CBOM. Detection stays precise: only recognized library API shapes
// are inventoried.

// CSPRNGAsset inventories a cryptographically secure RNG. name is the API/identity
// (e.g. "SecureRandom", "crypto/rand", "secrets"); detail is the specific call.
func CSPRNGAsset(name, detail string) Match {
	return Match{
		RuleID: "CB-INV-RANDOM", Title: "Cryptographically secure RNG in use",
		Severity: SeverityInfo, Category: CategoryInventory,
		Algorithm: name, Detail: detail, Primitive: "drbg",
	}
}

// SecureRandomAsset inventories the JCA SecureRandom CSPRNG. detail is the
// algorithm when known (SecureRandom.getInstance("DRBG")), otherwise "".
func SecureRandomAsset(detail string) Match { return CSPRNGAsset("SecureRandom", detail) }

// evalSecretKeyFactory inventories a key-derivation function requested via
// SecretKeyFactory.getInstance(...). PBKDF2 and PBE are the common JCA KDFs.
func evalSecretKeyFactory(alg string) []Match {
	up := strings.ToUpper(strings.TrimSpace(alg))
	switch {
	case strings.HasPrefix(up, "PBKDF2"):
		return []Match{kdfAsset("PBKDF2", alg)}
	case strings.HasPrefix(up, "PBE"):
		return []Match{kdfAsset("PBE", alg)}
	}
	return nil
}

func kdfAsset(family, detail string) Match {
	return Match{
		RuleID: "CB-INV-KDF", Title: "Key derivation function in use",
		Severity: SeverityInfo, Category: CategoryInventory,
		Algorithm: family, Detail: detail, Primitive: "kdf",
		Functions: []string{"keyderive"},
	}
}

// strongSymmetric reports whether up (uppercased algorithm) is a modern symmetric
// cipher worth inventorying as a positive asset.
func strongSymmetric(up string) bool {
	switch up {
	case "AES", "CHACHA20", "CHACHA20-POLY1305", "CAMELLIA", "ARIA":
		return true
	}
	return false
}

// invCipher inventories a strong symmetric cipher in use. mode is lowercased
// (e.g. "gcm"), or "" when the transform names no mode.
func invCipher(alg, detail, mode string) Match {
	up := strings.ToUpper(alg)
	prim := "block-cipher"
	switch {
	case mode == "gcm" || strings.Contains(up, "POLY1305"):
		prim = "ae" // authenticated encryption
	case strings.HasPrefix(up, "CHACHA"):
		prim = "stream-cipher"
	}
	return Match{
		RuleID: "CB-INV-CIPHER", Title: "Symmetric cipher in use",
		Severity: SeverityInfo, Category: CategoryInventory,
		Algorithm: alg, Detail: detail, Primitive: prim, Mode: mode,
		Functions: []string{"encrypt", "decrypt"},
	}
}

// macAsset inventories a MAC in use.
func macAsset(name, detail string) Match {
	return Match{
		RuleID: "CB-INV-MAC", Title: "MAC in use",
		Severity: SeverityInfo, Category: CategoryInventory,
		Algorithm: name, Detail: detail, Primitive: "mac",
	}
}

// invMAC inventories a non-weak HMAC in use (e.g. "HmacSHA256" -> HMAC-SHA-256).
func invMAC(alg string) Match {
	name := "HMAC"
	if hash := strings.TrimPrefix(normHash(alg), "HMAC"); hash != "" {
		name = "HMAC-" + canonHash(hash)
	}
	return macAsset(name, alg)
}
