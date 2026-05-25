package rules

import "strings"

// EvalProtocol maps a TLS/SSL protocol token (from SSLContext.getInstance, a Spring
// `server.ssl.protocol`/`enabled-protocols` value, etc.) to a protocol-asset match.
// Broken (SSLv2/SSLv3) and deprecated (TLS 1.0/1.1) versions are flagged; TLS 1.2/1.3
// and the generic "TLS" selector are inventoried.
func EvalProtocol(proto string) []Match {
	key := strings.ToUpper(strings.TrimSpace(proto))
	// Normalize the many spellings to a dotless form: SSLv3 -> SSL3, TLSv1.2 ->
	// TLS12, TLSV1_1 (Istio) -> TLS11, TLSv1_method (Node) -> TLS1METHOD.
	key = strings.NewReplacer("_", "", ".", "", " ", "", "V", "").Replace(key)
	key = strings.TrimSuffix(key, "METHOD")

	switch key {
	case "SSL2", "SSL2HELLO":
		return []Match{weakProtocol("SSLv2", "2.0", SeverityHigh, "SSL 2.0 is broken", proto)}
	case "SSL", "SSL3":
		return []Match{weakProtocol("SSLv3", "3.0", SeverityHigh, "SSL 3.0 is broken (POODLE)", proto)}
	case "TLS1", "TLS10":
		return []Match{weakProtocol("TLSv1.0", "1.0", SeverityMedium, "TLS 1.0 is deprecated", proto)}
	case "TLS11":
		return []Match{weakProtocol("TLSv1.1", "1.1", SeverityMedium, "TLS 1.1 is deprecated", proto)}
	case "TLS", "TLS12":
		return []Match{invProtocol("TLSv1.2", "1.2", proto)}
	case "TLS13":
		return []Match{invProtocol("TLSv1.3", "1.3", proto)}
	}
	return nil
}

func weakProtocol(name, version string, sev Severity, title, detail string) Match {
	return Match{
		RuleID: "CB-WEAK-PROTOCOL", Title: title + "; require TLS 1.2 or 1.3",
		Severity: sev, Category: CategoryWeak,
		Algorithm: name, Detail: detail,
		AssetKind: "protocol", ProtocolVersion: version,
		Remediation: "Disable legacy protocols; allow only TLS 1.2 and TLS 1.3.",
	}
}

func invProtocol(name, version, detail string) Match {
	return Match{
		RuleID: "CB-INV-PROTOCOL", Title: name + " in use",
		Severity: SeverityInfo, Category: CategoryInventory,
		Algorithm: name, Detail: detail,
		AssetKind: "protocol", ProtocolVersion: version,
	}
}

// EvalCipherSuite flags a weak TLS cipher-suite name (e.g. from a Spring
// `server.ssl.ciphers` setting). Modern AEAD suites are not flagged.
func EvalCipherSuite(suite string) []Match {
	up := strings.ToUpper(strings.TrimSpace(suite))
	if up == "" {
		return nil
	}
	// Ordered: more specific tokens first (3DES before the generic DES check).
	checks := []struct {
		token, algo, why string
		sev              Severity
	}{
		{"NULL", "NULL", "no encryption", SeverityHigh},
		{"_ANON", "anon", "no authentication", SeverityHigh},
		{"EXPORT", "EXPORT", "export-grade (40/56-bit)", SeverityHigh},
		{"RC4", "RC4", "broken stream cipher", SeverityHigh},
		{"3DES", "3DES", "deprecated", SeverityMedium},
		{"_DES_", "DES", "broken 56-bit cipher", SeverityHigh},
		{"_MD5", "MD5", "broken MAC hash", SeverityMedium},
	}
	for _, c := range checks {
		if strings.Contains(up, c.token) {
			return []Match{{
				RuleID: "CB-WEAK-CIPHERSUITE", Title: "Weak TLS cipher suite (" + c.algo + ": " + c.why + ")",
				Severity: c.sev, Category: CategoryWeak, Algorithm: suite, Detail: suite,
				Remediation: "Use modern AEAD suites (e.g. TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).",
			}}
		}
	}
	return nil
}
