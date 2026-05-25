// Package config detects cryptographic settings in framework configuration files
// (Spring Boot application.properties / application.yml). TLS protocol versions and
// cipher suites are commonly configured here rather than in code, e.g.:
//
//	server.ssl.enabled-protocols=TLSv1.2,TLSv1.3
//	server.ssl.ciphers=TLS_RSA_WITH_RC4_128_SHA
package config

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// kv is a flattened config entry: dotted key, value, and 1-based line number.
type kv struct {
	key   string
	value string
	line  int
}

// Analyze parses a framework/infra config file (Spring properties/YAML, Kubernetes
// /Istio YAML, nginx/Apache .conf) and returns crypto findings for recognized SSL
// settings. Files that aren't config (or aren't crypto-relevant) produce nothing.
func Analyze(path string, src []byte) ([]rules.Finding, error) {
	if strings.HasSuffix(path, ".conf") {
		return parseConf(path, src), nil
	}
	if strings.HasSuffix(path, ".tf") {
		return parseTerraform(path, src), nil
	}

	var entries []kv
	if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
		entries = flattenYAML(src)
	} else {
		entries = flattenProperties(src)
	}

	var findings []rules.Finding
	for _, e := range entries {
		k := strings.ToLower(e.key)
		evidence := e.key + "=" + e.value
		switch {
		case isProtocolKey(k):
			// Values may be comma- or space-separated; only TLS/SSL tokens match.
			for _, p := range splitProtocols(e.value) {
				for _, m := range rules.EvalProtocol(p) {
					findings = append(findings, finding(m, path, e.line, evidence))
				}
			}
		case isCipherKey(k):
			for _, c := range splitList(e.value) {
				for _, m := range rules.EvalCipherSuite(c) {
					findings = append(findings, finding(m, path, e.line, evidence))
				}
			}
		}
	}
	return findings, nil
}

// isProtocolKey matches the many keys that carry a TLS protocol version across
// Spring, Kubernetes ingress, and Istio. The value is gated by EvalProtocol, so a
// broad key match can't produce false positives.
func isProtocolKey(lowerKey string) bool {
	for _, suffix := range []string{
		"ssl.protocol", "ssl.enabled-protocols", "ssl-protocols", "ssl_protocols",
		"protocols", "minprotocolversion", "maxprotocolversion",
		"tlsminversion", "tls-min-version", "tls_min_version",
		"min-tls-version", "min_tls_version", "minimumprotocolversion",
	} {
		if strings.HasSuffix(lowerKey, suffix) {
			return true
		}
	}
	return false
}

// isCipherKey matches explicit cipher-suite-list keys (not OpenSSL cipher specs,
// which use !-exclusions and would false-positive).
func isCipherKey(lowerKey string) bool {
	return strings.HasSuffix(lowerKey, "ssl.ciphers") || strings.HasSuffix(lowerKey, "ssl.cipher-suites")
}

func finding(m rules.Match, path string, line int, evidence string) rules.Finding {
	return rules.Finding{Match: m, File: path, Line: line, Column: 1, Evidence: evidence}
}

// splitList splits a comma-separated value and trims each element.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitProtocols splits on commas and whitespace (nginx/ingress list TLS versions
// space-separated).
func splitProtocols(v string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if p = strings.Trim(p, "\"'"); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseConf scans an nginx or Apache config for TLS protocol directives.
//   - nginx:  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;   (all listed are enabled)
//   - Apache: SSLProtocol -all +TLSv1.2             (+/bare = enabled, - = disabled)
func parseConf(path string, src []byte) []rules.Finding {
	var findings []rules.Finding
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(strings.TrimRight(line, ";"))
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "ssl_protocols": // nginx — every listed protocol is enabled
			for _, tok := range fields[1:] {
				for _, m := range rules.EvalProtocol(tok) {
					findings = append(findings, finding(m, path, i+1, line))
				}
			}
		case "SSLProtocol": // Apache — honor +/- enable/disable
			for _, tok := range fields[1:] {
				if strings.HasPrefix(tok, "-") || strings.EqualFold(tok, "all") {
					continue // disabled, or the ambiguous "all" token
				}
				for _, m := range rules.EvalProtocol(strings.TrimPrefix(tok, "+")) {
					findings = append(findings, finding(m, path, i+1, line))
				}
			}
		}
	}
	return findings
}

// flattenProperties parses key=value / key: value lines, tracking line numbers.
func flattenProperties(src []byte) []kv {
	var out []kv
	for i, line := range strings.Split(string(src), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "!") {
			continue
		}
		idx := strings.IndexAny(s, "=:")
		if idx < 0 {
			continue
		}
		out = append(out, kv{
			key:   strings.TrimSpace(s[:idx]),
			value: strings.TrimSpace(s[idx+1:]),
			line:  i + 1,
		})
	}
	return out
}

// flattenYAML flattens a YAML mapping tree into dotted-key entries, preserving line
// numbers. Invalid or non-mapping YAML yields no entries.
func flattenYAML(src []byte) []kv {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	var out []kv
	walkYAML("", doc.Content[0], &out)
	return out
}

func walkYAML(prefix string, n *yaml.Node, out *[]kv) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			if prefix != "" {
				key = prefix + "." + key
			}
			walkYAML(key, n.Content[i+1], out)
		}
	case yaml.SequenceNode:
		for _, item := range n.Content {
			if item.Kind == yaml.ScalarNode {
				*out = append(*out, kv{key: prefix, value: item.Value, line: item.Line})
			}
		}
	case yaml.ScalarNode:
		*out = append(*out, kv{key: prefix, value: n.Value, line: n.Line})
	}
}

// parseTerraform scans HCL `key = "value"` assignments for TLS protocol versions,
// AWS TLS security policies, and KMS key specs. Block headers and expressions
// (non-identifier keys) are skipped.
func parseTerraform(path string, src []byte) []rules.Finding {
	var findings []rules.Finding
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 1 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if !isIdent(key) {
			continue
		}
		val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"'`)
		if val == "" {
			continue
		}

		var matches []rules.Match
		switch key {
		case "minimum_protocol_version", "tls_min_version", "min_tls_version", "minimum_tls_version":
			matches = rules.EvalProtocol(stripPolicyYear(val))
		case "ssl_policy", "tls_security_policy", "security_policy":
			matches = rules.AWSTLSPolicy(val)
		case "customer_master_key_spec", "key_spec":
			matches = rules.KMSKeySpec(val)
		}
		for _, m := range matches {
			findings = append(findings, finding(m, path, i+1, key+" = "+val))
		}
	}
	return findings
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// stripPolicyYear removes a trailing _<year> (CloudFront "TLSv1.1_2016" -> "TLSv1.1").
func stripPolicyYear(v string) string {
	if i := strings.LastIndexByte(v, '_'); i > 0 {
		if y := v[i+1:]; len(y) == 4 && isDigits(y) {
			return v[:i]
		}
	}
	return v
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
