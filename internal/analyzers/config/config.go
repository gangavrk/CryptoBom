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

// Analyze parses a .properties / .yml / .yaml file and returns crypto findings for
// recognized SSL settings. Files that aren't config (or aren't crypto-relevant)
// simply produce nothing.
func Analyze(path string, src []byte) ([]rules.Finding, error) {
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
		case strings.HasSuffix(k, "ssl.enabled-protocols") || strings.HasSuffix(k, "ssl.protocol"):
			for _, p := range splitList(e.value) {
				for _, m := range rules.EvalProtocol(p) {
					findings = append(findings, finding(m, path, e.line, evidence))
				}
			}
		case strings.HasSuffix(k, "ssl.ciphers") || strings.HasSuffix(k, "ssl.cipher-suites"):
			for _, c := range splitList(e.value) {
				for _, m := range rules.EvalCipherSuite(c) {
					findings = append(findings, finding(m, path, e.line, evidence))
				}
			}
		}
	}
	return findings, nil
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
