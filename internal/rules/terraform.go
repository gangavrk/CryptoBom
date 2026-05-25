package rules

import "strings"

// AWSTLSPolicy maps an AWS ELB/CloudFront TLS security-policy name to matches.
// Policy names encode the minimum TLS version (e.g. ELBSecurityPolicy-TLS-1-1-2017-01,
// and the legacy date-only policies that still allow TLS 1.0).
func AWSTLSPolicy(name string) []Match {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "tls-1-0"):
		return EvalProtocol("TLSv1.0")
	case strings.Contains(l, "tls-1-1"):
		return EvalProtocol("TLSv1.1")
	case l == "elbsecuritypolicy-2015-05" || l == "elbsecuritypolicy-2016-08" ||
		l == "elbsecuritypolicy-2015-03":
		return EvalProtocol("TLSv1.0") // legacy date-only policies allow TLS 1.0
	}
	return nil
}

// KMSKeySpec maps an AWS KMS key spec (RSA_2048, ECC_NIST_P256, …) to matches. RSA
// and ECC keys are quantum-vulnerable; symmetric/HMAC specs produce nothing.
func KMSKeySpec(spec string) []Match {
	u := strings.ToUpper(strings.TrimSpace(spec))
	switch {
	case strings.HasPrefix(u, "RSA_"):
		return AnnotateKey(evalKeyPairGen("RSA"), digits(u[4:]), "")
	case strings.HasPrefix(u, "ECC_"):
		curve := u[strings.LastIndex(u, "_")+1:] // P256 / P384 / P521 / P256K1
		return AnnotateKey(evalKeyPairGen("EC"), 0, curve)
	}
	return nil
}

// digits parses a leading run of digits, e.g. "2048" -> 2048, "" / non-digits -> 0.
func digits(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}
