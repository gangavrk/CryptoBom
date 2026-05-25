// Package cbom renders findings as a CycloneDX CBOM (Cryptography Bill of
// Materials). Each distinct cryptographic asset becomes one cryptographic-asset
// component; every place it appears is recorded as an evidence occurrence.
package cbom

import (
	"crypto/rand"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/cryptobom/cryptobom/internal/rules"
	"github.com/cryptobom/cryptobom/internal/version"
)

// Emit writes a CycloneDX CBOM (JSON) for findings to w. target names the
// scanned path and is recorded as the BOM's subject component.
func Emit(w io.Writer, target string, findings []rules.Finding) error {
	bom := Build(target, findings)
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.Encode(bom)
}

// Build assembles the BOM in memory (separated from encoding for testability).
func Build(target string, findings []rules.Finding) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SerialNumber = newSerial()
	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    "cryptobom",
				Version: version.Version,
			}},
		},
		Component: &cdx.Component{
			Type: cdx.ComponentTypeApplication,
			Name: target,
		},
	}

	components := buildComponents(findings)
	bom.Components = &components
	return bom
}

// group accumulates occurrences of one asset (keyed by rule + algorithm + mode).
type group struct {
	key   string
	match rules.Match
	scope string
	occ   []cdx.EvidenceOccurrence
}

func buildComponents(findings []rules.Finding) []cdx.Component {
	byKey := map[string]*group{}
	var order []string
	for _, f := range findings {
		key := f.RuleID + "|" + f.Algorithm + "|" + f.Mode + "|" + paramSet(f.Match)
		if f.Scope != "" {
			key += "|" + f.Scope // keep test assets in their own component
		}
		g, ok := byKey[key]
		if !ok {
			g = &group{key: key, match: f.Match, scope: f.Scope}
			byKey[key] = g
			order = append(order, key)
		}
		line := f.Line
		g.occ = append(g.occ, cdx.EvidenceOccurrence{
			Location:          f.File,
			Line:              &line,
			Symbol:            f.RuleID,
			AdditionalContext: f.Evidence,
		})
	}

	sort.Strings(order)
	out := make([]cdx.Component, 0, len(order))
	for _, key := range order {
		out = append(out, componentFor(byKey[key]))
	}
	return out
}

func componentFor(g *group) cdx.Component {
	m := g.match

	occ := g.occ
	sort.Slice(occ, func(i, j int) bool {
		if occ[i].Location != occ[j].Location {
			return occ[i].Location < occ[j].Location
		}
		return *occ[i].Line < *occ[j].Line
	})

	props := []cdx.Property{
		{Name: "cryptobom:rule", Value: m.RuleID},
		{Name: "cryptobom:title", Value: m.Title},
		{Name: "cryptobom:severity", Value: string(m.Severity)},
		{Name: "cryptobom:category", Value: string(m.Category)},
	}
	if g.scope != "" {
		props = append(props, cdx.Property{Name: "cryptobom:scope", Value: g.scope})
	}
	if m.Detail != "" {
		props = append(props, cdx.Property{Name: "cryptobom:detail", Value: m.Detail})
	}
	if m.Remediation != "" {
		props = append(props, cdx.Property{Name: "cryptobom:remediation", Value: m.Remediation})
	}

	return cdx.Component{
		BOMRef:           g.key,
		Type:             cdx.ComponentTypeCryptographicAsset,
		Name:             assetName(m),
		CryptoProperties: cryptoProperties(m),
		Evidence:         &cdx.Evidence{Occurrences: &occ},
		Properties:       &props,
	}
}

// cryptoProperties builds the CBOM crypto-properties for a match: a protocol asset
// for TLS/SSL versions, otherwise an algorithm asset.
func cryptoProperties(m rules.Match) *cdx.CryptoProperties {
	switch m.AssetKind {
	case "protocol":
		return &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: &cdx.CryptoProtocolProperties{
				Type:    cdx.CryptoProtocolTypeTLS,
				Version: m.ProtocolVersion,
			},
		}
	case "certificate":
		return &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{
				SubjectName:   m.CertSubject,
				NotValidAfter: m.CertNotAfter,
			},
		}
	case "material":
		props := &cdx.RelatedCryptoMaterialProperties{
			Type: cdx.RelatedCryptoMaterialType(m.MaterialType),
		}
		if m.KeySize > 0 {
			size := m.KeySize
			props.Size = &size
		}
		return &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: props,
		}
	}

	fns := make([]cdx.CryptoFunction, 0, len(m.Functions))
	for _, fn := range m.Functions {
		fns = append(fns, cdx.CryptoFunction(fn))
	}
	algoProps := &cdx.CryptoAlgorithmProperties{
		Primitive:       primitive(m.Primitive),
		AlgorithmFamily: m.Algorithm,
	}
	if len(fns) > 0 {
		algoProps.CryptoFunctions = &fns
	}
	if mode := algoMode(m.Mode); mode != "" {
		algoProps.Mode = mode
	}
	if m.KeySize > 0 {
		algoProps.ParameterSetIdentifier = strconv.Itoa(m.KeySize)
	}
	if m.Curve != "" {
		algoProps.EllipticCurve = m.Curve
		if algoProps.ParameterSetIdentifier == "" {
			algoProps.ParameterSetIdentifier = m.Curve
		}
	}
	if m.ClassicalBits > 0 {
		bits := m.ClassicalBits
		algoProps.ClassicalSecurityLevel = &bits
	}
	return &cdx.CryptoProperties{
		AssetType:           cdx.CryptoAssetTypeAlgorithm,
		AlgorithmProperties: algoProps,
	}
}

// assetName names the component, including the key size when known (e.g. RSA-2048).
func assetName(m rules.Match) string {
	if m.AssetKind == "certificate" && m.CertSubject != "" {
		return "X.509: " + m.CertSubject
	}
	if m.KeySize > 0 {
		return fmt.Sprintf("%s-%d", m.Algorithm, m.KeySize)
	}
	return m.Algorithm
}

// paramSet returns the parameter that distinguishes one keyed asset from another
// (key size or curve), used in the component dedup key.
func paramSet(m rules.Match) string {
	if m.KeySize > 0 {
		return strconv.Itoa(m.KeySize)
	}
	return m.Curve
}

func primitive(s string) cdx.CryptoPrimitive {
	switch s {
	case "pke":
		return cdx.CryptoPrimitivePKE
	case "signature":
		return cdx.CryptoPrimitiveSignature
	case "hash":
		return cdx.CryptoPrimitiveHash
	case "block-cipher":
		return cdx.CryptoPrimitiveBlockCipher
	case "stream-cipher":
		return cdx.CryptoPrimitiveStreamCipher
	case "key-agree":
		return cdx.CryptoPrimitiveKeyAgree
	case "kem":
		return cdx.CryptoPrimitiveKEM
	case "mac":
		return cdx.CryptoPrimitiveMAC
	case "kdf":
		return cdx.CryptoPrimitiveKDF
	}
	return cdx.CryptoPrimitiveUnknown
}

func algoMode(s string) cdx.CryptoAlgorithmMode {
	switch s {
	case "ecb":
		return cdx.CryptoAlgorithmModeECB
	case "cbc":
		return cdx.CryptoAlgorithmModeCBC
	case "gcm":
		return cdx.CryptoAlgorithmModeGCM
	case "ctr":
		return cdx.CryptoAlgorithmModeCTR
	case "cfb":
		return cdx.CryptoAlgorithmModeCFB
	case "ofb":
		return cdx.CryptoAlgorithmModeOFB
	}
	return ""
}

func newSerial() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
