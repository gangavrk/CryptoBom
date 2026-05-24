package main

import "testing"

func TestIsTestFile(t *testing.T) {
	tests := map[string]bool{
		"foo_test.go":            true,
		"server.go":              false,
		"test_crypto.py":         true,
		"crypto_test.py":         true,
		"conftest.py":            true,
		"crypto_samples.py":      false,
		"CryptoSamplesTest.java": true,
		"FooTests.kt":            true,
		"PaymentServiceTest.cs":  true,
		"CryptoSamples.java":     false,
		"Manifest.java":          false, // must not be mistaken for a *Test file
	}
	for name, want := range tests {
		if got := isTestFile(name); got != want {
			t.Errorf("isTestFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestIsTestDir(t *testing.T) {
	for _, name := range []string{"test", "tests", "testdata", "__tests__"} {
		if !isTestDir(name) {
			t.Errorf("isTestDir(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"src", "main", "internal", "latest"} {
		if isTestDir(name) {
			t.Errorf("isTestDir(%q) = true, want false", name)
		}
	}
}
