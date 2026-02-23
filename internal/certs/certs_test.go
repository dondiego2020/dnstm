package certs

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test_cert.pem")
	keyPath := filepath.Join(tmpDir, "test_key.pem")
	domain := "test.example.com"

	fingerprint, err := GenerateCertificate(certPath, keyPath, domain)
	if err != nil {
		t.Fatalf("GenerateCertificate failed: %v", err)
	}

	// Fingerprint should be 64 hex characters (SHA256)
	if len(fingerprint) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(fingerprint))
	}

	// Should be valid hex
	_, err = hex.DecodeString(fingerprint)
	if err != nil {
		t.Errorf("fingerprint is not valid hex: %v", err)
	}

	// Files should exist
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("certificate file not found: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not found: %v", err)
	}

	// Key file should have restricted permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("key file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestGenerateCertificate_CertContent(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test_cert.pem")
	keyPath := filepath.Join(tmpDir, "test_key.pem")
	domain := "test.example.com"

	_, err := GenerateCertificate(certPath, keyPath, domain)
	if err != nil {
		t.Fatalf("GenerateCertificate failed: %v", err)
	}

	// Read and parse certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM type = %q, want 'CERTIFICATE'", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Verify certificate properties
	if cert.Subject.CommonName != domain {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, domain)
	}

	// Check SAN
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != domain {
		t.Errorf("DNSNames = %v, want [%q]", cert.DNSNames, domain)
	}

	// Check validity period (10 years)
	expectedExpiry := time.Now().AddDate(10, 0, 0)
	daysDiff := int(cert.NotAfter.Sub(expectedExpiry).Hours() / 24)
	if daysDiff < -1 || daysDiff > 1 {
		t.Errorf("NotAfter = %v, expected ~%v", cert.NotAfter, expectedExpiry)
	}

	// Check key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected KeyUsageDigitalSignature")
	}

	// Check extended key usage
	hasServerAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Error("expected ExtKeyUsageServerAuth")
	}

	// Verify it's ECDSA P-256
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
	}
}

func TestGenerateCertificate_KeyContent(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test_cert.pem")
	keyPath := filepath.Join(tmpDir, "test_key.pem")
	domain := "test.example.com"

	_, err := GenerateCertificate(certPath, keyPath, domain)
	if err != nil {
		t.Fatalf("GenerateCertificate failed: %v", err)
	}

	// Read and parse key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key: %v", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	if block.Type != "EC PRIVATE KEY" {
		t.Errorf("PEM type = %q, want 'EC PRIVATE KEY'", block.Type)
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse EC private key: %v", err)
	}

	// Verify it's P-256
	if key.Curve.Params().Name != "P-256" {
		t.Errorf("curve = %q, want 'P-256'", key.Curve.Params().Name)
	}
}

func TestGenerateCertificate_Uniqueness(t *testing.T) {
	tmpDir := t.TempDir()

	fingerprints := make(map[string]bool)
	for i := 0; i < 5; i++ {
		certPath := filepath.Join(tmpDir, "cert"+string(rune('0'+i))+".pem")
		keyPath := filepath.Join(tmpDir, "key"+string(rune('0'+i))+".pem")

		fingerprint, err := GenerateCertificate(certPath, keyPath, "test.example.com")
		if err != nil {
			t.Fatalf("GenerateCertificate failed: %v", err)
		}

		if fingerprints[fingerprint] {
			t.Errorf("duplicate fingerprint generated: %s", fingerprint)
		}
		fingerprints[fingerprint] = true
	}
}

func TestReadCertificateFingerprint(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test_cert.pem")
	keyPath := filepath.Join(tmpDir, "test_key.pem")
	domain := "test.example.com"

	expectedFingerprint, err := GenerateCertificate(certPath, keyPath, domain)
	if err != nil {
		t.Fatalf("GenerateCertificate failed: %v", err)
	}

	fingerprint, err := ReadCertificateFingerprint(certPath)
	if err != nil {
		t.Fatalf("ReadCertificateFingerprint failed: %v", err)
	}

	if fingerprint != expectedFingerprint {
		t.Errorf("fingerprint = %q, want %q", fingerprint, expectedFingerprint)
	}
}

func TestReadCertificateFingerprint_NotFound(t *testing.T) {
	_, err := ReadCertificateFingerprint("/nonexistent/path")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReadCertificateFingerprint_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "invalid.pem")

	if err := os.WriteFile(certPath, []byte("not valid pem"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := ReadCertificateFingerprint(certPath)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestCertsExist(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test_cert.pem")
	keyPath := filepath.Join(tmpDir, "test_key.pem")

	// Neither exists
	if CertsExist(certPath, keyPath) {
		t.Error("CertsExist should return false when files don't exist")
	}

	// Only cert exists
	if err := os.WriteFile(certPath, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if CertsExist(certPath, keyPath) {
		t.Error("CertsExist should return false when only cert exists")
	}

	// Both exist
	if err := os.WriteFile(keyPath, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if !CertsExist(certPath, keyPath) {
		t.Error("CertsExist should return true when both files exist")
	}
}

func TestGetOrCreateInDir(t *testing.T) {
	tmpDir := t.TempDir()
	domain := "test.example.com"

	// First call should create
	info1, err := GetOrCreateInDir(tmpDir, domain)
	if err != nil {
		t.Fatalf("GetOrCreateInDir failed: %v", err)
	}
	if info1 == nil {
		t.Fatal("expected non-nil CertInfo")
	}
	if info1.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
	if info1.CertPath != filepath.Join(tmpDir, "cert.pem") {
		t.Errorf("cert path = %q, want %q", info1.CertPath, filepath.Join(tmpDir, "cert.pem"))
	}

	// Second call should return same cert
	info2, err := GetOrCreateInDir(tmpDir, domain)
	if err != nil {
		t.Fatalf("GetOrCreateInDir (second call) failed: %v", err)
	}
	if info2.Fingerprint != info1.Fingerprint {
		t.Errorf("fingerprint changed: %q -> %q", info1.Fingerprint, info2.Fingerprint)
	}
}

func TestGetFromDir(t *testing.T) {
	tmpDir := t.TempDir()
	domain := "test.example.com"

	// Before generation
	info := GetFromDir(tmpDir)
	if info != nil {
		t.Error("expected nil before cert generation")
	}

	// After generation
	_, err := GenerateInDir(tmpDir, domain)
	if err != nil {
		t.Fatalf("GenerateInDir failed: %v", err)
	}

	info = GetFromDir(tmpDir)
	if info == nil {
		t.Fatal("expected non-nil after generation")
	}
	if info.CertPath != filepath.Join(tmpDir, "cert.pem") {
		t.Errorf("cert path = %q, want %q", info.CertPath, filepath.Join(tmpDir, "cert.pem"))
	}
}

func TestGenerateInDir(t *testing.T) {
	tmpDir := t.TempDir()
	domain := "test.example.com"

	info, err := GenerateInDir(tmpDir, domain)
	if err != nil {
		t.Fatalf("GenerateInDir failed: %v", err)
	}

	if info == nil {
		t.Fatal("expected non-nil CertInfo")
	}
	if len(info.Fingerprint) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(info.Fingerprint))
	}

	// Verify file paths
	if info.CertPath != filepath.Join(tmpDir, "cert.pem") {
		t.Errorf("cert path = %q, want %q", info.CertPath, filepath.Join(tmpDir, "cert.pem"))
	}
	if info.KeyPath != filepath.Join(tmpDir, "key.pem") {
		t.Errorf("key path = %q, want %q", info.KeyPath, filepath.Join(tmpDir, "key.pem"))
	}
}

func TestFormatFingerprint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			expected: "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF",
		},
		{
			input:    "invalid",
			expected: "invalid",
		},
		{
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := FormatFingerprint(tt.input)
			if result != tt.expected {
				t.Errorf("FormatFingerprint(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFormatFingerprint_UpperCase(t *testing.T) {
	input := "aabbccdd" + strings.Repeat("00", 28)
	result := FormatFingerprint(input)

	// Should be uppercase
	if strings.ContainsAny(result, "abcdef") {
		t.Errorf("FormatFingerprint should return uppercase, got %q", result)
	}
}
