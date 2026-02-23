package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/net2share/dnstm/internal/system"
)

// CertInfo holds certificate information.
type CertInfo struct {
	CertPath    string
	KeyPath     string
	Fingerprint string
}

// GetOrCreateInDir returns existing certificate info from dir, or generates a new one.
func GetOrCreateInDir(dir, domain string) (*CertInfo, error) {
	info := GetFromDir(dir)
	if info != nil && info.Fingerprint != "" {
		return info, nil
	}

	return GenerateInDir(dir, domain)
}

// GetFromDir reads existing cert info from dir, returns nil if not found.
func GetFromDir(dir string) *CertInfo {
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if !CertsExist(certPath, keyPath) {
		return nil
	}

	fingerprint, err := ReadCertificateFingerprint(certPath)
	if err != nil {
		return nil
	}

	return &CertInfo{
		CertPath:    certPath,
		KeyPath:     keyPath,
		Fingerprint: fingerprint,
	}
}

// GenerateInDir generates a certificate into dir/cert.pem and dir/key.pem.
func GenerateInDir(dir, domain string) (*CertInfo, error) {
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	fingerprint, err := GenerateCertificate(certPath, keyPath, domain)
	if err != nil {
		return nil, err
	}

	return &CertInfo{
		CertPath:    certPath,
		KeyPath:     keyPath,
		Fingerprint: fingerprint,
	}, nil
}

// GenerateCertificate creates a self-signed ECDSA P-256 certificate.
func GenerateCertificate(certPath, keyPath, domain string) (fingerprint string, err error) {
	if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
		return "", fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Generate ECDSA P-256 private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"DNSTM Router"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years validity
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Calculate SHA256 fingerprint
	hash := sha256.Sum256(certDER)
	fingerprint = hex.EncodeToString(hash[:])

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	// Write certificate file
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return "", fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write key file
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", fmt.Errorf("failed to write private key: %w", err)
	}

	// Set ownership to dnstm user so the service can read the certs
	if err := system.ChownToDnstm(certPath); err != nil {
		// Non-fatal: log but continue (user might not exist yet)
		_ = err
	}
	if err := system.ChownToDnstm(keyPath); err != nil {
		_ = err
	}
	// Also chown the directory
	if err := system.ChownToDnstm(filepath.Dir(certPath)); err != nil {
		_ = err
	}

	return fingerprint, nil
}

// ReadCertificateFingerprint reads a certificate and returns its SHA256 fingerprint.
func ReadCertificateFingerprint(certPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:]), nil
}

// CertsExist checks if both certificate files exist.
func CertsExist(certPath, keyPath string) bool {
	_, err1 := os.Stat(certPath)
	_, err2 := os.Stat(keyPath)
	return err1 == nil && err2 == nil
}

// FormatFingerprint formats a fingerprint for display (with colons).
func FormatFingerprint(fingerprint string) string {
	if len(fingerprint) != 64 {
		return fingerprint
	}

	result := ""
	for i := 0; i < len(fingerprint); i += 2 {
		if i > 0 {
			result += ":"
		}
		result += strings.ToUpper(fingerprint[i : i+2])
	}
	return result
}
