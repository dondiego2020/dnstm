package keys

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "test_server.key")
	pubPath := filepath.Join(tmpDir, "test_server.pub")

	pubKey, err := Generate(privPath, pubPath)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Public key should be 64 hex characters
	if len(pubKey) != 64 {
		t.Errorf("public key length = %d, want 64", len(pubKey))
	}

	// Should be valid hex
	_, err = hex.DecodeString(pubKey)
	if err != nil {
		t.Errorf("public key is not valid hex: %v", err)
	}

	// Files should exist
	if _, err := os.Stat(privPath); err != nil {
		t.Errorf("private key file not found: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Errorf("public key file not found: %v", err)
	}

	// Private key file should have restricted permissions
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("failed to stat private key: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("private key permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestGenerate_KeyFormat(t *testing.T) {
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "test_server.key")
	pubPath := filepath.Join(tmpDir, "test_server.pub")

	pubKey, err := Generate(privPath, pubPath)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Read files and verify format
	privData, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("failed to read private key: %v", err)
	}

	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("failed to read public key: %v", err)
	}

	// Both should be 64 hex chars + newline
	privHex := strings.TrimSpace(string(privData))
	pubHex := strings.TrimSpace(string(pubData))

	if len(privHex) != 64 {
		t.Errorf("private key length = %d, want 64", len(privHex))
	}
	if len(pubHex) != 64 {
		t.Errorf("public key length = %d, want 64", len(pubHex))
	}

	// Public key should match return value
	if pubHex != pubKey {
		t.Errorf("public key mismatch: file=%q, returned=%q", pubHex, pubKey)
	}
}

func TestGenerate_Uniqueness(t *testing.T) {
	tmpDir := t.TempDir()

	keys := make(map[string]bool)
	for i := 0; i < 10; i++ {
		privPath := filepath.Join(tmpDir, "test"+string(rune('0'+i))+"_server.key")
		pubPath := filepath.Join(tmpDir, "test"+string(rune('0'+i))+"_server.pub")

		pubKey, err := Generate(privPath, pubPath)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}

		if keys[pubKey] {
			t.Errorf("duplicate public key generated: %s", pubKey)
		}
		keys[pubKey] = true
	}
}

func TestReadPublicKey(t *testing.T) {
	tmpDir := t.TempDir()
	pubPath := filepath.Join(tmpDir, "test_server.pub")

	// Write a test key
	expectedKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(pubPath, []byte(expectedKey+"\n"), 0644); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}

	key, err := ReadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("ReadPublicKey failed: %v", err)
	}

	if key != expectedKey {
		t.Errorf("key = %q, want %q", key, expectedKey)
	}
}

func TestReadPublicKey_NotFound(t *testing.T) {
	_, err := ReadPublicKey("/nonexistent/path")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestKeysExist(t *testing.T) {
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "test_server.key")
	pubPath := filepath.Join(tmpDir, "test_server.pub")

	// Neither exists
	if KeysExist(privPath, pubPath) {
		t.Error("KeysExist should return false when files don't exist")
	}

	// Only private exists
	if err := os.WriteFile(privPath, []byte("test"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if KeysExist(privPath, pubPath) {
		t.Error("KeysExist should return false when only private key exists")
	}

	// Both exist
	if err := os.WriteFile(pubPath, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if !KeysExist(privPath, pubPath) {
		t.Error("KeysExist should return true when both files exist")
	}
}

func TestGetOrCreateInDir(t *testing.T) {
	tmpDir := t.TempDir()

	// First call should create
	info1, err := GetOrCreateInDir(tmpDir)
	if err != nil {
		t.Fatalf("GetOrCreateInDir failed: %v", err)
	}
	if info1 == nil {
		t.Fatal("expected non-nil KeyInfo")
	}
	if info1.PublicKey == "" {
		t.Error("expected non-empty public key")
	}
	if info1.PrivateKeyPath != filepath.Join(tmpDir, "server.key") {
		t.Errorf("private key path = %q, want %q", info1.PrivateKeyPath, filepath.Join(tmpDir, "server.key"))
	}

	// Second call should return same key
	info2, err := GetOrCreateInDir(tmpDir)
	if err != nil {
		t.Fatalf("GetOrCreateInDir (second call) failed: %v", err)
	}
	if info2.PublicKey != info1.PublicKey {
		t.Errorf("public key changed: %q -> %q", info1.PublicKey, info2.PublicKey)
	}
}

func TestGetFromDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Before generation
	info := GetFromDir(tmpDir)
	if info != nil {
		t.Error("expected nil before key generation")
	}

	// After generation
	_, err := GenerateInDir(tmpDir)
	if err != nil {
		t.Fatalf("GenerateInDir failed: %v", err)
	}

	info = GetFromDir(tmpDir)
	if info == nil {
		t.Fatal("expected non-nil after generation")
	}
	if info.PrivateKeyPath != filepath.Join(tmpDir, "server.key") {
		t.Errorf("private key path = %q, want %q", info.PrivateKeyPath, filepath.Join(tmpDir, "server.key"))
	}
}

func TestGenerateInDir(t *testing.T) {
	tmpDir := t.TempDir()

	info, err := GenerateInDir(tmpDir)
	if err != nil {
		t.Fatalf("GenerateInDir failed: %v", err)
	}

	if info == nil {
		t.Fatal("expected non-nil KeyInfo")
	}
	if len(info.PublicKey) != 64 {
		t.Errorf("public key length = %d, want 64", len(info.PublicKey))
	}

	// Verify file paths
	if info.PrivateKeyPath != filepath.Join(tmpDir, "server.key") {
		t.Errorf("private key path = %q, want %q", info.PrivateKeyPath, filepath.Join(tmpDir, "server.key"))
	}
	if info.PublicKeyPath != filepath.Join(tmpDir, "server.pub") {
		t.Errorf("public key path = %q, want %q", info.PublicKeyPath, filepath.Join(tmpDir, "server.pub"))
	}
}
