package keys

import (
	"path/filepath"
)

// KeyInfo holds key information.
type KeyInfo struct {
	PrivateKeyPath string
	PublicKeyPath  string
	PublicKey      string
}

// GetOrCreateInDir returns existing key info from dir, or generates new keys.
func GetOrCreateInDir(dir string) (*KeyInfo, error) {
	info := GetFromDir(dir)
	if info != nil && info.PublicKey != "" {
		return info, nil
	}

	return GenerateInDir(dir)
}

// GetFromDir reads existing key info from dir, returns nil if not found.
func GetFromDir(dir string) *KeyInfo {
	privPath := filepath.Join(dir, "server.key")
	pubPath := filepath.Join(dir, "server.pub")

	if !KeysExist(privPath, pubPath) {
		return nil
	}

	pubKey, err := ReadPublicKey(pubPath)
	if err != nil {
		return nil
	}

	return &KeyInfo{
		PrivateKeyPath: privPath,
		PublicKeyPath:  pubPath,
		PublicKey:      pubKey,
	}
}

// GenerateInDir generates keys into dir/server.key and dir/server.pub.
func GenerateInDir(dir string) (*KeyInfo, error) {
	privPath := filepath.Join(dir, "server.key")
	pubPath := filepath.Join(dir, "server.pub")

	pubKey, err := Generate(privPath, pubPath)
	if err != nil {
		return nil, err
	}

	return &KeyInfo{
		PrivateKeyPath: privPath,
		PublicKeyPath:  pubPath,
		PublicKey:      pubKey,
	}, nil
}
