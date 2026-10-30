package adminapi

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeKey(t *testing.T, key any) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadPrivateKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	got, err := LoadPrivateKey(writeKey(t, priv))
	if err != nil || !got.Equal(priv) {
		t.Fatalf("ed25519 key: %v", err)
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := LoadPrivateKey(writeKey(t, ec)); err == nil {
		t.Error("non-ed25519 key must be rejected")
	}

	bad := filepath.Join(t.TempDir(), "bad")
	_ = os.WriteFile(bad, []byte("not a key"), 0o600)
	if _, err := LoadPrivateKey(bad); err == nil {
		t.Error("garbage must be rejected")
	}
	if _, err := LoadPrivateKey(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file must error")
	}
}
