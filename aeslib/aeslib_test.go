package aeslib

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// round trip tests for both modes and key sizes
func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	for _, mode := range []string{ModeCBC, ModeGCM} {
		for _, size := range KeySize {
			key, err := GenerateKey(size)
			if err != nil {
				t.Fatalf("GenerateKey(%d) failed: %v", size, err)
			}
			ct, err := Encrypt(plaintext, key, mode)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			pt, err := Decrypt(ct, key, mode)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("round trip mismatch for mode %s size %d", mode, size)
			}
		}
	}
}

func TestFileHelpers(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, "input.txt")
	output := filepath.Join(tmp, "output.bin")
	decrypted := filepath.Join(tmp, "decrypted.txt")
	keyfile := filepath.Join(tmp, "k.hex")
	os.WriteFile(input, []byte("hello world"), 0o644)
	key, _ := GenerateKey(256)
	os.WriteFile(keyfile, []byte(hex.EncodeToString(key)), 0o644)

	if err := EncryptFile(input, output, keyfile, ModeCBC); err != nil {
		t.Fatalf("EncryptFile error: %v", err)
	}
	if err := DecryptFile(output, decrypted, keyfile, ModeCBC); err != nil {
		t.Fatalf("DecryptFile error: %v", err)
	}
	data, _ := os.ReadFile(decrypted)
	if string(data) != "hello world" {
		t.Fatalf("file roundtrip mismatch")
	}
}

func TestSanitizePath(t *testing.T) {
	ok, err := sanitizePath("./foo/bar.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(ok) {
		t.Fatal("expected absolute path")
	}
	if _, err := sanitizePath("../etc/passwd"); err == nil {
		t.Fatal("expected error for traversal")
	}
}
