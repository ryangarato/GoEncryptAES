package aeslib

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptDecrypt is a round-trip test that verifies encryption and decryption work correctly.
// It tests all supported key sizes (128, 192, 256 bits) and cipher modes (CBC, GCM).
// For each combination, it encrypts plaintext and verifies the decrypted output matches the original.
func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("The quick brown fox jumps over the lazy dog")

	// Test all combinations of modes and key sizes
	for _, mode := range []string{ModeCBC, ModeGCM} {
		for _, size := range KeySize {
			// Generate a random key of the specified size
			key, err := GenerateKey(size)
			if err != nil {
				t.Fatalf("GenerateKey(%d) failed: %v", size, err)
			}

			// Encrypt the plaintext
			ct, err := Encrypt(plaintext, key, mode)
			if err != nil {
				t.Fatalf("Encrypt failed for mode %s size %d: %v", mode, size, err)
			}

			// Decrypt the ciphertext
			pt, err := Decrypt(ct, key, mode)
			if err != nil {
				t.Fatalf("Decrypt failed for mode %s size %d: %v", mode, size, err)
			}

			// Verify the decrypted plaintext matches the original
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("round trip mismatch for mode %s size %d: expected %q, got %q", mode, size, plaintext, pt)
			}
		}
	}
}

// TestFileHelpers tests the EncryptFile and DecryptFile functions.
// It creates temporary files, encrypts a plaintext file, and verifies that
// decryption recovers the original content.
func TestFileHelpers(t *testing.T) {
	// Create a temporary directory for test files
	tmp := t.TempDir()

	// Define file paths
	input := filepath.Join(tmp, "input.txt")
	output := filepath.Join(tmp, "output.bin")
	decrypted := filepath.Join(tmp, "decrypted.txt")
	keyfile := filepath.Join(tmp, "k.hex")

	// Create test input file
	testData := []byte("hello world")
	os.WriteFile(input, testData, 0o644)

	// Generate a test key and write it as hex
	key, _ := GenerateKey(256)
	os.WriteFile(keyfile, []byte(hex.EncodeToString(key)), 0o644)

	// Test file encryption (CBC mode)
	if err := EncryptFile(input, output, keyfile, ModeCBC); err != nil {
		t.Fatalf("EncryptFile error: %v", err)
	}

	// Test file decryption
	if err := DecryptFile(output, decrypted, keyfile, ModeCBC); err != nil {
		t.Fatalf("DecryptFile error: %v", err)
	}

	// Verify the decrypted content matches the original
	data, _ := os.ReadFile(decrypted)
	if string(data) != "hello world" {
		t.Fatalf("file roundtrip mismatch: expected 'hello world', got %q", string(data))
	}
}

// TestSanitizePath tests the path sanitization function.
// It verifies that:
// 1. Relative paths are converted to absolute paths
// 2. Directory traversal attempts (containing "..") are rejected
func TestSanitizePath(t *testing.T) {
	// Test that relative paths are converted to absolute
	ok, err := sanitizePath("./foo/bar.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(ok) {
		t.Fatal("expected absolute path")
	}

	// Test that directory traversal is rejected
	_, err = sanitizePath("../etc/passwd")
	if err == nil {
		t.Fatal("expected error for traversal attempt")
	}
}
