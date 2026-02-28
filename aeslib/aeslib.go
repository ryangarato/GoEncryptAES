// Package aeslib provides AES encryption and decryption utilities with support for CBC and GCM modes.
// It includes secure key generation, file-based encryption/decryption, and path sanitization
// to prevent directory traversal attacks.
package aeslib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Cipher mode constants.
const (
	ModeCBC = "cbc" // CBC (Cipher Block Chaining) mode
	ModeGCM = "gcm" // GCM (Galois/Counter Mode) mode with built-in authentication
)

// KeySize contains the valid AES key lengths in bits.
// AES supports 128, 192, and 256-bit keys.
var KeySize = []int{128, 192, 256}

// GenerateKey generates a cryptographically secure random AES key of the specified bit length.
// Valid key sizes are 128, 192, and 256 bits. The returned key length is keyBits/8 bytes.
// This function uses crypto/rand for secure random number generation.
//
// Returns an error if the requested key size is not supported.
func GenerateKey(keyBits int) ([]byte, error) {
	// Validate the requested key size against supported values
	valid := false
	for _, s := range KeySize {
		if s == keyBits {
			valid = true
			break
		}
	}
	if !valid {
		return nil, errors.New("invalid key size: must be 128, 192, or 256 bits")
	}

	// Convert bit length to byte length
	kb := keyBits / 8
	key := make([]byte, kb)

	// Fill the key with cryptographically secure random bytes
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES in the specified mode (CBC or GCM).
// For CBC mode: returns IV as a prefix followed by ciphertext
// For GCM mode: returns nonce as a prefix followed by ciphertext and authentication tag
// The mode parameter is case-insensitive.
//
// Returns an error if the key length is invalid or the mode is unsupported.
func Encrypt(plaintext, key []byte, mode string) ([]byte, error) {
	switch strings.ToLower(mode) {
	case ModeCBC:
		return encryptCBC(plaintext, key)
	case ModeGCM:
		return encryptGCM(plaintext, key)
	default:
		return nil, errors.New("unsupported cipher mode: must be 'cbc' or 'gcm'")
	}
}

// Decrypt decrypts ciphertext created by Encrypt, expecting the IV/nonce prefix.
// The ciphertext parameter must include the IV/nonce prefix produced by Encrypt.
// The mode parameter is case-insensitive and must match the mode used for encryption.
//
// Returns an error if decryption fails, padding is invalid, or authentication fails (GCM).
func Decrypt(ciphertext, key []byte, mode string) ([]byte, error) {
	switch strings.ToLower(mode) {
	case ModeCBC:
		return decryptCBC(ciphertext, key)
	case ModeGCM:
		return decryptGCM(ciphertext, key)
	default:
		return nil, errors.New("unsupported cipher mode: must be 'cbc' or 'gcm'")
	}
}

// encryptCBC encrypts plaintext using AES in CBC mode with PKCS#7 padding.
// It generates a random IV and prepends it to the ciphertext.
// Format: [IV (16 bytes)][encrypted data]
func encryptCBC(plaintext, key []byte) ([]byte, error) {
	// Create AES cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Apply PKCS#7 padding to the plaintext
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	// Allocate output: IV (16 bytes) + encrypted data
	ciphertext := make([]byte, aes.BlockSize+len(padded))
	iv := ciphertext[:aes.BlockSize]

	// Generate a cryptographically secure random IV
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt the padded plaintext using CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], padded)
	return ciphertext, nil
}

// decryptCBC decrypts CBC-encrypted ciphertext with PKCS#7 padding removal.
// It expects the IV to be prepended to the ciphertext.
// Format: [IV (16 bytes)][encrypted data]
func decryptCBC(ciphertext, key []byte) ([]byte, error) {
	// Ensure ciphertext is long enough to contain an IV
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short: minimum required is 16 bytes for IV")
	}

	// Extract IV and encrypted data
	iv := ciphertext[:aes.BlockSize]
	data := make([]byte, len(ciphertext)-aes.BlockSize)
	copy(data, ciphertext[aes.BlockSize:])

	// Create AES cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Verify encrypted data is a multiple of block size
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	// Decrypt using CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	// Remove PKCS#7 padding and return plaintext
	return pkcs7Unpad(data)
}

// encryptGCM encrypts plaintext using AES in GCM mode with authenticated encryption.
// GCM provides both confidentiality and authenticity.
// It generates a random nonce and prepends it to the ciphertext and auth tag.
// Format: [nonce (12 bytes)][encrypted data + auth tag]
func encryptGCM(plaintext, key []byte) ([]byte, error) {
	// Create AES cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM cipher mode (provides authenticated encryption)
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a cryptographically secure random nonce
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal encrypts plaintext and prepends nonce
	// g.Seal automatically appends the 16-byte authentication tag
	return g.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptGCM decrypts AES-GCM encrypted ciphertext with built-in authentication verification.
// It expects the nonce to be prepended to the ciphertext.
// Returns an error if authentication fails.
// Format: [nonce (12 bytes)][encrypted data + auth tag]
func decryptGCM(ciphertext, key []byte) ([]byte, error) {
	// Create AES cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM cipher mode
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract nonce size and verify ciphertext length
	nonceSize := g.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short: minimum required is 12 bytes for nonce")
	}

	// Extract nonce and encrypted data
	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]

	// Open decrypts and verifies the authentication tag
	// Will return an error if the authentication tag is invalid
	return g.Open(nil, nonce, data, nil)
}

// File-based encryption/decryption helpers

// EncryptFile reads plaintext from inputPath, encrypts it using the specified mode,
// and writes the ciphertext to outputPath.
// The key is read from keyPath; it can be either raw bytes or hex-encoded.
// If the key file contains hex-encoded data, it will be automatically decoded.
// An error is returned if any file operation fails or encryption fails.
func EncryptFile(inputPath, outputPath, keyPath, mode string) error {
	// Read plaintext from input file
	in, err := readFile(inputPath)
	if err != nil {
		return err
	}

	// Read and decode key from key file
	key, err := readKey(keyPath)
	if err != nil {
		return err
	}

	// Encrypt the plaintext
	ct, err := Encrypt(in, key, mode)
	if err != nil {
		return err
	}

	// Write ciphertext to output file with restricted permissions
	return os.WriteFile(outputPath, ct, 0o644)
}

// DecryptFile reads ciphertext from inputPath, decrypts it using the specified mode,
// and writes the plaintext to outputPath.
// The key is read from keyPath using the same logic as EncryptFile.
// An error is returned if any file operation fails or decryption fails.
func DecryptFile(inputPath, outputPath, keyPath, mode string) error {
	// Read ciphertext from input file
	ct, err := readFile(inputPath)
	if err != nil {
		return err
	}

	// Read and decode key from key file
	key, err := readKey(keyPath)
	if err != nil {
		return err
	}

	// Decrypt the ciphertext
	pt, err := Decrypt(ct, key, mode)
	if err != nil {
		return err
	}

	// Write plaintext to output file with restricted permissions
	return os.WriteFile(outputPath, pt, 0o644)
}

// Helper functions for internal use

// readFile safely reads a file after sanitizing the path to prevent directory traversal.
// Returns an error if the path is invalid or the file cannot be read.
func readFile(path string) ([]byte, error) {
	// Sanitize the path to prevent directory traversal attacks
	p, err := sanitizePath(path)
	if err != nil {
		return nil, err
	}
	// #nosec G304 - path has been sanitized by sanitizePath() above
	return os.ReadFile(p)
}

// readKey reads a key file and attempts to decode it if it's hex-encoded.
// If the key file contains hex-encoded data, it returns the decoded bytes.
// If hex decoding fails or the data doesn't look like hex, it returns the raw bytes.
// This allows flexibility in key file formats.
func readKey(path string) ([]byte, error) {
	// Read the key file (with path sanitization)
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	// Try to parse as hex-encoded string
	// Only attempt if data length is even (hex strings are always even length)
	if len(data)%2 == 0 {
		if decoded, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil {
			return decoded, nil
		}
	}

	// If hex decoding failed or data was odd-length, return raw bytes
	return data, nil
}

// sanitizePath converts a relative path to absolute and ensures it doesn't contain
// directory traversal attempts (e.g., ".."). This prevents security issues where
// paths could escape the intended directory.
// Returns an error if the path is empty or contains traversal attempts.
func sanitizePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path provided")
	}

	// Clean the path (removes redundant separators and . references)
	clean := filepath.Clean(p)

	// Reject paths containing ".." to prevent directory traversal
	if strings.Contains(clean, "..") {
		return "", errors.New("path contains parent directory traversal (..) which is not allowed")
	}

	// Convert to absolute path
	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", err
	}

	return abs, nil
}
