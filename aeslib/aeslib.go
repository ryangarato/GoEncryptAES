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

const (
	ModeCBC = "cbc"
	ModeGCM = "gcm"
)

// KeySize enumerates valid key lengths (in bits).
var KeySize = []int{128, 192, 256}

// GenerateKey returns a randomly generated key with the requested bit length.
// Supported sizes are 128, 192, and 256 bits. The returned slice has size keyBits/8.
func GenerateKey(keyBits int) ([]byte, error) {
	valid := false
	for _, s := range KeySize {
		if s == keyBits {
			valid = true
			break
		}
	}
	if !valid {
		return nil, errors.New("invalid key size")
	}
	kb := keyBits / 8
	key := make([]byte, kb)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES in the given mode. The returned ciphertext
// contains any IV/nonce as a prefix so it can be passed directly to Decrypt.
func Encrypt(plaintext, key []byte, mode string) ([]byte, error) {
	switch strings.ToLower(mode) {
	case ModeCBC:
		return encryptCBC(plaintext, key)
	case ModeGCM:
		return encryptGCM(plaintext, key)
	default:
		return nil, errors.New("unsupported mode")
	}
}

// Decrypt undoes Encrypt. The ciphertext must include the IV/nonce prefix
// produced by Encrypt.
func Decrypt(ciphertext, key []byte, mode string) ([]byte, error) {
	switch strings.ToLower(mode) {
	case ModeCBC:
		return decryptCBC(ciphertext, key)
	case ModeGCM:
		return decryptGCM(ciphertext, key)
	default:
		return nil, errors.New("unsupported mode")
	}
}

// internal helpers --------------------------------------------------------

func encryptCBC(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize+len(padded))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], padded)
	return ciphertext, nil
}

func decryptCBC(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	data := make([]byte, len(ciphertext)-aes.BlockSize)
	copy(data, ciphertext[aes.BlockSize:])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return pkcs7Unpad(data)
}

func encryptGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptGCM(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := g.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]
	return g.Open(nil, nonce, data, nil)
}

// File-based helpers -------------------------------------------------------

// EncryptFile reads inputPath, encrypts it and writes to outputPath. The key
// is read from keyPath; if keyPath points to a hex-encoded key it will be
// decoded automatically.
func EncryptFile(inputPath, outputPath, keyPath, mode string) error {
	in, err := readFile(inputPath)
	if err != nil {
		return err
	}
	key, err := readKey(keyPath)
	if err != nil {
		return err
	}
	ct, err := Encrypt(in, key, mode)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, ct, 0o644)
}

// DecryptFile reads ciphertext from inputPath, decrypts it and writes
// plaintext to outputPath. The key is loaded the same way as in EncryptFile.
func DecryptFile(inputPath, outputPath, keyPath, mode string) error {
	ct, err := readFile(inputPath)
	if err != nil {
		return err
	}
	key, err := readKey(keyPath)
	if err != nil {
		return err
	}
	pt, err := Decrypt(ct, key, mode)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, pt, 0o644)
}

// Helpers ------------------------------------------------------------------

func readFile(path string) ([]byte, error) {
	p, err := sanitizePath(path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func readKey(path string) ([]byte, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	// try to parse hex
	if len(data)%2 == 0 {
		if decoded, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil {
			return decoded, nil
		}
	}
	return data, nil
}

func sanitizePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	clean := filepath.Clean(p)
	if strings.Contains(clean, "..") {
		return "", errors.New("path contains parent directory traversal")
	}
	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", err
	}
	return abs, nil
}
