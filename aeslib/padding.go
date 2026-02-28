package aeslib

import (
	"bytes"
	"crypto/aes"
	"errors"
)

// pkcs7Pad applies PKCS#7 padding to data to make it a multiple of blockSize.
// PKCS#7 padding adds N bytes of value N at the end, where N is the number of padding bytes needed.
// For example, if 3 bytes of padding are needed, it adds 3 bytes, each with value 0x03.
// This ensures the padding is always valid and unambiguous during removal.
func pkcs7Pad(data []byte, blockSize int) []byte {
	// Calculate the number of padding bytes needed
	// If data is already a multiple of blockSize, one full block of padding is added
	padding := blockSize - (len(data) % blockSize)

	// Create the padding bytes using bytes.Repeat, which is more idiomatic than a custom function
	// Each padding byte has the value equal to the total number of padding bytes
	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	// Append the padding to the original data and return
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS#7 padding from data.
// It verifies that all padding bytes are valid and consistent.
// Returns an error if the padding is invalid or corrupted.
//
// Padding validation checks:
// 1. Data is not empty
// 2. Padding length is between 1 and blockSize (16 for AES)
// 3. Padding length doesn't exceed data length
// 4. All padding bytes have the same value (equal to the padding length)
func pkcs7Unpad(data []byte) ([]byte, error) {
	// Ensure data is not empty
	if len(data) == 0 {
		return nil, errors.New("cannot unpad empty data")
	}

	// The last byte indicates the padding length
	padLen := int(data[len(data)-1])

	// Validate padding length constraints
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil, errors.New("invalid padding: length is invalid or corrupted")
	}

	// Verify all padding bytes have the same value as padLen
	// This ensures the padding wasn't corrupted
	for _, v := range data[len(data)-padLen:] {
		if int(v) != padLen {
			return nil, errors.New("invalid padding: bytes are inconsistent")
		}
	}

	// Return the data without the padding
	return data[:len(data)-padLen], nil
}
