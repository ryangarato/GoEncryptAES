package aeslib

import (
	"crypto/aes"
	"errors"
)

// pkcs7Pad pads data to a multiple of blockSize using PKCS#7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytesRepeat(byte(padding), padding)
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS#7 padding, returning an error if the padding is invalid.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil, errors.New("invalid padding")
	}
	// verify all padding bytes are the same
	for _, v := range data[len(data)-padLen:] {
		if int(v) != padLen {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

// helper to avoid importing bytes package in hot path
func bytesRepeat(b byte, count int) []byte {
	if count <= 0 {
		return []byte{}
	}
	buf := make([]byte, count)
	for i := range buf {
		buf[i] = b
	}
	return buf
}
