// Package main provides the command-line interface for GoEncryptAES.
// It supports three main commands: encrypt, decrypt, and genkey.
// All file path inputs are sanitized to prevent directory traversal attacks.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ryangarato/GoEncryptAES/aeslib"
)

// usage prints the command-line usage information to stderr.
func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
	fmt.Fprintf(flag.CommandLine.Output(), "  %s encrypt -in <file> -out <file> -key <keyfile> [-mode cbc|gcm]\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "  %s decrypt -in <file> -out <file> -key <keyfile> [-mode cbc|gcm]\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "  %s genkey -out <file> [-size 256]\n", os.Args[0])
	flag.PrintDefaults()
}

// main is the entry point for the CLI application.
// It routes commands to their respective handlers (encrypt, decrypt, genkey).
func main() {
	// Check for minimum required arguments
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	// Route to appropriate command handler
	cmd := os.Args[1]
	switch cmd {
	case "encrypt":
		encryptCmd(os.Args[2:])
	case "decrypt":
		decryptCmd(os.Args[2:])
	case "genkey":
		genkeyCmd(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

// encryptCmd handles the "encrypt" subcommand.
// It reads a plaintext file, encrypts it using the specified mode and key, and writes the ciphertext.
// Supports both CBC (with PKCS#7 padding) and GCM (authenticated encryption) modes.
func encryptCmd(args []string) {
	// Define flags for the encrypt command
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	in := fs.String("in", "", "input file path (plaintext)")
	out := fs.String("out", "", "output file path (ciphertext)")
	key := fs.String("key", "", "key file path (hex-encoded or raw bytes)")
	mode := fs.String("mode", aeslib.ModeCBC, "cipher mode (cbc or gcm)")
	fs.Usage = usage
	fs.Parse(args)

	// Validate required flags
	if *in == "" || *out == "" || *key == "" {
		fs.Usage()
		os.Exit(1)
	}

	// Sanitize file paths to prevent directory traversal attacks
	// Only allow relative paths (prevent absolute paths) and block ".." references
	cleanIn := filepath.Clean(*in)
	cleanOut := filepath.Clean(*out)
	cleanKey := filepath.Clean(*key)
	if filepath.IsAbs(cleanIn) || filepath.HasPrefix(cleanIn, "..") ||
		filepath.IsAbs(cleanOut) || filepath.HasPrefix(cleanOut, "..") ||
		filepath.IsAbs(cleanKey) || filepath.HasPrefix(cleanKey, "..") {
		fmt.Fprintf(os.Stderr, "invalid file path: absolute paths and directory traversal are not allowed\n")
		os.Exit(1)
	}

	// Perform encryption
	if err := aeslib.EncryptFile(cleanIn, cleanOut, cleanKey, *mode); err != nil {
		fmt.Fprintf(os.Stderr, "encryption failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("encryption complete, output=", *out)
}

// decryptCmd handles the "decrypt" subcommand.
// It reads a ciphertext file, decrypts it using the specified mode and key, and writes the plaintext.
// Supports both CBC and GCM modes. For GCM, the authentication tag is verified automatically.
func decryptCmd(args []string) {
	// Define flags for the decrypt command
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	in := fs.String("in", "", "input file path (ciphertext)")
	out := fs.String("out", "", "output file path (plaintext)")
	key := fs.String("key", "", "key file path (hex-encoded or raw bytes)")
	mode := fs.String("mode", aeslib.ModeCBC, "cipher mode (cbc or gcm)")
	fs.Usage = usage
	fs.Parse(args)

	// Validate required flags
	if *in == "" || *out == "" || *key == "" {
		fs.Usage()
		os.Exit(1)
	}

	// Sanitize file paths to prevent directory traversal attacks
	cleanIn := filepath.Clean(*in)
	cleanOut := filepath.Clean(*out)
	cleanKey := filepath.Clean(*key)
	if filepath.IsAbs(cleanIn) || filepath.HasPrefix(cleanIn, "..") ||
		filepath.IsAbs(cleanOut) || filepath.HasPrefix(cleanOut, "..") ||
		filepath.IsAbs(cleanKey) || filepath.HasPrefix(cleanKey, "..") {
		fmt.Fprintf(os.Stderr, "invalid file path: absolute paths and directory traversal are not allowed\n")
		os.Exit(1)
	}

	// Perform decryption
	if err := aeslib.DecryptFile(cleanIn, cleanOut, cleanKey, *mode); err != nil {
		fmt.Fprintf(os.Stderr, "decryption failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("decryption complete, output=", *out)
}

// genkeyCmd handles the "genkey" subcommand.
// It generates a cryptographically secure random key of the specified length (128, 192, or 256 bits)
// and writes it as hex-encoded text to the specified file with restricted permissions (0o600).
func genkeyCmd(args []string) {
	// Define flags for the genkey command
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := fs.String("out", "", "destination key file path")
	size := fs.Int("size", 256, "key length in bits (128, 192, or 256)")
	fs.Usage = usage
	fs.Parse(args)

	// Validate required flags
	if *out == "" {
		fs.Usage()
		os.Exit(1)
	}

	// Validate key size
	if *size != 128 && *size != 192 && *size != 256 {
		fmt.Fprintf(os.Stderr, "invalid key size %d: must be 128, 192, or 256 bits\n", *size)
		os.Exit(1)
	}

	// Sanitize the output path to prevent directory traversal
	cleanPath := filepath.Clean(*out)
	if filepath.IsAbs(cleanPath) || strings.Contains(cleanPath, "..") {
		fmt.Fprintf(os.Stderr, "invalid output path: absolute paths and directory traversal are not allowed\n")
		os.Exit(1)
	}

	// Additional security check: ensure the absolute path is within or below the current working directory
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid output path: %s\n", *out)
		os.Exit(1)
	}
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to determine working directory: %v\n", err)
		os.Exit(1)
	}
	if !strings.HasPrefix(absPath, wd) {
		fmt.Fprintf(os.Stderr, "invalid output path: file path would escape the current working directory\n")
		os.Exit(1)
	}

	// Generate the cryptographically secure random key
	key, err := aeslib.GenerateKey(*size)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key generation failed: %v\n", err)
		os.Exit(1)
	}

	// Write the key as hex-encoded string with restricted permissions (readable/writable by owner only)
	if err := os.WriteFile(cleanPath, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "unable to write key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("key written to", *out)
}
