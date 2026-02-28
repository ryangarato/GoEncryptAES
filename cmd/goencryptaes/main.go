package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ryangarato/GoEncryptAES/aeslib"
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
	fmt.Fprintf(flag.CommandLine.Output(), "  %s encrypt -in <file> -out <file> -key <keyfile> [-mode cbc|gcm]\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "  %s decrypt -in <file> -out <file> -key <keyfile> [-mode cbc|gcm]\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "  %s genkey -out <file> [-size 256]\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
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

func encryptCmd(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	in := fs.String("in", "", "input file path")
	out := fs.String("out", "", "output file path")
	key := fs.String("key", "", "key file path (hex or raw)")
	mode := fs.String("mode", aeslib.ModeCBC, "cipher mode (cbc or gcm)")
	fs.Usage = usage
	fs.Parse(args)

	if *in == "" || *out == "" || *key == "" {
		fs.Usage()
		os.Exit(1)
	}

	// Validate paths to prevent directory traversal
	cleanIn := filepath.Clean(*in)
	cleanOut := filepath.Clean(*out)
	cleanKey := filepath.Clean(*key)
	if filepath.IsAbs(cleanIn) || filepath.HasPrefix(cleanIn, "..") ||
		filepath.IsAbs(cleanOut) || filepath.HasPrefix(cleanOut, "..") ||
		filepath.IsAbs(cleanKey) || filepath.HasPrefix(cleanKey, "..") {
		fmt.Fprintf(os.Stderr, "invalid file path\n")
		os.Exit(1)
	}

	if err := aeslib.EncryptFile(cleanIn, cleanOut, cleanKey, *mode); err != nil {
		fmt.Fprintf(os.Stderr, "encryption failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("encryption complete, output=", *out)
}

func decryptCmd(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	in := fs.String("in", "", "input ciphertext file path")
	out := fs.String("out", "", "output plaintext file path")
	key := fs.String("key", "", "key file path (hex or raw)")
	mode := fs.String("mode", aeslib.ModeCBC, "cipher mode (cbc or gcm)")
	fs.Usage = usage
	fs.Parse(args)

	if *in == "" || *out == "" || *key == "" {
		fs.Usage()
		os.Exit(1)
	}

	if err := aeslib.DecryptFile(*in, *out, *key, *mode); err != nil {
		fmt.Fprintf(os.Stderr, "decryption failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("decryption complete, output=", *out)
}

func genkeyCmd(args []string) {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := fs.String("out", "", "destination key file path")
	size := fs.Int("size", 256, "key length in bits (128,192,256)")
	fs.Usage = usage
	fs.Parse(args)

	if *out == "" {
		fs.Usage()
		os.Exit(1)
	}
	if *size != 128 && *size != 192 && *size != 256 {
		fmt.Fprintf(os.Stderr, "invalid key size %d\n", *size)
		os.Exit(1)
	}

	// Validate path to prevent directory traversal
	cleanPath := filepath.Clean(*out)
	if filepath.IsAbs(cleanPath) || filepath.HasPrefix(cleanPath, "..") {
		fmt.Fprintf(os.Stderr, "invalid output path: %s\n", *out)
		os.Exit(1)
	}

	key, err := aeslib.GenerateKey(*size)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key generation failed: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(cleanPath, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "unable to write key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("key written to", *out)
}
