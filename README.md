# GoEncryptAES

**GoEncryptAES** is a small, idiomatic Go library and command‑line utility for
AES encryption. The code is written with Go's standard library, follows the
language's conventions, and comes with both CBC and GCM modes, key management
helpers, and a simple CLI. Everything is MIT‑licensed.

---

## Quick start

### Install

```bash
# from the repository root
cd ~/GoEncryptAES
go install ./cmd/goencryptaes
```

The binary `goencryptaes` will be placed in your `$GOBIN` (or `$GOPATH/bin`).

### Commands

```text
Usage:
  goencryptaes encrypt -in <file> -out <file> -key <keyfile> [-mode cbc|gcm]
  goencryptaes decrypt -in <file> -out <file> -key <keyfile> [-mode cbc|gcm]
  goencryptaes genkey -out <file> [-size 256]
```

* `encrypt`: encrypts a file using AES (CBC or GCM). The key may be raw
  bytes or hex‑encoded; the command will accept either.
* `decrypt`: reverses an encryption operation.
* `genkey`: generates a secure random key and writes it (hex‑encoded) to the
  specified file.  Recommended sizes are 128, 192, or 256 bits.

Paths passed to the CLI are sanitized to prevent directory traversal issues.

### Example

```bash
goencryptaes genkey -out ~/keys/my.key -size 256
goencryptaes encrypt -in secret.txt -out secret.aes -key ~/keys/my.key -mode gcm
goencryptaes decrypt -in secret.aes -out secret.dec -key ~/keys/my.key -mode gcm
```

---

## Library usage

The `aeslib` package can be imported by other Go programs that need AES
capabilities. It exposes simple, test‑covered functions such as:

```go
key, _ := aeslib.GenerateKey(256)
ciphertext, _ := aeslib.Encrypt(plaintext, key, aeslib.ModeGCM)
cleartext, _ := aeslib.Decrypt(ciphertext, key, aeslib.ModeGCM)
```

Higher‑level helpers handle file I/O and key decoding (`EncryptFile` /
`DecryptFile`).

## Development & Testing

Run the unit tests with:

```bash
go test ./...
```

Adherence to Go tooling (vet, fmt, goimports) is encouraged.

---

### Package layout

```
cmd/goencryptaes    # CLI entrypoint
aeslib/              # reusable AES helpers and sanitization
```

By reorganizing the code into a library plus a main package and adding flags
and key generation, the project is more extensible, safer, and closer to a
professional Go project.
