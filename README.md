# GoEncryptAES

GoEncryptAES is an open-source implementation of AES-256 encryption using native Go libraries. This project is designed to provide secure, simple and easy-to-use file encryption. The code is free and open-source under the MIT license.

## Usage
The project provides two different applications, which are self-explanatory due to their names:

- `encrypt`
- `decrypt`

### Encrypt
The `encrypt` program encrypts a given file with AES-256 encryption. Both the initialization vector (IV) and the key used for encryption are generated at random during execution. This approach enhances the security of the encrypted file.

```bash
./encrypt original.file
```

After successful encryption, the program produces two files in the same directory as the input file. These are:

- The encrypted file of the original file, with the `.encrypted` extension.
- The key file with the `.key` extension.

### Decrypt

To decrypt a file, you will need the encrypted file generated during the encryption process. The key file is required only during the decryption process, so it should be stored securely until the need for decryption.

Run the `decrypt` executable file and provide the name of the encrypted file as a command-line argument:
```bash
./decrypt encrypted_file.encrypted
```

The `decrypt` program will look for the key file with the same name as the encrypted file, but with the `.key` extension. For example, if the encrypted file is named `my_file.encrypted`, the program will look for the key file named `my_file.key`.

Make sure the key file is in the same directory as the encrypted file before running the `decrypt` program. Once executed, the original file will be restored to its previous state in the same directory.


## Building from Source Code
To use GoEncryptAES, you need to have Go installed on your machine. After installing Go, you can clone this repository or download the source code to your local machine. Once the source code is available, navigate to the directory containing the code and run the following commands:

In the Encryption directory:
```go
go build encrypt.go
```

In the Decryption directory:
```go 
go build decrypt.go
```
