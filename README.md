# crypto-key-recovery-tool
Attempts to recover cryptographic keys from memory dumps or corrupted files using common key derivation functions and known plaintext attacks. Supports common algorithms like AES and RSA, allowing for targeted key recovery attempts. - Focused on Basic cryptographic operations

## Install
`git clone https://github.com/ShadowStrikeHQ/crypto-key-recovery-tool`

## Usage
`./crypto-key-recovery-tool [params]`

## Parameters
- `-h`: Show help message and exit
- `--algorithm`: No description provided
- `--key-length`: No description provided
- `--memory-dump`: Path to the memory dump file.
- `--ciphertext-file`: Path to the ciphertext file.
- `--known-plaintext-file`: Path to the known plaintext file for known plaintext attacks.
- `--password`: Password to attempt to derive key using PBKDF2
- `--salt`: No description provided
- `--iterations`: No description provided
- `--iv`: No description provided
- `--tag`: No description provided
- `--tag-length`: No description provided
- `--aad`: No description provided

## License
Copyright (c) ShadowStrikeHQ
