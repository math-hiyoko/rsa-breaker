# rsa-breaker

A CLI tool to recover RSA private keys from public keys.


## ✨ Features

- Parse RSA public keys (PEM / DER / OpenSSH)
- Attempt to recover private keys
- Output private keys in:
  - PKCS#1
  - PKCS#8
  - OpenSSH (optional)
- Automatic output filename generation


## Installation

```bash
cargo install rsa-breaker
```
