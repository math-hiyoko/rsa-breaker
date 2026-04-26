# rsa-breaker

A CLI tool to recover RSA private keys from public keys.


## Features

- Parse RSA public keys (PEM / DER / OpenSSH)
- Attempt to recover private keys
- Output private keys in:
  - PKCS#1
  - PKCS#8
  - OpenSSH
- Automatic output filename generation

```bash
rsa-breaker --input ~/.ssh/id_rsa.pub --output ~/.ssh/id_rsa
```

## Installation

```bash
cargo install --git https://github.com/math-hiyoko/rsa-breaker.git
```
