[![CI](https://github.com/fire-lib/fire-crypto/actions/workflows/ci.yaml/badge.svg)](https://github.com/fire-lib/fire-crypto/actions/workflows/ci.yaml)
[![crates.io](https://img.shields.io/crates/v/fire-crypto)](https://crates.io/crates/fire-crypto)
[![docs.rs](https://img.shields.io/docsrs/fire-crypto)](https://docs.rs/fire-crypto)

## Crypto library

Fire crypto ought to be a simple to use crypto providing encryption and signing.

## Dependency

Main dependency is `dalek-cryptography`.

## Features
- `cipher` Enabling encryption and decryption
- `signature` Enabling signing and verifying
- `b64` Enabling base64 support
- `serde` Enabling serde support (needs `b64` to work)

## Not verified

This crate has not passed any verification and may contain bugs.