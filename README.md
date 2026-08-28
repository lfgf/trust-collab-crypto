# @kojinx/collab-crypto

> Zero-knowledge, audit-ready End-to-End Encryption (E2EE) cryptographic library for Kojinx Collaboration Hub.

Part of the **Kojinx Surgical Trust Module** architecture.

## Guarantees & Features

- **AES-256-GCM Symmetric Encryption**: Every message is encrypted with an isolated 256-bit session key using authenticating Galois/Counter Mode with fresh 96-bit (12-byte) initialization vectors (nonces).
- **Asymmetric Key Wrapping (RSA-OAEP SHA-256)**: Session keys are distributed using per-user public keys and can only be unwrapped locally by authorized private keys.
- **Safety Number Generator**: Deterministic SHA-256 identity verification numbers formatted in 6 blocks of 5 digits (Signal-style).
- **Zero Proprietary Dependencies**: Pure standard W3C Web Crypto API (`crypto.subtle`) + Angular `InjectionToken` inversion.
- **Cross-Platform**: Operates identically on Desktop (Tauri Rust Keyring) and Mobile (Capacitor/Web Crypto Secure Storage).

## Installation & Build

```bash
# Install dependencies
npm install

# Build library and sync to host application node_modules
npm run build

# Run unit test suite
npm test
```
