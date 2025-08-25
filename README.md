# Dual Key Tunneling Protocol (DKTP)

## Introduction

[![Build](https://github.com/QRCS-CORP/DKTP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/DKTP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/DKTP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/DKTP/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/dktp/badge)](https://www.codefactor.io/repository/github/qrcs-corp/dktp)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/DKTP/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/DKTP/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/DKTP/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/DKTP)](https://github.com/QRCS-CORP/DKTP/releases/tag/2025-08-25)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/DKTP.svg)](https://github.com/QRCS-CORP/DKTP/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Communications&color=brightgreen)](#)

**DKTP is a next-generation tunnel protocol that achieves up to 512-bit cryptographic security by fusing asymmetric key exchange with directional pre-shared secrets. It enables post-quantum secure, mutually authenticated, high-assurance communications between peers without requiring PKI or persistent root trust.**

[DKTP Help Documentation](https://qrcs-corp.github.io/DKTP/docs/)  
[DKTP Protocol Specification](https://qrcs-corp.github.io/DKTP/docs/pdf/dktp_specification.pdf)  
[DKTP Summary Document](https://qrcs-corp.github.io/DKTP/docs/pdf/dktp_summary.pdf)

## Overview

DKTP combines post-quantum asymmetric key exchange, directional pre-shared secrets, and symmetric authenticated encryption to create a dual-entropy secure tunnel that offers:

- **Mutual authentication without a central certificate authority**
- **Forward and post-compromise secrecy**, with ratcheting PSKs
- **Separate transmit/receive channels**, each independently keyed
- **Capable of full 512-bit cryptographic strength**, RCS-512, SHAKE-512, SHA3-512, and KMAC-512
- **Perfect configuration binding** via signed session cookies

DKTP is especially suited for critical infrastructure, embedded systems, offline and sovereign networks, or any deployment needing long-term assurance without runtime PKI.

## Design Philosophy

DKTP was created to:

- **Eliminate legacy dependencies** by removing RSA, ECDH, X.509, and TLS-style complexity
- **Deliver full quantum resilience** using NIST-standardized asymmetric primitives and sponge-based symmetric constructs
- **Protect at every lifecycle phase**, from key exchange to session update, with multiple layers of entropy and ratchet progression
- **Enable secure tunnels in zero-trust and sovereign environments** where no centralized trust model is available

DKTP is implemented with deterministic, low-footprint logic suitable for embedded and high-assurance systems and verified using the QSC cryptographic library.

## Cryptographic Primitives

DKTP integrates post-quantum secure algorithms in all phases of the handshake and channel encryption process.

### Asymmetric Cryptography
- **Key Encapsulation:**
  - *McEliece:* Supports aggressive parameter sets (e.g., mceliece6960119, 400+ bits PQ security)
  - *Kyber:* Optional support using FIPS 203-compliant modes

- **Digital Signature:**
  - *SPHINCS+-SHAKE256 and SHAKE512 parameter sets*
  - *Dilithium*: Supported for faster signing where required

### Symmetric Cryptography
- **Cipher:**  
  - *RCS:* Wide-block AEAD stream cipher based on Rijndael with a cSHAKE key schedule and KMAC authentication, with dual-channel separation and strong entropy mixing

- **KDF / Hashing / MACs:**
  - *SHAKE* for all key derivation
  - *SHA3* for all cryptographic hashes and message structure integrity
  - *KMAC* for authenticated encryption and message validation

- **Entropy & Nonce:**  
  - Keccak-based PRNG + system randomness (via ACP)

## Protocol Overview

DKTP defines a six-stage tunnel lifecycle that includes:

1. **Connect Request** — client initiates with configuration string and signed session hash
2. **Connect Response** — server provides signed ephemeral key
3. **Exchange Request** — client encapsulates session secret
4. **Exchange Response** — server responds with reciprocal ciphertext and signature
5. **Establish Request** — client confirms tunnel keys via encrypted proof
6. **Establish Response** — server verifies and finalizes session state

Each session:
- Uses **ephemeral asymmetric key pairs**
- Mixes **static pre-shared keys** with **KEM-derived secrets**
- Generates **two symmetric keys**, one for each direction
- Evolves the PSK after each session using `psk' = H(psk || tck)`

This design achieves:
- **Directional keying**
- **Session separation**
- **Authentication binding**
- **Replay protection via timestamps**
- **Channel ratcheting for post-compromise recovery**

## Use Cases

- **Sovereign device-to-device tunnels** with no runtime key validation
- **Air-gapped infrastructure communications** (e.g., SCADA/ICS)
- **High-security enclave channels** for financial institutions or embedded OEMs
- **Hardware root-of-trust tunnels** using passphrase-unlocked PSK modules
- **Post-quantum secure VPN overlays** and tunnel brokers

DKTP can replace traditional PKI-bound VPNs, TLS-based client/server tunnels, or shared-key-only protocols like IPsec with a **next-generation mutual-auth, post-quantum secure, certificate-free tunnel**.

## Compilation and Deployment

DKTP is implemented using the QSC library for all cryptographic primitives. It supports compilation on:

- **Windows** (MSVC 2022+)
- **macOS** (Clang)
- **Linux** (GCC, Clang)

### Prerequisites

- **CMake** 3.15+
- **QSC** cryptographic library
- **AVX2/AVX-512** (recommended for best performance)

### Building DKTP

Use the included Visual Studio or Eclipse project files.

**Windows:**
- Open the solution
- Ensure QSC is referenced in client/server builds
- Match AVX instruction sets in debug/release configs

**Linux/macOS (Eclipse):**
- Use included `.project` and `.cproject` files
- Choose correct OS settings under `/Eclipse/Ubuntu` or `/Eclipse/MacOS`
- Compile QSC, then DKTP, then tunnel components

Example flag sets:

- `-msse2 -mavx2 -maes -mpclmul -mrdrnd -mbmi2` — AVX2+AES-NI
- `-mavx512f -mavx512bw -mvaes` — full AVX-512+VAES

## Keywords

Cryptography, Post-Quantum, Tunnel Protocol, Key Exchange, Dual-Entropy, Symmetric Ratchet, Mutual Authentication, SHAKE-512, KMAC, McEliece, SPHINCS+, RCS-512, Secure Communication, AVX, Embedded Security, Certificate-Free, High-Assurance, DKTP.

## License

ACQUISITION INQUIRIES:  
QRCS is actively seeking licensing or acquisition opportunities for this technology.  
Please contact: contact@qrcscorp.ca  

PATENT NOTICE:  
One or more patent applications covering DKTP have been filed.  
Unauthorized use may result in patent liability.

QRCS-PL private license. See license file for terms.  
Written by John G. Underhill, 2025. All rights reserved.  
Not for commercial redistribution without written authorization.
