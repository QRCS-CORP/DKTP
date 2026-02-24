# Dual Key Tunneling Protocol (DKTP)

[![Build](https://github.com/QRCS-CORP/DKTP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/DKTP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/DKTP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/DKTP/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/dktp/badge)](https://www.codefactor.io/repository/github/qrcs-corp/dktp)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/DKTP/security/policy)
[![License: QRCS-PREL](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/DKTP/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![Docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/DKTP/)
[![Release](https://img.shields.io/github/v/release/QRCS-CORP/DKTP)](https://github.com/QRCS-CORP/DKTP/releases/tag/2025-08-25)
[![Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/DKTP.svg)](https://github.com/QRCS-CORP/DKTP/commits/main)
[![Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Communications&color=brightgreen)](#)

**DKTP is a next-generation tunnel protocol achieving 512-bit post-quantum cryptographic security by fusing asymmetric key exchange with directional pre-shared secrets. It provides mutually authenticated, high-assurance communications between peers without requiring PKI or persistent root trust.**

---

## Documentation

| Document | Description |
|---|---|
| [Help Documentation](https://qrcs-corp.github.io/DKTP/) | Full API and integration reference |
| [Summary](https://qrcs-corp.github.io/DKTP/pdf/dktp_summary.pdf) | Protocol overview and design rationale |
| [Protocol Specification](https://qrcs-corp.github.io/DKTP/pdf/dktp_specification.pdf) | Formal message and state machine specification |
| [Formal Analysis](https://qrcs-corp.github.io/DKTP/pdf/dktp_formal.pdf) | Cryptographic security proofs and model |
| [Implementation Analysis](https://qrcs-corp.github.io/DKTP/pdf/dktp_analysis.pdf) | Code-level security analysis |
| [Integration Guide](https://qrcs-corp.github.io/DKTP/pdf/dktp_integration.pdf) | Deployment and integration guidance |

---

## Overview

DKTP combines post-quantum asymmetric key exchange, directional pre-shared secrets, and symmetric authenticated encryption into a dual-entropy secure tunnel. Core properties:

- **Mutual authentication** without a central certificate authority or PKI
- **Forward and post-compromise secrecy** with ratcheting pre-shared secrets
- **Separate transmit and receive channels**, each independently keyed and authenticated
- **512-bit cryptographic strength** throughout: RCS-512, SHAKE-512, SHA3-512, and KMAC-512
- **Perfect configuration binding** via signed session transcript hashes
- **Certificate-free operation**, suited to sovereign, air-gapped, and zero-trust deployments

---

## Design Goals

DKTP was designed to address the limitations of legacy secure transport protocols:

- **Eliminate legacy dependencies** — no RSA, ECDH, X.509, or TLS-style certificate chains
- **Full quantum resilience** — all asymmetric operations use NIST-standardized post-quantum primitives
- **Lifecycle-wide protection** — multiple entropy layers and ratchet progression from key exchange through session update
- **Zero-trust and sovereign operation** — no centralized trust model, no runtime key validation infrastructure required
- **Deterministic, low-footprint implementation** — suitable for embedded and high-assurance systems

---

## Cryptographic Primitives

### Key Encapsulation (KEM)

| Algorithm | Parameter Sets | Security Level |
|---|---|---|
| Classic McEliece | mceliece6960119 and others | 400+ bits post-quantum |
| ML-KEM (Kyber) | FIPS 203-compliant modes | 128–256 bits post-quantum |

### Digital Signatures

| Algorithm | Notes |
|---|---|
| SPHINCS+ | SHAKE-256 and SHAKE-512 parameter sets; stateless hash-based |
| ML-DSA (Dilithium) | Available for lower-latency signing requirements |

### Symmetric Cryptography

| Primitive | Role |
|---|---|
| RCS-512 | Wide-block AEAD stream cipher; Rijndael with cSHAKE key schedule and KMAC authentication |
| SHAKE-512 | Key derivation and session secret expansion |
| SHA3-512 | Transcript hashing and message integrity |
| KMAC-512 | Authenticated encryption tags and message validation |
| ACP (Keccak-based PRNG) | Entropy generation and nonce production |

---

## Protocol Lifecycle

DKTP defines a six-stage handshake establishing a fully authenticated, dual-channel encrypted session.
```
Client                                          Server
  |                                               |
  |──── (1) Connect Request ──────────────────>  |  Client sends signed config hash and key ID
  |<─── (2) Connect Response ─────────────────── |  Server returns signed ephemeral public key
  |                                               |
  |──── (3) Exchange Request ──────────────────> |  Client encapsulates session secret
  |<─── (4) Exchange Response ────────────────── |  Server returns reciprocal ciphertext and signature
  |                                               |
  |──── (5) Establish Request ─────────────────> |  Client sends encrypted transcript proof
  |<─── (6) Establish Response ───────────────── |  Server verifies and finalizes session keys
  |                                               |
  |<══════════ Encrypted Session ══════════════> |  Dual-channel RCS-512 with symmetric ratchet
```

Each session uses ephemeral asymmetric key pairs and mixes static pre-shared secrets with KEM-derived material to produce two independent symmetric channel keys. After session completion the pre-shared secret is evolved as `psk' = H(psk || session_key)`, providing forward secrecy and post-compromise recovery.

---

## Security Properties

| Property | Mechanism |
|---|---|
| Mutual authentication | Signature verification on both sides during handshake |
| Forward secrecy | Ephemeral KEMs; PSK ratcheted after every session |
| Post-compromise secrecy | Symmetric ratchet continuously refreshes channel keys |
| Replay protection | Packet timestamps validated against a configurable window |
| Channel separation | Independent TX and RX keys derived with domain-separated cSHAKE |
| Configuration binding | Session cookie commits to both peers' configuration strings |
| Transcript integrity | Incremental transcript hash bound through all six KEX stages |

---

## Quick Start (Windows)

The following steps bring up a local loopback connection between the Listener and Sender projects using Visual Studio.

**Step 1 — Start the Listener**

Set the DKTP Listener as the startup project and run it. On first launch it will generate a keypair and display the peering key path:
```
listener> The remote peer-key was not detected, generating a new local/remote keypair...
listener> The peering key has been saved to
          C:\Users\<username>\Documents\DKTP\Listener\listener_remote_peer_key.dpkey
listener> Distribute the peering key to intended host, and generate the remote peer key.
listener> Enter the path of the sender's peering key:
```

Copy the displayed key path. The Listener is now waiting for the Sender's peering key.

**Step 2 — Start the Sender**

Right-click the DKTP Sender project in Solution Explorer and select **Debug → Start New Instance**. Follow the prompts:
```
sender> Enter the destination IPv4 address, ex. 192.168.1.1
```

Enter the loopback address `127.0.0.1`.
```
sender> Enter the path of the listener's peering key:
```

Paste in the Listener key path from Step 1. The Sender will generate its own keypair:
```
sender> The private-key was not detected, generating a new private/public keypair...
sender> The peering key has been saved to
        C:\Users\<username>\Documents\DKTP\Sender\sender_remote_peer_key.dpkey
sender> Load the peering key on the listener host.
sender> Load the remote-peer key on the server before connecting.
```

Copy the Sender key path displayed in the console.

**Step 3 — Exchange keys**

Return to the Listener console and paste in the Sender key path at the prompt. The Listener will confirm both keys are loaded:
```
listener> waiting for a connection...
```

**Step 4 — Connect**

Return to the Sender console:
```
sender> Connect to remote host (Y|N)?
```

Type `Y` and press Enter. The Sender and Listener are now connected through a fully authenticated, post-quantum encrypted channel.

---

## Building

DKTP is implemented in C23 using the QSC cryptographic library for all primitives.

### Supported Platforms

| Platform | Compiler |
|---|---|
| Windows | MSVC 2022+ |
| Linux | GCC, Clang |
| macOS | Clang |

### Windows (MSVC)

The Visual Studio solution contains three projects: **DKTP** (library), **Listener**, and **Sender**. The DKTP library is expected in a folder parallel to the Listener and Sender project folders.

> **Critical:** The `Enable Enhanced Instruction Set` property must be set to the **same value** across the QSC library, the DKTP library, and every application project (Listener, Sender) in both Debug and Release configurations. Mismatched intrinsics settings produce ABI-incompatible struct layouts and are a source of undefined behavior.

**Build order:**
1. Build the **QSC** library
2. Build the **DKTP** library
3. Build **Listener** and **Sender**

**Include path configuration:**

If the library files are not at their default locations, update the include paths in each project under:
`Configuration Properties → C/C++ → General → Additional Include Directories`

Default paths:
- `$(SolutionDir)DKTP`
- `$(SolutionDir)..\QSC\QSC`

Ensure each application project's **References** property includes the DKTP library, and that the DKTP library references the QSC library.

### Linux and macOS

Use the included Eclipse `.project` and `.cproject` files. Select the correct OS configuration under `/Eclipse/Ubuntu` or `/Eclipse/MacOS`. Build QSC first, then DKTP, then the tunnel components.

**Recommended compiler flags:**
```bash
# AVX2 with AES-NI
-msse2 -mavx2 -maes -mpclmul -mrdrnd -mbmi2

# Full AVX-512 with VAES
-mavx512f -mavx512bw -mvaes
```

---

## Use Cases

- **Sovereign device-to-device tunnels** requiring no runtime key validation infrastructure
- **Air-gapped networks** (SCADA, ICS, OT environments) needing long-term quantum-resistant security
- **High-security enclave communications** for financial institutions, defence, and critical infrastructure
- **Hardware root-of-trust channels** using passphrase-unlocked PSK modules
- **Post-quantum VPN overlays** replacing TLS or IPsec where PKI is unavailable or undesirable
- **Embedded and constrained systems** requiring a deterministic, low-footprint secure transport

---

## License and Patent Notice

This software is published under the **Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025–2026**.

This license permits **non-commercial evaluation, academic research, cryptographic analysis, interoperability testing, and feasibility assessment only**. Production deployment, commercial use, and incorporation into products or services require a separate written license agreement.

> **Patent Notice:** One or more patent applications covering DKTP have been filed. Unauthorized commercial use may result in patent liability.

For licensing, supported builds, or commercial integration: **licensing@qrcscorp.ca**  
For investment inquiries: **contact@qrcscorp.ca**  
Full product portfolio: [qrcscorp.ca](https://www.qrcscorp.ca)

*© 2026 Quantum Resistant Cryptographic Solutions Corporation. All rights reserved.*