/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef DKTP_DOXYMAIN_H
#define DKTP_DOXYMAIN_H

/**
 * \mainpage Dual Key Tunneling Protocol (DKTP)
 *
 * \section intro_sec Introduction
 *
 * In today's digital landscape, numerous key exchange protocols are widely used; examples include the mechanisms
 * found in secure networking protocols such as TLS, PGP, and SSH. These protocols define methods for exchanging
 * secret keys between devices, typically as part of a larger scheme that also incorporates authentication and
 * establishes an encrypted tunnel for communication. In such systems, the shared secret is used to key symmetric
 * ciphers for encrypting and decrypting traffic.
 *
 * \section dktp_sec About DKTP
 *
 * DKTP is a complete specification that not only defines a robust key exchange function but also integrates
 * authentication mechanisms and an encrypted tunnel within a single protocol. Rather than retrofitting existing
 * schemes with quantum-strength primitives, DKTP breaks new ground by introducing an entirely new set of mechanisms
 * designed from the ground up for security and performance in the post-quantum era.
 *
 * \section design_sec Design Philosophy
 *
 * Recognizing that a large-scale migration to post-quantum cryptography is inevitable, DKTP was developed without
 * the constraints of backward compatibility or the unnecessary complexity of legacy protocols. This new design
 * avoids artifacts from older systems, such as outdated APIs, cumbersome versioning, and compatibility issues, and
 * instead focuses on modern, streamlined solutions.
 *
 * \section crypto_sec Cryptographic Primitives
 *
 * DKTP employs state-of-the-art cryptographic algorithms to ensure high levels of security:
 *
 * - **Asymmetric Ciphers:** DKTP supports the Kyber and McEliece asymmetric ciphers with the full range of parameter sets.
 * - **Signature Schemes:** DKTP can use Dilithium or Sphincs+ signature schemes, which were both standardized by NIST.
 * - **Symmetric Cipher:** For symmetric encryption, DKTP uses the authenticated symmetric stream cipher RCS,
 *   which is based on the wide-block Rijndael cipher. This cipher is enhanced with increased rounds, a strong key-schedule,
 *   and AEAD authentication using KMAC or QMAC message authentication functions.
 *
 * \section protocol_spec Protocol Specifications
 *
 * DKTP defines a complete protocol specification that caters to varying trust and performance requirements:
 *
 * - The DKTP protocol implements a bi-directional trust model.
 *   Both hosts authenticate each other by exchanging signed public asymmetric cipher keys and verifying them using
 *   pre-shared public signature-verification keys. Each host then creates and exchanges a shared secret, and these
 *   secrets are combined to key 512-bit secure symmetric cipher instances. The DKTP protocol is best suited for
 *   high-security communications between remote hosts.
 *
 * DKTP offers a modern, flexible, and secure alternative to traditional key exchange protocols that are now being
 * retrofitted with quantum-safe algorithms. Designed specifically for the post-quantum era, DKTP integrates robust
 * key exchange, authentication, and encryption into a single protocol. It is ideally suited for any environment where
 * strong post-quantum security is a priority.
 *
 * \subsection library_dependencies Cryptographic Dependencies
 * QSTP uses the QSC cryptographic library: <a href="https://github.com/QRCS-CORP/QSC">The QSC Library</a>
 * \section conclusion_sec Conclusion
 *
 * QRCS-PL private License. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 * 
 * \author John G. Underhill
 * \date 2025-02-10
 */

#endif
