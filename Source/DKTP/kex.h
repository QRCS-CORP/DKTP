/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef DKTP_KEX_H
#define DKTP_KEX_H

#include "dktp.h"

/**
 * \file kex.h
 * \brief DKTP Key Exchange Functions.
 *
 * \details
 * This header file contains the internal key exchange functions for the Dual Key Tunneling Protocol (DKTP).
 *
 * The file defines internal state structures for both the client and server roles in the key exchange.
 * These structures encapsulate various cryptographic parameters such as key identities, session token hashes,
 * asymmetric keys (for encryption, signing, and verification), shared secrets, and session expiration times.
 *
 * The following internal (non-exportable) functions are declared:
 *
 * - \c dktp_kex_server_key_exchange: Executes the server-side Duplex key exchange.
 * - \c dktp_kex_client_key_exchange: Executes the client-side Duplex key exchange.
 * - \c dktp_kex_simplex_server_key_exchange: Executes the server-side Simplex key exchange.
 * - \c dktp_kex_simplex_client_key_exchange: Executes the client-side Simplex key exchange.
 * - \c dktp_kex_test: Runs a suite of internal tests to validate the correctness of the key exchange operations.
 *
 * \note These functions and state structures are internal and are not part of the public DKTP API.
 */

/**
 * \struct dktp_kex_client_state
 * \brief Internal state for the Duplex key exchange (client-side).
 *
 * \details
 * This structure holds the state information required by a client participating in a Duplex key exchange.
 * It includes:
 * - \c keyid: A unique key identity string (of size \c DKTP_KEYID_SIZE) that identifies the key exchange session.
 * - \c schash: A session token hash (of size \c DKTP_HASH_SIZE) used to verify session integrity.
 * - \c deckey: The client's asymmetric cipher private key (of size \c DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE).
 * - \c enckey: The client's asymmetric cipher public key (of size \c DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE).
 * - \c rverkey: The remote party's asymmetric signature verification key (of size \c DKTP_ASYMMETRIC_VERIFY_KEY_SIZE).
 * - \c sigkey: The client's asymmetric signature signing key (of size \c DKTP_ASYMMETRIC_SIGNING_KEY_SIZE).
 * - \c secl: The derived asymmetric shared secret (of size \c DKTP_SECRET_SIZE) computed during key exchange.
 * - \c tskl: The local tunnel key (of size \c DKTP_SYMMETRIC_KEY_SIZE) stored temporarily during the key exchange.
 * - \c tskr: The remote tunnel key (of size \c DKTP_SYMMETRIC_KEY_SIZE) stored temporarily during the key exchange.
 * - \c verkey: The client's local asymmetric signature verification key (of size \c DKTP_ASYMMETRIC_VERIFY_KEY_SIZE).
 * - \c expiration: A timestamp (in seconds from the epoch) indicating when the key exchange session expires.
 */
typedef struct dktp_kex_client_state
{
	uint8_t keyid[DKTP_KEYID_SIZE];							/*!< The key identity string */
	uint8_t schash[DKTP_HASH_SIZE];							/*!< The session token hash */
	uint8_t deckey[DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE];	/*!< The asymmetric cipher decapsulation key */
	uint8_t enckey[DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE];	/*!< The asymmetric cipher encapsulation key */
	uint8_t pssl[DKTP_SECRET_SIZE];							/*!< The local pre-shared secret */
	uint8_t pssr[DKTP_SECRET_SIZE];							/*!< The remote pre-shared secret */
	uint8_t rverkey[DKTP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The remote asymmetric signature verification-key */
	uint8_t sigkey[DKTP_ASYMMETRIC_SIGNING_KEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t secl[DKTP_SECRET_SIZE];							/*!< The asymmetric shared secret */
	uint8_t verkey[DKTP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The local asymmetric signature verification-key */
	uint64_t expiration;									/*!< The expiration time, in seconds from epoch */
} dktp_kex_client_state;

/**
 * \struct dktp_kex_server_state
 * \brief Internal state for the Duplex key exchange (server-side).
 *
 * \details
 * This structure holds the state information required by a server participating in a Duplex key exchange.
 * It contains cryptographic parameters including key identities, session hashes, asymmetric keys, and an expiration
 * timestamp. In addition, it includes a callback function (\c key_query) that is used to retrieve the appropriate
 * public key during the key exchange process.
 */
typedef struct dktp_kex_server_state
{
	uint8_t keyid[DKTP_KEYID_SIZE];							/*!< The key identity string */
	uint8_t schash[DKTP_HASH_SIZE];							/*!< The session token hash */
	uint8_t deckey[DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE];	/*!< The asymmetric cipher private key */
	uint8_t enckey[DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE];	/*!< The asymmetric cipher public key */
	uint8_t pssl[DKTP_SECRET_SIZE];							/*!< The local pre-shared secret */
	uint8_t pssr[DKTP_SECRET_SIZE];							/*!< The remote pre-shared secret */
	uint8_t rverkey[DKTP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The remote asymmetric signature verification-key */
	uint8_t sigkey[DKTP_ASYMMETRIC_SIGNING_KEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t verkey[DKTP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The local asymmetric signature verification-key */
	uint64_t expiration;									/*!< The expiration time, in seconds from epoch */
} dktp_kex_server_state;

/**
 * \brief Execute the server-side key exchange.
 *
 * \details
 * This function processes an incoming key exchange request on the server side.
 * It uses the server key exchange state (\c dktp_kex_server_state) to verify client credentials,
 * exchange the necessary asymmetric keys, and update the DKTP connection state accordingly.
 *
 * \param kss A pointer to the server key exchange state structure.
 * \param cns A pointer to the current DKTP connection state.
 *
 * \return Returns a value of type \c dktp_errors indicating the outcome of the key exchange process.
 *
 * \note This is an internal non-exportable API.
 */
dktp_errors dktp_kex_server_key_exchange(dktp_kex_server_state* kss, dktp_connection_state* cns);

/**
 * \brief Execute the client-side key exchange.
 *
 * \details
 * This function initiates and completes the key exchange from the client side.
 * It processes the server's response, computes the shared secret, and updates the DKTP connection state
 * with the derived cryptographic parameters.
 *
 * \param kcs A pointer to the client key exchange state structure.
 * \param cns A pointer to the current DKTP connection state.
 *
 * \return Returns a value of type \c dktp_errors representing the result of the key exchange operation.
 *
 * \note This is an internal non-exportable API.
 */
dktp_errors dktp_kex_client_key_exchange(dktp_kex_client_state* kcs, dktp_connection_state* cns);

/**
 * \brief Run internal tests for the key exchange functions.
 *
 * \details
 * This function executes a suite of internal tests designed to validate the correct operation of the DKTP
 * key exchange mechanisms. The tests include:
 *
 * - Verifying the proper initialization and management of state structures.
 * - Testing the cryptographic operations involved in key generation, shared secret derivation, and session token hashing.
 * - Ensuring that the key exchange functions correctly update the DKTP connection state.
 *
 * The function returns true if all internal tests pass, confirming the reliability and correctness of the key exchange implementation.
 *
 * \return Returns true if the key exchange tests succeed; otherwise, false.
 *
 * \note This is an internal non-exportable API.
 */
bool dktp_kex_test(void);

#endif
