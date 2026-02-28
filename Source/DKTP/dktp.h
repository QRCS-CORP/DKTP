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

#ifndef DKTP_H
#define DKTP_H

#include "rcs.h"
#include "async.h"
#include "sha3.h"

/**
* \file dktp.h
* \brief DKTP support header
* Common defined parameters and functions of the DKTP client and server implementations.
* 
* Note:
* These definitions determine the asymmetric protocol set used by DKTP.
* The individual parameter sets for each cipher and signature scheme,
* can be configured in the QSC libraries qsccommon.h file.
* For maximum security, I recommend the McElice/SPHINCS+ set.
* For a balance of performance and security, the Dilithium/Kyber,
* or Dilithium/McEliece sets are recommended.
* 
* Parameter Sets:
* Kyber-S1, Dilithium-S1
* Kyber-S3, Dilithium-S3
* Kyber-S5, Dilithium-S5
* Kyber-S6, Dilithium-S5
* McEliece-S1, Dilithium-S1
* McEliece-S3, Dilithium-S3
* McEliece-S5, Dilithium-S5
* McEliece-S6, Dilithium-S5
* McEliece-S7, Dilithium-S5
* McEliece-S1, Sphincs-S1(f,s)
* McEliece-S3, Sphincs-S3(f,s)
* McEliece-S5, Sphincs-S5(f,s)
* McEliece-S6, Sphincs-S5(f,s)
* McEliece-S7, Sphincs-S6(f,s)
* 
* Recommended:
* Kyber-S5, Dilithium-S5
* Kyber-S6, Dilithium-S5
* McEliece-S5, Dilithium-S5
* McEliece-S5, Sphincs-S5(f,s)
* 
* The parameter sets used by DKTP are selected in the QSC library in the 
* libraries qsccommon.h file. Settings are at library defaults, however, a true 512-bit
* security system can be acheived by selecting the McEliece/SPHINCS+ parameter in DKTP
* and setting SPHINCS+ to one of the 512-bit options in the QSC library. 
*/

/*!
* \def DKTP_CONFIG_DILITHIUM_KYBER
* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/Kyber.
*/
#define DKTP_CONFIG_DILITHIUM_KYBER

///*!
//* \def DKTP_CONFIG_DILITHIUM_MCELIECE
//* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/McEliece.
//*/
//#define DKTP_CONFIG_DILITHIUM_MCELIECE

///*!
//* \def DKTP_CONFIG_SPHINCS_MCELIECE
//* \brief Sets the asymmetric cryptographic primitive-set to Sphincs+/McEliece.
//*/
//#define DKTP_CONFIG_SPHINCS_MCELIECE

#include "dktpcommon.h"
#include "socketbase.h"

#if defined(DKTP_CONFIG_DILITHIUM_KYBER)
#	include "dilithium.h"
#	include "kyber.h"
#elif defined(DKTP_CONFIG_DILITHIUM_MCELIECE)
#	include "dilithium.h"
#	include "mceliece.h"
#elif defined(DKTP_CONFIG_SPHINCS_MCELIECE)
#	include "sphincsplus.h"
#	include "mceliece.h"
#else
#	error Invalid parameter set!
#endif

/*!
* \def DKTP_DOMAIN_IDENTITY_SIZE
* \brief The size of the domain identity string.
* This string size can be modified to accomodate different length domain strings.
*/
#define DKTP_DOMAIN_IDENTITY_SIZE 16U

/*!
* \def DKTP_DOMAIN_IDENTITY_STRING
* \brief The default domain/device identity string.
* This value is injected as a strict domain boundary that is authenticating but does not effect key output.
* The domain string is added as a customization to the cSHAKE instance in the establish [session-cookie hash] phase of the key-exchange, 
* used to verify a common domain identity between the peering hosts.
* Default domain string is 16 characters: Domain : Device Group : Protocol and Version.
*/
extern const char DKTP_DOMAIN_IDENTITY_STRING[DKTP_DOMAIN_IDENTITY_SIZE + sizeof(char)];

/*!
* \def DKTP_ASYMMETRIC_RATCHET
* \brief Enable the asymmetric ratchet option
*/
#define DKTP_ASYMMETRIC_RATCHET

/*!
* \def DKTP_CONFIG_SIZE
* \brief The size of the protocol configuration string
*/
#define DKTP_CONFIG_SIZE 48U

/*!
* \def DKTP_HASH_SIZE
* \brief The 512-bit hash function size
*/
#define DKTP_HASH_SIZE 64U

/*!
* \def DKTP_MACKEY_SIZE
* \brief The 512-bit mac key size
*/
#define DKTP_MACKEY_SIZE 64U

/*!
* \def DKTP_MACTAG_SIZE
* \brief The 512-bit mac key size
*/
#define DKTP_MACTAG_SIZE 64U

/*!
* \def DKTP_SYMMETRIC_KEY_SIZE
* \brief The 512-bit symmetric cipher key size
*/
#define DKTP_SYMMETRIC_KEY_SIZE 64U

/*!
* \def DKTP_SYMMETRIC_NONCE_SIZE
* \brief The 256-bit symmetric cipher nonce size
*/
#define DKTP_SYMMETRIC_NONCE_SIZE 32U

/*!
* \def DKTP_ASYMMETRIC_KEYCHAIN_COUNT
* \brief The key-chain asymmetric key count
*/
#define DKTP_ASYMMETRIC_KEYCHAIN_COUNT 10U

/*!
* \def DKTP_CLIENT_PORT
* \brief The default client port address
*/
#define DKTP_CLIENT_PORT 31118U

/*!
* \def DKTP_CONNECTIONS_MAX
* \brief The maximum number of connections
* 
* \details Modifiable constant: calculated given approx 5k 
* (3480 connection state + 1500 mtu + overhead), per connection on 256GB of DRAM.
* Can be scaled to a greater number provided the hardware can support it.
*/
#define DKTP_CONNECTIONS_MAX 50U

/*!
* \def DKTP_CONNECTION_MTU
* \brief The DKTP packet buffer size
*/
#define DKTP_CONNECTION_MTU 1500U

/*!
* \def DKTP_ERROR_SEQUENCE
* \brief The packet error sequence number
*/
#define DKTP_ERROR_SEQUENCE 0xFF00000000000000ULL

/*!
* \def DKTP_ERROR_MESSAGE_SIZE
* \brief The packet error message size
*/
#define DKTP_ERROR_MESSAGE_SIZE 1U

/*!
* \def DKTP_FLAG_SIZE
* \brief The packet flag size
*/
#define DKTP_FLAG_SIZE 1U

/*!
* \def DKTP_HEADER_SIZE
* \brief The DKTP packet header size
*/
#define DKTP_HEADER_SIZE 21U

/*!
* \def DKTP_KEEPALIVE_STRING
* \brief The keep alive string size
*/
#define DKTP_KEEPALIVE_STRING 20U

/*!
* \def DKTP_KEEPALIVE_TIMEOUT
* \brief The keep alive timeout in milliseconds (2 minutes)
*/
#define DKTP_KEEPALIVE_TIMEOUT (120U * 1000U)

/*!
* \def DKTP_KEYID_SIZE
* \brief The DKTP key identity size
*/
#define DKTP_KEYID_SIZE 16U

/*!
* \def DKTP_MSGLEN_SIZE
* \brief The size of the packet message length
*/
#define DKTP_MSGLEN_SIZE 4U

/*!
* \def DKTP_NONCE_SIZE
* \brief The size of the symmetric cipher nonce
*/
#define DKTP_NONCE_SIZE 32U

/*!
* \def DKTP_SERVER_PORT
* \brief The default server port address
*/
#define DKTP_SERVER_PORT 31119U

/*!
* \def DKTP_PACKET_TIME_THRESHOLD
* \brief The maximum number of seconds a packet is valid
* Note: On interior networks with a shared (NTP) time source, this could be set at 1 second,
* depending on network and device traffic conditions. For exterior networks, this time needs to
* be adjusted to account for clock-time differences, between 30-100 seconds.
*/
#define DKTP_PACKET_TIME_THRESHOLD 60U

/*!
* \def DKTP_POLLING_INTERVAL
* \brief The polling interval in milliseconds (2 minutes)
*/
#define DKTP_POLLING_INTERVAL (120U * 1000U)

/*!
* \def DKTP_PUBKEY_DURATION_DAYS
* \brief The number of days a public key remains valid
*/
#define DKTP_PUBKEY_DURATION_DAYS 365U

/*!
* \def DKTP_PUBKEY_DURATION_SECONDS
* \brief The number of seconds a public key remains valid
*/
#define DKTP_PUBKEY_DURATION_SECONDS (DKTP_PUBKEY_DURATION_DAYS * 24U * 60U * 60U)

/*!
* \def DKTP_PUBKEY_LINE_LENGTH
* \brief The line length of the printed DKTP public key
*/
#define DKTP_PUBKEY_LINE_LENGTH 64U

/*!
* \def DKTP_SECRET_SIZE
* \brief The size of the shared secret for each channel
*/
#define DKTP_SECRET_SIZE 32U

/*!
* \def DKTP_SEQUENCE_SIZE
* \brief The size of the packet sequence number
*/
#define DKTP_SEQUENCE_SIZE 8U

/*!
* \def DKTP_SEQUENCE_TERMINATOR
* \brief The sequence number of a packet that closes a connection
*/
#define DKTP_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
* \def DKTP_TIMESTAMP_SIZE
* \brief The key expiration timestamp size
*/
#define DKTP_TIMESTAMP_SIZE 8U

/*!
* \def DKTP_TIMESTAMP_STRING_SIZE
* \brief The key expiration timestamp string size
*/
#define DKTP_TIMESTAMP_STRING_SIZE 20U

/*!
* \def DKTP_MESSAGE_MAX
* \brief The maximum message size used during the key exchange (65,536  bytes)
*/
#define DKTP_MESSAGE_MAX 0x10000UL

/** \cond DOXYGEN_NO_DOCUMENT */
extern const char DKTP_CONFIG_STRING[DKTP_CONFIG_SIZE];
/** \endcond DOXYGEN_NO_DOCUMENT */

#if defined(DKTP_CONFIG_DILITHIUM_KYBER)

	/*!
	 * \def dktp_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define dktp_cipher_generate_keypair qsc_kyber_generate_keypair
	/*!
	 * \def dktp_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define dktp_cipher_decapsulate qsc_kyber_decapsulate
	/*!
	 * \def dktp_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define dktp_cipher_encapsulate qsc_kyber_encapsulate
	/*!
	 * \def dktp_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define dktp_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def dktp_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define dktp_signature_sign qsc_dilithium_sign
	/*!
	 * \def dktp_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define dktp_signature_verify qsc_dilithium_verify

/*!
* \def DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

/*!
* \def DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define DKTP_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define DKTP_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define DKTP_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

#elif defined(DKTP_CONFIG_DILITHIUM_MCELIECE)
	/*!
	 * \def dktp_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define dktp_cipher_generate_keypair qsc_mceliece_generate_keypair
	/*!
	 * \def dktp_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define dktp_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def dktp_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define dktp_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def dktp_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define dktp_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def dktp_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define dktp_signature_sign qsc_dilithium_sign
	/*!
	 * \def dktp_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define dktp_signature_verify qsc_dilithium_verify

/*!
* \def DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define DKTP_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define DKTP_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define DKTP_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

#elif defined(DKTP_CONFIG_SPHINCS_MCELIECE)

	/*!
	 * \def dktp_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define dktp_cipher_generate_keypair qsc_mceliece_generate_keypair
	/*!
	 * \def dktp_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define dktp_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def dktp_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define dktp_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def dktp_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define dktp_signature_generate_keypair qsc_sphincsplus_generate_keypair
	/*!
	 * \def dktp_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define dktp_signature_sign qsc_sphincsplus_sign
	/*!
	 * \def dktp_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define dktp_signature_verify qsc_sphincsplus_verify

/*!
* \def DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define DKTP_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define DKTP_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

/*!
* \def DKTP_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define DKTP_ASYMMETRIC_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)

#else
#	error invalid parameter set!
#endif

/* public key encoding constants */

/*!
* \def DKTP_REMOTE_PEER_KEY_ENCODED_SIZE
* \brief The peer key size
*/
#define DKTP_REMOTE_PEER_KEY_ENCODED_SIZE (DKTP_KEYID_SIZE + DKTP_TIMESTAMP_SIZE + DKTP_CONFIG_SIZE + DKTP_SECRET_SIZE + DKTP_ASYMMETRIC_VERIFY_KEY_SIZE)

/*!
* \def DKTP_LOCAL_PEER_KEY_ENCODED_SIZE
* \brief The secret signature key size
*/
#define DKTP_LOCAL_PEER_KEY_ENCODED_SIZE (DKTP_KEYID_SIZE + DKTP_KEYID_SIZE + DKTP_TIMESTAMP_SIZE + DKTP_CONFIG_SIZE + DKTP_SECRET_SIZE + DKTP_ASYMMETRIC_SIGNING_KEY_SIZE + DKTP_ASYMMETRIC_VERIFY_KEY_SIZE)

/* error code strings */

/*!
* \def DKTP_ERROR_STRING_DEPTH
* \brief The depth of the DKTP error string array
*/
#define DKTP_ERROR_STRING_DEPTH 29U

/*!
* \def DKTP_ERROR_STRING_WIDTH
* \brief The width of each DKTP error string
*/
#define DKTP_ERROR_STRING_WIDTH 128U

/** \cond DOXYGEN_NO_DOCUMENT */
extern const char DKTP_ERROR_STRINGS[DKTP_ERROR_STRING_DEPTH][DKTP_ERROR_STRING_WIDTH];
/** \endcond DOXYGEN_NO_DOCUMENT */

/*!
* \def DKTP_MESSAGE_STRING_DEPTH
* \brief The depth of the DKTP message string array
*/
#define DKTP_MESSAGE_STRING_DEPTH 21U

/*!
* \def DKTP_MESSAGE_STRING_WIDTH
* \brief The width of each DKTP message string
*/
#define DKTP_MESSAGE_STRING_WIDTH 128U

/** \cond DOXYGEN_NO_DOCUMENT */
extern const char DKTP_MESSAGE_STRINGS[DKTP_MESSAGE_STRING_DEPTH][DKTP_MESSAGE_STRING_WIDTH];
/** \endcond DOXYGEN_NO_DOCUMENT */


/*!
* \def DKTP_CHANNEL_IDENTITY_LENGTH
* \brief The depth of the DKTP message string array
*/
#define DKTP_CHANNEL_IDENTITY_LENGTH 14U

/** \cond DOXYGEN_NO_DOCUMENT */
extern const char DKTP_RX_CHANNEL_IDENTITY[DKTP_CHANNEL_IDENTITY_LENGTH];
extern const char DKTP_TX_CHANNEL_IDENTITY[DKTP_CHANNEL_IDENTITY_LENGTH];
/** \endcond DOXYGEN_NO_DOCUMENT */

/*!
* \enum dktp_configuration
* \brief The asymmetric cryptographic primitive configuration
*/
DKTP_EXPORT_API typedef enum dktp_configuration
{
	dktp_configuration_none = 0x00U,				/*!< No configuration was specified */
	dktp_configuration_sphincs_mceliece = 0x01U,	/*!< The Sphincs+ and McEliece configuration */
	dktp_configuration_dilithium_kyber = 0x02U,		/*!< The Dilithium and Kyber configuration */
	dktp_configuration_dilithium_mceliece = 0x03U,	/*!< The Dilithium and Kyber configuration */
	dktp_configuration_dilithium_ntru = 0x04U,		/*!< The Dilithium and NTRU configuration */
	dktp_configuration_falcon_kyber = 0x05U,		/*!< The Falcon and Kyber configuration */
	dktp_configuration_falcon_mceliece = 0x06U,		/*!< The Falcon and McEliece configuration */
	dktp_configuration_falcon_ntru = 0x07U,			/*!< The Falcon and NTRU configuration */
} dktp_configuration;

/*!
* \enum dktp_messages
* \brief The logging message enumeration
*/
DKTP_EXPORT_API typedef enum dktp_messages
{
	dktp_messages_none = 0x00U,						/*!< No configuration was specified */
	dktp_messages_accept_fail = 0x01U,				/*!< The socket accept failed */
	dktp_messages_listen_fail = 0x02U,				/*!< The listener socket could not connect */
	dktp_messages_bind_fail = 0x03U,				/*!< The listener socket could not bind to the address */
	dktp_messages_create_fail = 0x04U,				/*!< The listener socket could not be created */
	dktp_messages_connect_success = 0x05U,			/*!< The server connected to a host */
	dktp_messages_receive_fail = 0x06U,				/*!< The socket receive function failed */
	dktp_messages_allocate_fail = 0x07U,			/*!< The server memory allocation request has failed */
	dktp_messages_kex_fail = 0x08U,					/*!< The key exchange has experienced a failure */
	dktp_messages_disconnect = 0x09U,				/*!< The server has disconnected the client */
	dktp_messages_disconnect_fail = 0x0AU,			/*!< The server has disconnected the client due to an error */
	dktp_messages_socket_message = 0x0BU,			/*!< The server has had a socket level error */
	dktp_messages_queue_empty = 0x0CU,				/*!< The server has reached the maximum number of connections */
	dktp_messages_listener_fail = 0x0DU,			/*!< The server listener socket has failed */
	dktp_messages_sockalloc_fail = 0x0EU,			/*!< The server has run out of socket connections */
	dktp_messages_decryption_fail = 0x0FU,			/*!< The message decryption has failed */
	dktp_messages_connection_fail = 0x10U,			/*!< The connection failed or was interrupted */
	dktp_messages_invalid_request = 0x11U,			/*!< The function received an invalid request */
	dktp_messages_peer_key_mismatch = 0x12U,		/*!< The remote peer identity does not match the local key */
	dktp_messages_system_message = 0x13U,			/*!< The host encountered an error */
	dktp_messages_asymmetric_ratchet = 0x14U,		/*!< The host received an asymmetric ratchet request */
} dktp_messages;

/*!
* \enum dktp_errors
* \brief The DKTP error values
*/
DKTP_EXPORT_API typedef enum dktp_errors
{
	dktp_error_none = 0x00U,						/*!< No error was detected */
	dktp_error_accept_fail = 0x01U,					/*!< The socket accept function returned an error */
	dktp_error_authentication_failure = 0x02U,		/*!< The symmetric cipher had an authentication failure */
	dktp_error_channel_down = 0x03U,				/*!< The communications channel has failed */
	dktp_error_connection_failure = 0x04U,			/*!< The device could not make a connection to the remote host */
	dktp_error_connect_failure = 0x05U,				/*!< The transmission failed at the KEX connection phase */
	dktp_error_decapsulation_failure = 0x06U,		/*!< The asymmetric cipher failed to decapsulate the shared secret */
	dktp_error_decryption_failure = 0x07U,			/*!< The decryption authentication has failed */
	dktp_error_establish_failure = 0x08U,			/*!< The transmission failed at the KEX establish phase */
	dktp_error_exchange_failure = 0x09U,			/*!< The transmission failed at the KEX exchange phase */
	dktp_error_hash_invalid = 0x0AU,				/*!< The public-key hash is invalid */
	dktp_error_hosts_exceeded = 0x0BU,				/*!< The server has run out of socket connections */
	dktp_error_invalid_input = 0x0CU,				/*!< The expected input was invalid */
	dktp_error_invalid_request = 0x0DU,				/*!< The packet flag was unexpected */
	dktp_error_key_expired = 0x0EU,					/*!< The DKTP public key has expired  */
	dktp_error_key_unrecognized = 0x0FU,			/*!< The key identity is unrecognized */
	dktp_error_keychain_fail = 0x10U,				/*!< The ratchet operation has failed */
	dktp_error_listener_fail = 0x11U,				/*!< The listener function failed to initialize */
	dktp_error_memory_allocation = 0x12U,			/*!< The server has run out of memory */
	dktp_error_message_time_invalid = 0x13U,		/*!< The packet has valid time expired */
	dktp_error_packet_unsequenced = 0x14U,			/*!< The packet was received out of sequence */
	dktp_error_random_failure = 0x15U,				/*!< The random generator has failed */
	dktp_error_receive_failure = 0x16U,				/*!< The receiver failed at the network layer */
	dktp_error_transmit_failure = 0x17U,			/*!< The transmitter failed at the network layer */
	dktp_error_unknown_protocol = 0x18U,			/*!< The protocol string was not recognized */
	dktp_error_verify_failure = 0x19U,				/*!< The expected data could not be verified */
	dktp_error_peer_key_mismatch = 0x1AU,			/*!< The remote peer key identity does not match the local key */
	dktp_error_disconnect_request = 0x1BU,			/*!< The remote host has disconnected */
	dktp_error_general_failure = 0x1CU				/*!< A general failure occurred */
} dktp_errors;

/*!
* \enum dktp_flags
* \brief The DKTP packet flags
*/
DKTP_EXPORT_API typedef enum dktp_flags
{
	dktp_flag_none = 0x00U,							/*!< No flag was specified */
	dktp_flag_connect_request = 0x01U,				/*!< The DKTP key-exchange client connection request flag  */
	dktp_flag_connect_response = 0x02U,				/*!< The DKTP key-exchange server connection response flag */
	dktp_flag_connection_terminate = 0x03U,			/*!< The connection is to be terminated */
	dktp_flag_encrypted_message = 0x04U,			/*!< The message has been encrypted flag */
	dktp_flag_exstart_request = 0x05U,				/*!< The DKTP key-exchange client exstart request flag */
	dktp_flag_exstart_response = 0x06U,				/*!< The DKTP key-exchange server exstart response flag */
	dktp_flag_exchange_request = 0x07U,				/*!< The DKTP key-exchange client exchange request flag */
	dktp_flag_exchange_response = 0x08U,			/*!< The DKTP key-exchange server exchange response flag */
	dktp_flag_establish_request = 0x09U,			/*!< The DKTP key-exchange client establish request flag */
	dktp_flag_establish_response = 0x0AU,			/*!< The DKTP key-exchange server establish response flag */
	dktp_flag_keep_alive_request = 0x0BU,			/*!< The packet contains a keep alive request */
	dktp_flag_keep_alive_response = 0x0CU,			/*!< The packet contains a keep alive response */
	dktp_flag_remote_connected = 0x0DU,				/*!< The remote host is connected flag */
	dktp_flag_remote_terminated = 0x0EU,			/*!< The remote host has terminated the connection */
	dktp_flag_session_established = 0x0FU,			/*!< The exchange is in the established state */
	dktp_flag_session_establish_verify = 0x10U,		/*!< The exchange is in the established verify state */
	dktp_flag_unrecognized_protocol = 0x11U,		/*!< The protocol string is not recognized */
	dktp_flag_asymmetric_ratchet_request = 0x12U,	/*!< The host has received a asymmetric key ratchet request */
	dktp_flag_asymmetric_ratchet_response = 0x13U,	/*!< The host has received a asymmetric key ratchet request */
	dktp_flag_symmetric_ratchet_request = 0x14U,	/*!< The host has received a symmetric key ratchet request */
	dktp_flag_transfer_request = 0x15U,				/*!< Reserved - The host has received a transfer request */
	dktp_flag_error_condition = 0xFFU,				/*!< The connection experienced an error */
} dktp_flags;

/*!
* \struct dktp_asymmetric_cipher_keypair
* \brief The DKTP asymmetric cipher key container
*/
DKTP_EXPORT_API typedef struct dktp_asymmetric_cipher_keypair
{
	uint8_t* deckey;
	uint8_t* enckey;
} dktp_asymmetric_cipher_keypair;

/*!
* \struct dktp_asymmetric_signature_keypair
* \brief The DKTP asymmetric signature key container
*/
DKTP_EXPORT_API typedef struct dktp_asymmetric_signature_keypair
{
	uint8_t* sigkey;
	uint8_t* verkey;
} dktp_asymmetric_signature_keypair;

/*!
* \struct dktp_network_packet
* \brief The DKTP packet structure
*/
DKTP_EXPORT_API typedef struct dktp_network_packet
{
	uint8_t flag;									/*!< The packet flag */
	uint32_t msglen;								/*!< The packets message length */
	uint64_t sequence;								/*!< The packet sequence number */
	uint64_t utctime;								/*!< The UTC time the packet was created in seconds */
	uint8_t* pmessage;								/*!< A pointer to the packets message buffer */
} dktp_network_packet;

/*!
* \struct dktp_remote_peer_key
* \brief The DKTP client key structure
*/
DKTP_EXPORT_API typedef struct dktp_remote_peer_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[DKTP_CONFIG_SIZE];				/*!< The primitive configuration string */
	uint8_t keyid[DKTP_KEYID_SIZE];					/*!< The key identity string */
	uint8_t pss[DKTP_SECRET_SIZE];		/*!< The pre-shared secret array */
	uint8_t verkey[DKTP_ASYMMETRIC_VERIFY_KEY_SIZE];/*!< The asymmetric signatures verification-key */
} dktp_remote_peer_key;

/*!
* \struct dktp_local_peer_key
* \brief The DKTP server key structure
*/
DKTP_EXPORT_API typedef struct dktp_local_peer_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[DKTP_CONFIG_SIZE];				/*!< The primitive configuration string */
	uint8_t keyid[DKTP_KEYID_SIZE];					/*!< The key identity string */
	uint8_t peerid[DKTP_KEYID_SIZE];				/*!< The peer identity string */
	uint8_t pss[DKTP_SECRET_SIZE];					/*!< The pre-shared secret copy array */
	uint8_t sigkey[DKTP_ASYMMETRIC_SIGNING_KEY_SIZE];/*!< The asymmetric signature signing-key */
	uint8_t verkey[DKTP_ASYMMETRIC_VERIFY_KEY_SIZE]; /*!< The asymmetric signature verification-key */
} dktp_local_peer_key;

/*!
* \struct dktp_connection_state
* \brief The DKTP socket connection state structure
*/
DKTP_EXPORT_API typedef struct dktp_connection_state
{
	qsc_socket target;								/*!< The target socket structure */
	qsc_rcs_state rxcpr;							/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;							/*!< The transmit channel cipher state */
#if defined(DKTP_ASYMMETRIC_RATCHET)
	uint8_t deckey[DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE]; /*!< The decasulation key storage */
	uint8_t enckey[DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE]; /*!< The encasulation key storage */
	uint8_t pssl[DKTP_SECRET_SIZE];					/*!< The local pre-shared secret */
	uint8_t pssr[DKTP_SECRET_SIZE];					/*!< The remote pre-shared secret */
	uint8_t sigkey[DKTP_ASYMMETRIC_SIGNING_KEY_SIZE]; /*!< The local signing key */
	uint8_t verkey[DKTP_ASYMMETRIC_VERIFY_KEY_SIZE];  /*!< The remote signature verification key */
	qsc_mutex txlock;								/*!< The transmit channel lock */
#endif
	uint64_t rxseq;									/*!< The receive channels packet sequence number  */
	uint64_t txseq;									/*!< The transmit channels packet sequence number  */
	uint32_t cid;									/*!< The connections instance count */
	dktp_flags exflag;								/*!< The KEX position flag */
	bool receiver;									/*!< The instance was initialized in listener mode */
} dktp_connection_state;

/*!
* \brief Close the network connection between hosts
*
* \param cns: A pointer to the connection state structure
* \param err: The error message
* \param notify: Notify the remote host connection is closing
*/
DKTP_EXPORT_API void dktp_connection_close(dktp_connection_state* cns, dktp_errors err, bool notify);

/*!
* \brief Reset the connection state
*
* \param cns: A pointer to the connection state structure
*/
DKTP_EXPORT_API void dktp_connection_state_dispose(dktp_connection_state* cns);

/*!
 * \brief Decrypt an error message.
 *
 * \param cns A pointer to the DKTP client state structure.
 * \param message [const] The serialized error packet.
 * \param merr A pointer to an \c dktp_errors error value.
 *
 * \return Returns true if the message was decrypted successfully, false on failure.
 */
DKTP_EXPORT_API bool dktp_decrypt_error_message(dktp_errors* merr, dktp_connection_state* cns, const uint8_t* message);

/*!
* \brief Return a pointer to a string description of an error code
*
* \param error: The error type
* 
* \return Returns a pointer to an error string or NULL
*/
DKTP_EXPORT_API const char* dktp_error_to_string(dktp_errors error);

/*!
* \brief Populate a packet header and set the creation time
*
* \param packetout: A pointer to the output packet structure
* \param flag: The packet flag
* \param sequence: The packet sequence number
* \param msglen: The length of the message array
*/
DKTP_EXPORT_API void dktp_header_create(dktp_network_packet* packetout, dktp_flags flag, uint64_t sequence, uint32_t msglen);

/*!
* \brief Validate a packet header and timestamp
*
* \param cns: A pointer to the connection state structure
* \param packetin: A pointer to the input packet structure
* \param kexflag: The packet flag
* \param pktflag: The packet flag
* \param sequence: The packet sequence number
* \param msglen: The length of the message array
*
* \return: Returns the function error state
*/
DKTP_EXPORT_API dktp_errors dktp_header_validate(dktp_connection_state* cns, const dktp_network_packet* packetin, dktp_flags kexflag, dktp_flags pktflag, uint64_t sequence, uint32_t msglen);

/*!
* \brief Generate a DKTP key-pair; generates the public and private asymmetric signature keys.
*
* \param enckey: The public key, distributed to clients
* \param deckey: The private key, a secret key known only by the server
* \param keyid: [const] The key identity string
*/
DKTP_EXPORT_API void dktp_generate_keypair(dktp_remote_peer_key* enckey, dktp_local_peer_key* deckey, const uint8_t keyid[DKTP_KEYID_SIZE]);

/*!
* \brief Get the error string description
*
* \param emsg: The message enumeration
* 
* \return Returns a pointer to the message string or NULL
*/
DKTP_EXPORT_API const char* dktp_get_error_description(dktp_messages emsg);

/*!
* \brief Log the message, socket error, and string description
*
* \param emsg: The message enumeration
* \param err: The socket exception enumeration
* \param msg: [const] The message string
*/
DKTP_EXPORT_API void dktp_log_error(dktp_messages emsg, qsc_socket_exceptions err, const char* msg);

/*!
* \brief Log a message
*
* \param emsg: The message enumeration
*/
DKTP_EXPORT_API void dktp_log_message(dktp_messages emsg);

/*!
* \brief Log a message and description
*
* \param emsg: The message enumeration
* \param msg: [const] The message string
*/
DKTP_EXPORT_API void dktp_log_write(dktp_messages emsg, const char* msg);

/*!
* \brief Log a system error message
*
* \param err: The system error enumerator
*/
DKTP_EXPORT_API void dktp_log_system_error(dktp_errors err);

/*!
* \brief Clear a packet's state
*
* \param packet: A pointer to the packet structure
*/
DKTP_EXPORT_API void dktp_packet_clear(dktp_network_packet* packet);

/*!
* \brief Decrypt a message and copy it to the message output
*
* \param cns: A pointer to the connection state structure
* \param message: The message output array
* \param msglen: A pointer receiving the message length
* \param packetin: [const] A pointer to the input packet structure
*
* \return: Returns the function error state
*/
DKTP_EXPORT_API dktp_errors dktp_packet_decrypt(dktp_connection_state* cns, uint8_t* message, size_t* msglen, const dktp_network_packet* packetin);

/*!
* \brief Encrypt a message and build an output packet
*
* \param cns: A pointer to the connection state structure
* \param packetout: A pointer to the output packet structure
* \param message: [const] The input message array
* \param msglen: The length of the message array
*
* \return: Returns the function error state
*/
DKTP_EXPORT_API dktp_errors dktp_packet_encrypt(dktp_connection_state* cns, dktp_network_packet* packetout, const uint8_t* message, size_t msglen);

/*!
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
DKTP_EXPORT_API void dktp_packet_error_message(dktp_network_packet* packet, dktp_errors error);

/*!
* \brief Deserialize a byte array to a packet header
*
* \param packet: [const] The header byte array to deserialize
* \param header: A pointer to the packet structure
*/
DKTP_EXPORT_API void dktp_packet_header_deserialize(const uint8_t* header, dktp_network_packet* packet);

/*!
* \brief Serialize a packet header to a byte array
*
* \param packet: [const] A pointer to the packet structure to serialize
* \param header: The header byte array
*/
DKTP_EXPORT_API void dktp_packet_header_serialize(const dktp_network_packet* packet, uint8_t* header);

/*!
* \brief Sets the local UTC seconds time in the packet header
*
* \param packet: A pointer to a network packet
*/
DKTP_EXPORT_API void dktp_packet_set_utc_time(dktp_network_packet* packet);

/*!
* \brief Checks the local UTC seconds time against the packet sent time for validity within the packet time threshold
*
* \param packet: [const] A pointer to a network packet
*
* \return Returns true if the packet was received within the valid-time threhold
*/
DKTP_EXPORT_API bool dktp_packet_time_valid(const dktp_network_packet* packet);

/*!
* \brief Serialize a packet to a byte array
*
* \param packet: [const] The header byte array to deserialize
* \param pstream: A pointer to the packet structure
* 
* \return Returns the size of the byte stream
*/
DKTP_EXPORT_API size_t dktp_packet_to_stream(const dktp_network_packet* packet, uint8_t* pstream);

/*!
* \brief Deserialize a local peer key structure and copy to an array
*
* \param lpk: A pointer to the output local peer key structure
* \param slpk: [const] The input serialized local peer key
*/
DKTP_EXPORT_API void dktp_local_peer_key_deserialize(dktp_local_peer_key* lpk, const uint8_t slpk[DKTP_LOCAL_PEER_KEY_ENCODED_SIZE]);

/*!
* \brief Erase a local peer key
*
* \param lpk: A pointer to the output local peer key structure
*/
DKTP_EXPORT_API void dktp_local_peer_key_erase(dktp_local_peer_key* lpk);

/*!
* \brief Serialize a local peer key structure
*
* \param slpk: The output serialized local peer key
* \param lpk: [const] A pointer to the local peer key structure
*/
DKTP_EXPORT_API void dktp_local_peer_key_serialize(uint8_t slpk[DKTP_LOCAL_PEER_KEY_ENCODED_SIZE], const dktp_local_peer_key* lpk);

/*!
* \brief Erase a remote peer key
*
* \param lpk: A pointer to the output remote peer key structure
*/
DKTP_EXPORT_API void dktp_remote_peer_key_erase(dktp_remote_peer_key* rpk);

/*!
* \brief Compares two public keys for equality
*
* \param a: [const] The first public key
* \param b: [const] The second public key
*
* \return Returns true if the certificates are identical
*/
DKTP_EXPORT_API bool dktp_remote_peer_key_compare(const dktp_remote_peer_key* a, const dktp_remote_peer_key* b);

/*!
* \brief Deserialize a remote peer key and populate a remote peer key structure
*
* \param rpk: A pointer to the output remote peer key
* \param srpk: [const] The input serialized remote peer key
*/
DKTP_EXPORT_API void dktp_remote_peer_key_deserialize(dktp_remote_peer_key* rpk, const uint8_t srpk[DKTP_REMOTE_PEER_KEY_ENCODED_SIZE]);

/*!
* \brief Serialize a remote peer key structure and copy to an array
*
* \param srpk: The output serialized remote peer key array
* \param rpk: [const] A pointer to the remote peer key structure
*/
DKTP_EXPORT_API void dktp_remote_peer_key_serialize(uint8_t srpk[DKTP_REMOTE_PEER_KEY_ENCODED_SIZE], const dktp_remote_peer_key* rpk);

/*!
* \brief Deserialize a byte array to a packet
*
* \param pstream: [const] The header byte array to deserialize
* \param packet: A pointer to the packet structure
*/
DKTP_EXPORT_API void dktp_stream_to_packet(const uint8_t* pstream, dktp_network_packet* packet);

#endif
