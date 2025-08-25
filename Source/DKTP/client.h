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

#ifndef DKTP_CLIENT_H
#define DKTP_CLIENT_H

#include "dktp.h"
#include "rcs.h"
#include "socketclient.h"

/**
 * \file client.h
 * \brief DKTP Client Functions
 *
 * \details
 * This header file defines the client-side functions for the Dual Key Tunneling Protocol (DKTP).
 * DKTP is a post-quantum secure messaging protocol that supports a Duplex key exchange
 * mechanism over IPv4 and IPv6 networks. These functions enable DKTP clients to initiate secure connections,
 * perform key exchanges, and manage cryptographic ratchet operations during an active session.
 *
 * The DKTP client functionality provided in this header includes:
 *
 * - **Key Ratchet Requests:**
 *   - **Asymmetric Key Ratchet Request:** (conditionally available when DKTP_ASYMMETRIC_RATCHET is defined)
 *     Initiates an asymmetric key ratchet to update session keys using asymmetric cryptographic operations,
 *     thereby enhancing forward secrecy.
 *
 * - **Duplex Key Exchange Connections:**
 *   - Establishes secure, bi-directional (mutually authenticated) communication channels using the DKTP protocol.
 *   - Supports connection establishment over both IPv4 and IPv6.
 *
 * - **Listener Functions:**
 *   - Functions that start a network listener (acting as a server) to accept incoming connections and perform
 *     either the DKTP key exchange.
 *
 * All connection functions accept callback functions for sending and receiving data over the DKTP connection,
 * and they return a value of type 'dktp_errors' to indicate the success or failure of the operation.
 *
 * \note This header file does not include any internal test functions.
 */

/**
 * \def DKTP_EXPORT_API
 * \brief Macro for exporting DKTP API functions.
 *
 * This macro ensures proper symbol visibility when building or linking the DKTP library. It is used to
 * control the export and import of functions in shared library builds.
 */

#if defined(DKTP_ASYMMETRIC_RATCHET)
/**
 * \brief Send an asymmetric key-ratchet request to the remote host.
 *
 * \details
 * This function sends a request to initiate an asymmetric key ratchet in an active DKTP session.
 * The asymmetric ratchet mechanism employs asymmetric cryptographic operations to update the session keys,
 * thereby providing enhanced forward secrecy. This function is only available when the DKTP_ASYMMETRIC_RATCHET
 * macro is defined.
 *
 * \param cns A pointer to the current DKTP connection state structure.
 *
 * \return Returns true if the ratchet request was successfully sent to the remote host, otherwise false.
 */
DKTP_EXPORT_API bool dktp_send_asymmetric_ratchet_request(dktp_connection_state* cns);
#endif

/**
 * \brief Connect to a remote host over IPv4 and perform the key exchange.
 *
 * \details
 * This function establishes a connection to a remote host using its IPv4 address and initiates the Duplex
 * key exchange protocol. The Duplex protocol enables mutual authentication and a bidirectional key exchange,
 * setting up a secure two-way communication channel. Upon successful connection, the provided callback functions
 * handle message transmission and reception.
 *
 * \param lpk A pointer to the local peer key.
 * \param rpk A pointer to the remote peer key.
 * \param address [const] A pointer to the IPv4 address information structure of the remote server.
 * \param port The DKTP application port number (typically defined by DKTP_CLIENT_PORT).
 * \param send_func A pointer to the send callback function responsible for transmitting messages.
 * \param receive_callback A pointer to the receive callback function used to process incoming data.
 *
 * \return Returns a value of type \c dktp_errors indicating the success or failure of the connection and key exchange.
 */
DKTP_EXPORT_API dktp_errors dktp_client_connect_ipv4(dktp_local_peer_key* lpk, 
	dktp_remote_peer_key* rpk, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(dktp_connection_state*), 
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t));

/**
 * \brief Connect to a remote host over IPv6 and perform the key exchange.
 *
 * \details
 * This function establishes a connection to a remote host using its IPv6 address and initiates the
 * key exchange protocol. The DKTP protocol provides mutual authentication and secure bidirectional communication.
 * Upon connection, the designated callback functions are invoked to manage the data transmission and reception.
 *
 * \param lpk A pointer to the local peer key.
 * \param rpk A pointer to the remote peer key.
 * \param address [const] A pointer to the IPv6 address information structure of the remote server.
 * \param port The DKTP application port number (typically defined by DKTP_CLIENT_PORT).
 * \param send_func A pointer to the send callback function responsible for message transmission.
 * \param receive_callback A pointer to the receive callback function used to process incoming data.
 *
 * \return Returns a value of type \c dktp_errors indicating the result of the connection and key exchange operation.
 */
DKTP_EXPORT_API dktp_errors dktp_client_connect_ipv6(dktp_local_peer_key* lpk, 
	dktp_remote_peer_key* rpk,
	const qsc_ipinfo_ipv6_address* address, uint16_t port,
	void (*send_func)(dktp_connection_state*),
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t));

/**
 * \brief Start the server over IPv4 and listen for a single host-to-host connection.
 *
 * \details
 * This function initiates a network listener on the IPv4 interface to accept an incoming connection for
 * the DKTP key exchange. The DKTP protocol facilitates mutual authentication and a bidirectional key exchange,
 * thereby establishing a secure communication channel. An additional key query callback is provided to identify
 * and retrieve the correct public key based on a received key identifier.
 *
 * \param lpk A pointer to the DKTP local peer key.
 * \param rpk A pointer to the DKTP remote peer key.
 * \param send_func A pointer to the send callback function responsible for transmitting messages.
 * \param receive_callback A pointer to the receive callback function used to process incoming client data.
 *
 * \return Returns a value of type \c dktp_errors representing the outcome of the listener initialization and key exchange.
 */
DKTP_EXPORT_API dktp_errors dktp_client_listen_ipv4(dktp_local_peer_key* lpk, 
	dktp_remote_peer_key* rpk, 
	void (*send_func)(dktp_connection_state*),
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t));

/**
 * \brief Start the server over IPv6 and listen for a single host-to-host connection.
 *
 * \details
 * This function sets up a network listener on the IPv6 interface to accept an incoming connection for
 * the DKTP key exchange protocol. The DKTP protocol enables secure bidirectional communication through mutual
 * authentication and key exchange. A key query callback is provided to determine and return the correct public key
 * based on a given key identifier during the connection process.
 *
 * \param lpk A pointer to the DKTP server signature key used for signing messages.
 * \param rpk A pointer to the DKTP remote peer key.
 * \param send_func A pointer to the send callback function that handles outgoing message transmission.
 * \param receive_callback A pointer to the receive callback function used to process incoming data from the connected host.
 *
 * \return Returns a value of type \c dktp_errors indicating the status of the listener setup and key exchange operation.
 */
DKTP_EXPORT_API dktp_errors dktp_client_listen_ipv6(dktp_local_peer_key* lpk,
	dktp_remote_peer_key* rpk,
	void (*send_func)(dktp_connection_state*),
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t));


#endif
