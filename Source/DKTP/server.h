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

#ifndef DKTP_SERVER_H
#define DKTP_SERVER_H

#include "dktp.h"
#include "rcs.h"
#include "socketserver.h"
/**
 * \file server.h
 * \brief DKTP Server functions.
 *
 * \details
 * This header declares the functions used to implement the server component of the Dual Key Tunneling Protocol (DKTP).
 * The server functions manage client connections, broadcast messages, and control the server lifecycle through operations
 * such as pausing, resuming, and quitting. DKTP employs a multi-threaded server design that supports both IPv4 and IPv6 connections.
 *
 * The functions provided in this header include:
 * - Broadcasting a message to all connected hosts.
 * - Pausing the server to suspend acceptance of new connections.
 * - Quitting the server by closing all active connections.
 * - Resuming the server listener from a paused state.
 * - Starting the multi-threaded server on IPv4 and IPv6 interfaces with support for callback functions to process
 *   incoming data and handle disconnect events.
 *
 * \note DKTP_EXPORT_API is used to ensure proper symbol visibility.
 */

/*!
 * \def DKTP_SERVER_PAUSE_INTERVAL
 * \brief The pause interval used by the server pause function.
 *
 * This macro defines the time interval (in milliseconds) that the server will pause before resuming
 * operations or processing new connection requests.
 */
#define DKTP_SERVER_PAUSE_INTERVAL 100U

/**
 * \brief Broadcast a message to all connected hosts.
 *
 * \details
 * This function iterates over all active connections managed by the server and transmits the specified message
 * to each connected host. It is useful for disseminating announcements or control messages across the network.
 *
 * \param message [const] A pointer to the message data to be broadcast.
 * \param msglen The length (in bytes) of the message.
 */
DKTP_EXPORT_API void dktp_server_broadcast(const uint8_t* message, size_t msglen);

/**
 * \brief Pause the server.
 *
 * \details
 * This function temporarily suspends the acceptance of new client connections. While paused, the server continues
 * to service existing connections but does not allow any new joins until it is resumed.
 */
DKTP_EXPORT_API void dktp_server_pause(void);

/**
 * \brief Quit the server.
 *
 * \details
 * This function gracefully shuts down the server by closing all active client connections and terminating the server's
 * listener. It is used to perform a complete shutdown of the server operations.
 */
DKTP_EXPORT_API void dktp_server_quit(void);

/**
 * \brief Resume the server listener.
 *
 * \details
 * This function resumes the server's listener functionality after it has been paused. Once resumed, the server will
 * once again accept new incoming client connections.
 */
DKTP_EXPORT_API void dktp_server_resume(void);

/**
 * \brief Start the IPv4 multi-threaded server.
 *
 * \details
 * This function initializes and starts the DKTP server for IPv4 connections using a multi-threaded architecture.
 * It listens on the provided socket and uses the specified DKTP private key for secure key exchange and authentication.
 * Two callback functions are provided:
 * - A receive callback to process incoming client data streams.
 * - A disconnect callback to handle cleanup and resource deallocation when a client disconnects.
 *
 * \param source A pointer to the listener socket used by the server.
 * \param lpk [const] A pointer to the DKTP server private signature key used for key exchange.
 * \param receive_callback A pointer to the function that processes incoming client data.
 * \param disconnect_callback A pointer to the function that handles client disconnect events.
 *
 * \return Returns a DKTP error code indicating the success or failure of starting the IPv4 server.
 */
DKTP_EXPORT_API dktp_errors dktp_server_start_ipv4(qsc_socket* source,
	const dktp_local_peer_key* lpk,
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(dktp_connection_state*));

/**
 * \brief Start the IPv6 multi-threaded server.
 *
 * \details
 * This function initializes and starts the DKTP server for IPv6 connections using a multi-threaded design.
 * It listens on the provided IPv6 socket and employs the specified DKTP private key for secure communications.
 * The server uses two callback functions to process incoming client data and handle disconnect events.
 *
 * \param source A pointer to the listener socket used by the server.
 * \param lpk [const] A pointer to the DKTP server private signature key used for key exchange and authentication.
 * \param receive_callback A pointer to the function that processes incoming client data.
 * \param disconnect_callback A pointer to the function that handles client disconnect events.
 *
 * \return Returns a DKTP error code indicating the outcome of starting the IPv6 server.
 */
DKTP_EXPORT_API dktp_errors dktp_server_start_ipv6(qsc_socket* source,
	const dktp_local_peer_key* lpk,
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(dktp_connection_state*));

#endif
