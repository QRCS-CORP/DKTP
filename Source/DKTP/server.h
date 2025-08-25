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
