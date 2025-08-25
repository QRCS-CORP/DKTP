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

#ifndef DKTP_CONNECTIONS_H
#define DKTP_CONNECTIONS_H

#include "dktpcommon.h"
#include "dktp.h"

/**
 * \file connections.h
 * \brief The server connection collection.
 *
 * \details
 * This header file defines internal functions for managing the collection of connection state objects
 * used by the DKTP server. The connections collection maintains an array of connection states (of type
 * \c dktp_connection_state), each representing an active or available socket connection. The functions
 * declared herein allow for:
 *
 * - Checking the active status of a connection slot.
 * - Adding new connection states to the collection.
 * - Retrieving connection states by instance or index.
 * - Initializing and disposing of the connections collection.
 * - Resetting and clearing connection states.
 * - Determining the capacity and availability of the collection.
 * - Running self-tests to ensure the collection operates correctly.
 *
 * \note These functions are internal and non-exportable.
 */

/**
 * \brief Determine if a connection state at the specified index is active.
 *
 * \details
 * This function checks whether the connection state at the provided index in the connections collection
 * is currently marked as active. This is useful for verifying if a connection slot is in use.
 *
 * \param index The index number of the connection slot in the collection.
 *
 * \return Returns true if the connection at the specified index is active; otherwise, false.
 */
bool dktp_connections_active(size_t index);

/**
 * \brief Add a new connection state to the collection and mark it as active.
 *
 * \details
 * This function creates a new connection state, adds it to the DKTP connections collection, and sets its
 * status to active. If the collection has reached its maximum capacity or if the allocation fails,
 * the function returns NULL.
 *
 * \return A pointer to the newly added connection state, or NULL on failure.
 */
dktp_connection_state* dktp_connections_add(void);

/**
 * \brief Get the number of available (inactive) connection states in the collection.
 *
 * \details
 * This function returns the count of connection slots in the collection that are currently available
 * (i.e., not active). This number indicates how many additional connections can be accommodated.
 *
 * \return The number of available connection state items.
 */
size_t dktp_connections_available(void);

/**
 * \brief Retrieve a connection state by its unique instance number.
 *
 * \details
 * This function locates and returns the connection state corresponding to the specified instance number.
 * The instance number uniquely identifies a connection within the collection.
 *
 * \param instance The unique instance number of the connection.
 *
 * \return A pointer to the connection state if found; otherwise, NULL.
 */
dktp_connection_state* dktp_connections_get(uint32_t instance);

/**
 * \brief Initialize the DKTP connections collection.
 *
 * \details
 * This function sets up the internal connections collection by creating an initial set of connection
 * states. The \c count parameter specifies the number of connection states to create initially (minimum of one),
 * and \c maximum defines the upper limit of connection states the collection can hold.
 *
 * \param count The initial number of connection states to create (must be at least one).
 * \param maximum The maximum number of connection states allowed in the collection (must be greater than or equal to \c count).
 */
void dktp_connections_initialize(size_t count, size_t maximum);

/**
 * \brief Clear all connection states in the collection.
 *
 * \details
 * This function resets or erases all entries in the connections collection, marking each as inactive.
 * This operation prepares the collection for new connection assignments without disposing of the collection itself.
 */
void dktp_connections_clear(void);

/**
 * \brief Dispose of the DKTP connections collection.
 *
 * \details
 * This function releases all resources allocated for the connections collection and cleans up its internal state.
 * It should be called when the connections collection is no longer required.
 */
void dktp_connections_dispose(void);

/**
 * \brief Retrieve a connection state pointer by its collection index.
 *
 * \details
 * This function returns the connection state pointer located at the specified index in the collection.
 * If the index is invalid or out of bounds, the function returns NULL.
 *
 * \param index The index of the connection state within the collection.
 *
 * \return A pointer to the connection state if the index is valid; otherwise, NULL.
 */
dktp_connection_state* dktp_connections_index(size_t index);

/**
 * \brief Check if the connections collection is full.
 *
 * \details
 * This function determines whether the connections collection has reached its maximum capacity.
 * When the collection is full, no additional connection states can be added.
 *
 * \return Returns true if the collection is full; otherwise, false.
 */
bool dktp_connections_full(void);

/**
 * \brief Retrieve the next available (inactive) connection state from the collection.
 *
 * \details
 * This function searches for and returns a pointer to the next available connection state in the collection.
 * If all connection slots are active, the function returns NULL.
 *
 * \return A pointer to the next available connection state, or NULL if none are available.
 */
dktp_connection_state* dktp_connections_next(void);

/**
 * \brief Reset a specific connection state in the collection.
 *
 * \details
 * This function resets the connection state identified by the provided instance number. Resetting a connection
 * typically involves clearing its data and marking it as inactive so that the slot can be reused.
 *
 * \param instance The unique instance number of the connection to reset.
 */
void dktp_connections_reset(uint32_t instance);

/**
 * \brief Get the total number of connection state items in the collection.
 *
 * \details
 * This function returns the total number of connection states maintained in the collection, including both active
 * and inactive items.
 *
 * \return The total size of the connections collection.
 */
size_t dktp_connections_size(void);

#if defined(DKTP_DEBUG_MODE)
/**
 * \brief Run the self-test routine for the connections collection.
 *
 * \details
 * This function executes a series of internal tests to verify the proper functioning of the DKTP connections collection.
 * The self-test routine may include the following:
 *
 * - Adding new connection states and verifying they are correctly marked as active.
 * - Checking the active status of connection slots.
 * - Retrieving connection states by instance or index.
 * - Resetting connection states and confirming they become inactive.
 * - Ensuring that the collection correctly reports the number of available and total connection slots.
 *
 * The self-test is used to validate the robustness and reliability of the connection management subsystem.
 */
void dktp_connections_self_test(void);
#endif

#endif
