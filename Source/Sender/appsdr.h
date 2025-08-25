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

#ifndef DKTP_SENDER_APP_H
#define DKTP_SENDER_APP_H

#include "dktpcommon.h"

/**
* \file appclt.h
* \brief The client application
* Version 1.2a: 2022-05-01
*/

static const char DKTP_APP_PATH[] = "DKTP";
static const char DKTP_LISTENER_REMOTE_PEER_KEY_NAME[] = "listener_remote_peer_key.dpkey";
static const char DKTP_LISTENER_PATH[] = "Listener";
static const char DKTP_REMOTE_PEER_KEY_EXTENSION[] = ".dpkey";
static const char DKTP_SENDER_LOCAL_PEER_KEY_NAME[] = "sender_local_peer_key.dskey";
static const char DKTP_SENDER_PATH[] = "Sender";
static const char DKTP_SENDER_REMOTE_PEER_KEY_NAME[] = "sender_remote_peer_key.dpkey";

#endif
