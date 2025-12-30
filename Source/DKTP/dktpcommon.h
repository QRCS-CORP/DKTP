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

#ifndef DKTP_MASTER_COMMON_H
#define DKTP_MASTER_COMMON_H

#include "qsccommon.h"
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/**
* \internal
* \file common.h
* \brief DKTP common includes and definitions
* \note These are internal definitions.
*/

/** \cond DOXYGEN_IGNORE */

/*!
\def DKTP_DLL_API
* \brief Enables the dll api exports
*/
#if defined(_DLL)
#	define DKTP_DLL_API
#endif
/*!
\def DKTP_EXPORT_API
* \brief The api export prefix
*/
#if defined(DKTP_DLL_API)
#	if defined(QSC_SYSTEM_COMPILER_MSC)
#		if defined(DKTP_DLL_IMPORT)
#			define DKTP_EXPORT_API __declspec(dllimport)
#		else
#			define DKTP_EXPORT_API __declspec(dllexport)
#		endif
#	elif defined(QSC_SYSTEM_COMPILER_GCC)
#		if defined(DKTP_DLL_IMPORT)
#		define DKTP_EXPORT_API __attribute__((dllimport))
#		else
#		define DKTP_EXPORT_API __attribute__((dllexport))
#		endif
#	else
#		if defined(__SUNPRO_C)
#			if !defined(__GNU_C__)
#				define DKTP_EXPORT_API __attribute__ (visibility(__global))
#			else
#				define DKTP_EXPORT_API __attribute__ __global
#			endif
#		elif defined(_MSG_VER)
#			define DKTP_EXPORT_API extern __declspec(dllexport)
#		else
#			define DKTP_EXPORT_API __attribute__ ((visibility ("default")))
#		endif
#	endif
#else
#	define DKTP_EXPORT_API
#endif

#if defined(DEBUG) || defined(_DEBUG) || defined(__DEBUG__) || (defined(__GNUC__) && !defined(__OPTIMIZE__))
  /*!
   * \def DKTP_DEBUG_MODE
   * \brief Defined when the build is in debug mode.
   */
#	define DKTP_DEBUG_MODE
#endif

#ifdef DKTP_DEBUG_MODE
  /*!
   * \def DKTP_ASSERT
   * \brief Define the DKTP_ASSERT function and guarantee it as debug only.
   */
#  define DKTP_ASSERT(expr) assert(expr)
#else
#  define DKTP_ASSERT(expr) ((void)0)
#endif

/** \endcond DOXYGEN_IGNORE */

#endif
