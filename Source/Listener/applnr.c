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

#include "applnr.h"
#include "dktp.h"
#include "client.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "ipinfo.h"
#include "netutils.h"
#include "stringutils.h"

static void listener_print_prompt(void)
{
	qsc_consoleutils_print_safe("listener> ");
}

static void listener_print_error(dktp_errors error)
{
	const char* msg;

	msg = dktp_error_to_string(error);

	if (msg != NULL)
	{
		listener_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}

static void listener_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			listener_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_line("");
			listener_print_prompt();
		}
	}
}

static void listener_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0U)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void listener_print_banner(void)
{
	qsc_consoleutils_print_line("DKTP: Listener Example Project");
	qsc_consoleutils_print_line("Dual Key Tunneling Protocol listener.");
	qsc_consoleutils_print_line("Type 'dktp quit' to save the key state, close the connection.");
	qsc_consoleutils_print_line("Type 'dktp asymmetric ratchet' to ratchet the connection key.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.0.0.0a (A1)");
	qsc_consoleutils_print_line("Date:      August 16, 2025");
	qsc_consoleutils_print_line("Contact:   contact@qrcscorp.ca");
	qsc_consoleutils_print_line("");
}

static bool listener_get_storage_path(char* path, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, path);
	qsc_folderutils_append_delimiter(path);
	qsc_stringutils_concat_strings(path, pathlen, DKTP_APP_PATH);
	res = qsc_folderutils_directory_exists(path);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(path);
	}

	return res;
}

static bool listener_get_local_path(char* fpath, size_t pathlen)
{
	bool res;

	qsc_stringutils_clear_string(fpath);
	res = listener_get_storage_path(fpath, pathlen);

	if (res)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, DKTP_LISTENER_PATH);
		res = qsc_folderutils_directory_exists(fpath);

		if (res == false)
		{
			res = qsc_folderutils_create_directory(fpath);
		}
	}

	return res;
}

static bool listener_local_peer_exists(char* fpath, size_t pathlen)
{
	bool res;

	res = listener_get_local_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, DKTP_LISTENER_LOCAL_PEER_KEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static void listener_local_peer_key_save(const dktp_local_peer_key* lpk)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = listener_get_local_path(fpath, sizeof(fpath));

	if (res == true)
	{
		uint8_t slpk[DKTP_LOCAL_PEER_KEY_ENCODED_SIZE] = { 0U };

		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), DKTP_LISTENER_LOCAL_PEER_KEY_NAME);
		dktp_local_peer_key_serialize(slpk, lpk);
		qsc_fileutils_copy_stream_to_file(fpath, (const char*)slpk, sizeof(slpk));
		qsc_memutils_clear(slpk, sizeof(slpk));
	}
}

static bool listener_remote_peer_exists(char* fpath, size_t pathlen)
{
	bool res;

	res = listener_get_local_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, DKTP_SENDER_REMOTE_PEER_KEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static void listener_remote_peer_key_save(const dktp_remote_peer_key* rpk)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = listener_get_local_path(fpath, sizeof(fpath));

	if (res == true)
	{
		uint8_t srpk[DKTP_REMOTE_PEER_KEY_ENCODED_SIZE] = { 0U };

		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), DKTP_SENDER_REMOTE_PEER_KEY_NAME);
		dktp_remote_peer_key_serialize(srpk, rpk);
		qsc_fileutils_copy_stream_to_file(fpath, (const char*)srpk, sizeof(srpk));
		qsc_memutils_clear(srpk, sizeof(srpk));
	}
}

static bool listener_key_dialogue(dktp_local_peer_key* lpk, dktp_remote_peer_key* rpk, uint8_t* keyid)
{
	uint8_t srpk[DKTP_REMOTE_PEER_KEY_ENCODED_SIZE] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0U };
	size_t elen;
	bool res;

	res = listener_local_peer_exists(fpath, sizeof(fpath));

	if (res == true)
	{
		uint8_t slpk[DKTP_LOCAL_PEER_KEY_ENCODED_SIZE] = { 0U };

		res = qsc_fileutils_copy_file_to_stream(fpath, (char*)slpk, sizeof(slpk));

		if (res == true)
		{
			dktp_local_peer_key_deserialize(lpk, slpk);

			listener_print_message("The private-key has been loaded.");

			if (listener_remote_peer_exists(fpath, sizeof(fpath)) == true)
			{
				res = qsc_fileutils_copy_file_to_stream(fpath, (char*)srpk, sizeof(srpk));

				if (res == true)
				{
					dktp_remote_peer_key_deserialize(rpk, srpk);
				}
				else
				{
					listener_print_message("Could not load the sender peer key, aborting startup.");
				}
			}
			else
			{
				listener_print_message("Could not load the sender peer key, aborting startup.");
			}
		}
		else
		{
			listener_print_message("Could not load the local peer key, aborting startup.");
		}
	}
	else
	{
		/* first run, new key */
		res = listener_get_local_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_folderutils_append_delimiter(fpath);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), DKTP_LISTENER_REMOTE_PEER_KEY_NAME);

			listener_print_message("The remote peer-key was not detected, generating a new local/remote keypair...");
			res = qsc_acp_generate(keyid, DKTP_KEYID_SIZE);

			if (res == true)
			{
				dktp_generate_keypair(rpk, lpk, keyid);
				dktp_remote_peer_key_serialize(srpk, rpk);
				res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)srpk, DKTP_REMOTE_PEER_KEY_ENCODED_SIZE);

				if (res == true)
				{
					size_t slen;

					qsc_consoleutils_print_safe("listener> The peering key has been saved to ");
					qsc_consoleutils_print_line(fpath);
					listener_print_message("Distribute the peering key to intended host, and generate the remote peer key.");

					/* get the peer key of the remote host */
					listener_print_message("Enter the path of the sender's peering key:");
					listener_print_prompt();

					qsc_stringutils_clear_string(fpath);
					slen = qsc_consoleutils_get_line(fpath, sizeof(fpath)) - 1U;

					if (slen > 0U && 
						qsc_fileutils_exists(fpath) == true && 
						qsc_stringutils_string_contains(fpath, DKTP_REMOTE_PEER_KEY_EXTENSION) == true)
					{
						elen = qsc_fileutils_copy_file_to_stream(fpath, srpk, DKTP_REMOTE_PEER_KEY_ENCODED_SIZE);

						if (elen == DKTP_REMOTE_PEER_KEY_ENCODED_SIZE)
						{
							dktp_remote_peer_key_erase(rpk);
							dktp_remote_peer_key_deserialize(rpk, srpk);
							qsc_memutils_clear(srpk, sizeof(srpk));

							/* copy the remote peer key-id to the local peer key to link them */
							qsc_memutils_copy(lpk->peerid, rpk->keyid, DKTP_KEYID_SIZE);

							/* copy the file */
							listener_remote_peer_key_save(rpk);
							res = true;
						}
						else
						{
							listener_print_message("The peer key is invalid.");
						}
					}
					else
					{
						listener_print_message("The path is invalid or inaccessable.");
					}

					if (res == true)
					{
						listener_local_peer_key_save(lpk);
					}
				}
				else
				{
					listener_print_message("Could not load the key-pair, aborting startup.");
				}
			}
			else
			{
				listener_print_message("Could not create the key-pair, aborting startup.");
			}
		}
	}

	return res;
}

static void listener_receive_callback(dktp_connection_state* cns, const uint8_t* pmsg, size_t msglen)
{
	char* cmsg;

	(void)cns;
	cmsg = qsc_memutils_malloc(msglen + sizeof(char));

	if (cmsg != NULL)
	{
		qsc_memutils_clear(cmsg, msglen + sizeof(char));
		qsc_memutils_copy(cmsg, pmsg, msglen);
		qsc_consoleutils_print_safe("RECD: ");
		listener_print_string(cmsg, msglen);
		listener_print_prompt();
		qsc_memutils_alloc_free(cmsg);
	}
}

static void listener_send_loop(dktp_connection_state* cns)
{
	dktp_network_packet pkt = { 0 };
	uint8_t msgstr[DKTP_CONNECTION_MTU] = { 0U };
	/* Note: the buffer can be sized to the expected message maximum */
	uint8_t pmsg[DKTP_CONNECTION_MTU] = { 0U };
	char sin[DKTP_CONNECTION_MTU + 1U] = { 0 };
	size_t mlen;
	size_t slen;

	(void)slen;
	mlen = 0U;
	pkt.pmessage = pmsg;

	/* start the sender loop */
	while (true)
	{
		listener_print_prompt();

		if (qsc_consoleutils_line_contains(sin, "dktp quit"))
		{
			break;
		}
#if defined(DKTP_ASYMMETRIC_RATCHET)
		else if (qsc_consoleutils_line_contains(sin, "dktp asymmetric ratchet"))
		{
			dktp_send_asymmetric_ratchet_request(cns);
			qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
		}
#endif
		else
		{
			if (mlen > 0U && mlen <= DKTP_CONNECTION_MTU)
			{
				/* convert the packet to bytes */
				dktp_packet_encrypt(cns, &pkt, (const uint8_t*)sin, mlen);
				qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
				mlen = dktp_packet_to_stream(&pkt, msgstr);
				slen = qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}
		}

		mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1U;

		if (mlen > 0U && (sin[0U] == '\n' || sin[0U] == '\r'))
		{
			listener_print_message("");
			mlen = 0U;
		}
	}

	dktp_connection_close(cns, dktp_error_none, true);
}

int main(void)
{
	dktp_local_peer_key lpk = { 0 };
	dktp_remote_peer_key rpk = { 0 };
	uint8_t kid[DKTP_KEYID_SIZE] = { 0U };
	dktp_errors qerr;

	listener_print_banner();

	if (listener_key_dialogue(&lpk, &rpk, kid) == true)
	{
		listener_print_message("Waiting for a connection...");
		qerr = dktp_client_listen_ipv4(&lpk, &rpk, &listener_send_loop, &listener_receive_callback);

		if (qerr == dktp_error_none)
		{
			/* save the updated pre-shared secrets */
			listener_local_peer_key_save(&lpk);
			listener_remote_peer_key_save(&rpk);
			qsc_consoleutils_print_line("Peer keys updated and saved.");
		}
		else
		{
			listener_print_error(qerr);
			listener_print_message("The network key-exchange failed, the application will exit.");
		}
	}
	else
	{
		listener_print_message("The signature key-pair could not be created, the application will exit.");
	}

	qsc_consoleutils_print_line("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}
