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

#include "appsdr.h"
#include "client.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"

static void sender_print_prompt(void)
{
	qsc_consoleutils_print_safe("sender> ");
}

static void sender_print_error(dktp_errors error)
{
	const char* msg;

	msg = dktp_error_to_string(error);

	if (msg != NULL)
	{
		sender_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}

static void sender_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			sender_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			sender_print_prompt();
		}
	}
}

static void sender_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0U)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void sender_print_banner(void)
{
	qsc_consoleutils_print_line("DKTP: Sender Example Project");
	qsc_consoleutils_print_line("Dual Key Tunneling Protocol sender.");
	qsc_consoleutils_print_line("Enter the IP address and the server public key to connect.");
	qsc_consoleutils_print_line("Type 'dktp quit' to save the key state, close the connection.");
	qsc_consoleutils_print_line("Type 'dktp asymmetric ratchet' to ratchet the connection key.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.0.0.0a (A1)");
	qsc_consoleutils_print_line("Date:      August 16, 2025");
	qsc_consoleutils_print_line("Contact:   contact@qrcscorp.ca");
	qsc_consoleutils_print_line("");
}

static bool sender_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, DKTP_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static bool sender_get_local_path(char* fpath, size_t pathlen)
{
	bool res;

	qsc_stringutils_clear_string(fpath);
	res = sender_get_storage_path(fpath, pathlen);

	if (res)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, DKTP_SENDER_PATH);
		res = qsc_folderutils_directory_exists(fpath);

		if (res == false)
		{
			res = qsc_folderutils_create_directory(fpath);
		}
	}

	return res;
}

static bool sender_local_peer_exists(char* fpath, size_t pathlen)
{
	bool res;

	qsc_stringutils_clear_string(fpath);
	res = sender_get_local_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, DKTP_SENDER_LOCAL_PEER_KEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static void sender_local_peer_key_save(const dktp_local_peer_key* lpk)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = sender_get_local_path(fpath, sizeof(fpath));

	if (res == true)
	{
		uint8_t slpk[DKTP_LOCAL_PEER_KEY_ENCODED_SIZE] = { 0U };

		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), DKTP_SENDER_LOCAL_PEER_KEY_NAME);
		dktp_local_peer_key_serialize(slpk, lpk);
		qsc_fileutils_copy_stream_to_file(fpath, (const char*)slpk, sizeof(slpk));
		qsc_memutils_clear(slpk, sizeof(slpk));
	}
}

static void sender_remote_peer_key_save(const dktp_remote_peer_key* rpk)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = sender_get_local_path(fpath, sizeof(fpath));

	if (res == true)
	{
		uint8_t srpk[DKTP_REMOTE_PEER_KEY_ENCODED_SIZE] = { 0U };

		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), DKTP_LISTENER_REMOTE_PEER_KEY_NAME);
		dktp_remote_peer_key_serialize(srpk, rpk);
		qsc_fileutils_copy_stream_to_file(fpath, (const char*)srpk, sizeof(srpk));
		qsc_memutils_clear(srpk, sizeof(srpk));
	}
}

static bool sender_message_confirm(const char* message)
{
	QSC_ASSERT(message != NULL);

	char ans;
	bool res;

	res = false;

	if (message != NULL)
	{
		sender_print_prompt();
		qsc_consoleutils_print_line(message);
		sender_print_prompt();
		ans = qsc_consoleutils_get_char();

		if (ans == 'y' || ans == 'Y')
		{
			res = true;
		}
	}

	return res;
}

static bool sender_ipv4_dialogue(qsc_ipinfo_ipv4_address* address, dktp_local_peer_key* lpk, dktp_remote_peer_key* rpk)
{
	/* file paths are hard coded for the example. */
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	uint8_t slpk[DKTP_LOCAL_PEER_KEY_ENCODED_SIZE] = { 0 };
	uint8_t srpk[DKTP_REMOTE_PEER_KEY_ENCODED_SIZE] = { 0 };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char sadd[QSC_IPINFO_IPV4_STRNLEN] = { 0 };
	size_t elen;
	size_t slen;
	bool res;

	res = false;

	/* get the ip address from the user */
	sender_print_message("Enter the destination IPv4 address, ex. 192.168.1.1");
	sender_print_message("");
	slen = qsc_consoleutils_get_formatted_line(sadd, sizeof(sadd));

	if (slen >= QSC_IPINFO_IPV4_MINLEN)
	{
		addv4t = qsc_ipinfo_ipv4_address_from_string(sadd);

		res = (qsc_ipinfo_ipv4_address_is_valid(&addv4t) == true && 
			qsc_ipinfo_ipv4_address_is_zeroed(&addv4t) == false);

		if (res == true)
		{
			qsc_memutils_copy(address->ipv4, addv4t.ipv4, sizeof(addv4t.ipv4));
		}
		else
		{
			sender_print_message("The address format is invalid.");
		}
	}
	else
	{
		sender_print_message("The address format is invalid.");
	}

	/* get the path to the targets remote peer key */
	if (res == true)
	{
		sender_print_message("Enter the path of the listener's peering key:");
		sender_print_message("");

		slen = qsc_consoleutils_get_line(fpath, sizeof(fpath)) - 1U;
		res = false;

		if (slen > 0U && 
			qsc_fileutils_exists(fpath) == true && 
			qsc_stringutils_string_contains(fpath, DKTP_REMOTE_PEER_KEY_EXTENSION) == true)
		{
			elen = qsc_fileutils_copy_file_to_stream(fpath, (char*)srpk, DKTP_REMOTE_PEER_KEY_ENCODED_SIZE);

			if (elen == DKTP_REMOTE_PEER_KEY_ENCODED_SIZE)
			{
				char npath[QSC_SYSTEM_MAX_PATH] = { 0 };

				dktp_remote_peer_key_deserialize(rpk, srpk);

				/* store the listener's remote peer key */
				sender_get_local_path(npath, sizeof(npath));
				qsc_folderutils_append_delimiter(npath);
				qsc_stringutils_concat_strings(npath, sizeof(npath), DKTP_LISTENER_REMOTE_PEER_KEY_NAME);
				res = qsc_fileutils_file_copy(fpath, npath);
			}
			else
			{
				sender_print_message("The peering key is invalid.");
			}
		}
		else
		{
			sender_print_message("The path is invalid or inaccessable.");
		}
	}

	/* get the senders remote peer key from storage */
	if (res == true)
	{
		res = sender_local_peer_exists(fpath, sizeof(fpath));

		if (res == true)
		{
			res = qsc_fileutils_copy_file_to_stream(fpath, (char*)slpk, sizeof(slpk));

			if (res == true)
			{
				dktp_local_peer_key_deserialize(lpk, slpk);
				sender_print_message("The private-key has been loaded.");
			}
			else
			{
				sender_print_message("Could not load the key-pair, aborting startup.");
			}
		}
		else
		{
			/* first run, create a new key */
			res = sender_get_local_path(dir, sizeof(dir));

			if (res == true)
			{
				uint8_t keyid[DKTP_KEYID_SIZE] = { 0U };

				qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
				qsc_folderutils_append_delimiter(fpath);
				qsc_stringutils_concat_strings(fpath, sizeof(fpath), DKTP_SENDER_REMOTE_PEER_KEY_NAME);

				sender_print_message("The private-key was not detected, generating a new private/public keypair...");
				res = qsc_acp_generate(keyid, DKTP_KEYID_SIZE);

				if (res == true)
				{
					dktp_remote_peer_key lrpk = { 0 };

					dktp_generate_keypair(&lrpk, lpk, keyid);
					dktp_remote_peer_key_serialize(srpk, &lrpk);
					dktp_remote_peer_key_erase(&lrpk);

					/* store the serialized remote peer key */
					res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)srpk, DKTP_REMOTE_PEER_KEY_ENCODED_SIZE);
					qsc_memutils_clear(srpk, sizeof(srpk));

					if (res == true)
					{
						qsc_consoleutils_print_safe("sender> The peering key has been saved to ");
						qsc_consoleutils_print_line(fpath);
						sender_print_message("Load the peering key on the listener host.");

						/* store the local peer key */
						qsc_stringutils_clear_string(fpath);
						qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
						qsc_folderutils_append_delimiter(fpath);
						qsc_stringutils_concat_strings(fpath, sizeof(fpath), DKTP_SENDER_LOCAL_PEER_KEY_NAME);
						/* copy the remote peer key-id to the local peer key to link them */
						qsc_memutils_copy(lpk->peerid, rpk->keyid, DKTP_KEYID_SIZE);
						/* save the local peer key to file */
						dktp_local_peer_key_serialize(slpk, lpk);
						res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)slpk, sizeof(slpk));
						qsc_memutils_clear(slpk, sizeof(slpk));

						if (res == true)
						{
							sender_print_message("Load the remote-peer key on the server before connecting.");
						}
					}
					else
					{
						sender_print_message("Could not load the key-pair, aborting startup.");
					}
				}
				else
				{
					sender_print_message("Could not create the key-pair, aborting startup.");
				}
			}
		}
	}

	return res;
}

static void sender_receive_callback(dktp_connection_state* cns, const uint8_t* pmsg, size_t msglen)
{
	char* cmsg;

	(void)cns;
	cmsg = qsc_memutils_malloc(msglen + sizeof(char));

	if (cmsg != NULL)
	{
		qsc_memutils_clear(cmsg, msglen + sizeof(char));
		qsc_memutils_copy(cmsg, pmsg, msglen);
		qsc_consoleutils_print_safe("RECD: ");
		sender_print_string(cmsg, msglen);
		sender_print_prompt();
		qsc_memutils_alloc_free(cmsg);
	}
}

static void sender_send_loop(dktp_connection_state* cns)
{
	dktp_network_packet pkt = { 0 };
	/* Note: the buffer can be sized to the expected message maximum */
	uint8_t pmsg[DKTP_CONNECTION_MTU] = { 0U };
	uint8_t msgstr[DKTP_CONNECTION_MTU] = { 0U };
	char sin[DKTP_CONNECTION_MTU + 1U] = { 0 };
	size_t mlen;

	mlen = 0U;
	pkt.pmessage = pmsg;

	/* start the sender loop */
	while (true)
	{
		if (mlen > 0U)
		{
			sender_print_prompt();
		}

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
				qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}
		}

		mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1U;

		if (mlen > 0U && (sin[0U] == '\n' || sin[0U] == '\r'))
		{
			sender_print_message("");
			mlen = 0U;
		}
	}

	dktp_connection_close(cns, dktp_error_disconnect_request, true);
}

int main(void)
{
	dktp_local_peer_key lpk = { 0 };
	dktp_remote_peer_key rpk = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	bool res;

	res = false;
	sender_print_banner();

	res = sender_ipv4_dialogue(&addv4t, &lpk, &rpk);

	if (res == true)
	{
		dktp_errors err;

		res = sender_message_confirm("Connect to remote host (Y|N)?");
		sender_print_prompt();

		if (res == true)
		{
			err = dktp_client_connect_ipv4(&lpk, &rpk, &addv4t, DKTP_CLIENT_PORT, &sender_send_loop, &sender_receive_callback);

			if (err == dktp_error_none)
			{
				sender_local_peer_key_save(&lpk);
				sender_remote_peer_key_save(&rpk);
				qsc_consoleutils_print_line("Peer keys updated and saved.");
			}
			else
			{
				sender_print_error(err);
			}
		}
		else
		{
			sender_print_message("Connection aborted, exiting the application.");
		}
	}
	else
	{
		sender_print_message("Invalid input, exiting the application.");
	}
	
	sender_print_message("The application has exited. Press any key to close..");
	qsc_consoleutils_get_wait();

	return 0;
}
