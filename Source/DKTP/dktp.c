#include "dktp.h"
#include "logger.h"
#include "async.h"
#include "acp.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

void dktp_connection_close(dktp_connection_state* cns, dktp_errors err, bool notify)
{
	DKTP_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		if (qsc_socket_is_connected(&cns->target) == true)
		{
			if (notify == true)
			{
				dktp_network_packet resp = { 0U };

				/* build a disconnect message */
#if defined(DKTP_ASYMMETRIC_RATCHET)
				qsc_async_mutex_lock(cns->txlock);
#endif
				cns->txseq += 1U;
				resp.flag = dktp_flag_error_condition;
				resp.sequence = cns->txseq;
				resp.msglen = DKTP_MACTAG_SIZE + 1U;
				dktp_packet_set_utc_time(&resp);

				/* tunnel gets encrypted message */
				if (cns->exflag == dktp_flag_session_established)
				{
					uint8_t spct[DKTP_HEADER_SIZE + DKTP_MACTAG_SIZE + 1U] = { 0U };
					uint8_t pmsg[1U] = { 0U };

					resp.pmessage = spct + DKTP_HEADER_SIZE;
					dktp_packet_header_serialize(&resp, spct);
					/* the error is the message, error=none on disconnect */
					pmsg[0U] = (uint8_t)err;

					/* add the header to aad */
					qsc_rcs_set_associated(&cns->txcpr, spct, DKTP_HEADER_SIZE);
					/* encrypt the message */
					qsc_rcs_transform(&cns->txcpr, resp.pmessage, pmsg, sizeof(pmsg));
					/* send the message */
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
				else
				{
					/* pre-established phase */
					uint8_t spct[DKTP_HEADER_SIZE + 1U] = { 0U };

					dktp_packet_header_serialize(&resp, spct);
					spct[DKTP_HEADER_SIZE] = (uint8_t)err;
					/* send the message */
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
#if defined(DKTP_ASYMMETRIC_RATCHET)
				qsc_async_mutex_unlock(cns->txlock);
#endif
			}

			/* close the socket */
			qsc_socket_close_socket(&cns->target);
		}
	}
}

bool dktp_decrypt_error_message(dktp_errors* merr, dktp_connection_state* cns, const uint8_t* message)
{
	DKTP_ASSERT(cns != NULL);
	DKTP_ASSERT(message != NULL);

	dktp_network_packet pkt = { 0U };
	uint8_t dmsg[1U] = { 0U };
	const uint8_t* emsg;
	size_t mlen;
	dktp_errors err;
	bool res;

	res = false;
	err = dktp_error_invalid_input;

	if (cns->exflag == dktp_flag_session_established)
	{
		dktp_packet_header_deserialize(message, &pkt);
		emsg = message + DKTP_HEADER_SIZE;

		if (cns != NULL && message != NULL)
		{
			if (pkt.sequence == cns->rxseq + 1U)
			{
				if (cns->exflag == dktp_flag_session_established)
				{
					/* anti-replay; verify the packet time */
					if (dktp_packet_time_valid(&pkt) == true)
					{
						qsc_rcs_set_associated(&cns->rxcpr, message, DKTP_HEADER_SIZE);
						mlen = pkt.msglen - DKTP_MACTAG_SIZE;

						if (mlen == 1U)
						{
							/* authenticate then decrypt the data */
							if (qsc_rcs_transform(&cns->rxcpr, dmsg, emsg, mlen) == true)
							{
								cns->rxseq += 1;
								err = (dktp_errors)dmsg[0U];
								res = true;
							}
						}
					}
				}
			}
		}
	}

	*merr = err;

	return res;
}

void dktp_connection_state_dispose(dktp_connection_state* cns)
{
	DKTP_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		qsc_rcs_dispose(&cns->rxcpr);
		qsc_rcs_dispose(&cns->txcpr);
		qsc_memutils_clear((uint8_t*)&cns->target, sizeof(qsc_socket));
		cns->rxseq = 0U;
		cns->txseq = 0U;
		cns->cid = 0U;
		cns->exflag = dktp_flag_none;
		cns->receiver = false;
#if defined(DKTP_ASYMMETRIC_RATCHET)
		qsc_memutils_secure_erase(cns->deckey, DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE);
		qsc_memutils_secure_erase(cns->enckey, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
		qsc_memutils_secure_erase(cns->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_secure_erase(cns->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
		qsc_memutils_secure_erase(cns->pssl, DKTP_SECRET_SIZE);
		qsc_memutils_secure_erase(cns->pssr, DKTP_SECRET_SIZE);

		if (cns->txlock)
		{
			qsc_async_mutex_destroy(cns->txlock);
		}
#endif
	}
}

const char* dktp_error_to_string(dktp_errors error)
{
	const char* dsc;

	dsc = NULL;

	if (error < DKTP_ERROR_STRING_DEPTH && error >= 0)
	{
		dsc = DKTP_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}

void dktp_header_create(dktp_network_packet* packetout, dktp_flags flag, uint64_t sequence, uint32_t msglen)
{
	packetout->flag = flag;
	packetout->sequence = sequence;
	packetout->msglen = msglen;
	/* set the packet creation time */
	dktp_packet_set_utc_time(packetout);
}

dktp_errors dktp_header_validate(dktp_connection_state* cns, const dktp_network_packet* packetin, dktp_flags kexflag, dktp_flags pktflag, uint64_t sequence, uint32_t msglen)
{
	dktp_errors merr;

	if (packetin->flag == dktp_flag_error_condition)
	{
		merr = (dktp_errors)packetin->pmessage[0U];
	}
	else
	{
		if (dktp_packet_time_valid(packetin) == true)
		{
			if (packetin->msglen == msglen)
			{
				if (packetin->sequence == sequence)
				{
					if (packetin->flag == pktflag)
					{
						if (cns->exflag == kexflag)
						{
							cns->rxseq += 1U;
							merr = dktp_error_none;
						}
						else
						{
							merr = dktp_error_invalid_request;
						}
					}
					else
					{
						merr = dktp_error_invalid_request;
					}
				}
				else
				{
					merr = dktp_error_packet_unsequenced;
				}
			}
			else
			{
				merr = dktp_error_receive_failure;
			}
		}
		else
		{
			merr = dktp_error_message_time_invalid;
		}
	}

	return merr;
}

void dktp_generate_keypair(dktp_remote_peer_key* enckey, dktp_local_peer_key* deckey, const uint8_t keyid[DKTP_KEYID_SIZE])
{
	DKTP_ASSERT(deckey != NULL);
	DKTP_ASSERT(enckey != NULL);

	if (deckey != NULL && enckey != NULL)
	{

		/* add the timestamp plus duration to the key */
		deckey->expiration = qsc_timestamp_datetime_utc() + DKTP_PUBKEY_DURATION_SECONDS;
		/* set the configuration and key-identity strings */
		qsc_memutils_copy(deckey->config, DKTP_CONFIG_STRING, DKTP_CONFIG_SIZE);
		qsc_memutils_copy(deckey->keyid, keyid, DKTP_KEYID_SIZE);
		/* create the pre-shared secret */
		qsc_acp_generate(deckey->pss, DKTP_SECRET_SIZE);

		/* generate the signature key-pair */
		dktp_signature_generate_keypair(deckey->verkey, deckey->sigkey, qsc_acp_generate);

		/* copy the key expiration, config, key-id, and the signatures verification key, to the public key structure */
		enckey->expiration = deckey->expiration;
		qsc_memutils_copy(enckey->config, deckey->config, DKTP_CONFIG_SIZE);
		qsc_memutils_copy(enckey->keyid, deckey->keyid, DKTP_KEYID_SIZE);
		qsc_memutils_copy(enckey->pss, deckey->pss, DKTP_SECRET_SIZE);
		qsc_memutils_copy(enckey->verkey, deckey->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
	}
}

const char* dktp_get_error_description(dktp_messages message)
{
	const char* dsc;

	dsc = NULL;

	if (message < DKTP_MESSAGE_STRING_DEPTH && message >= 0)
	{
		dsc = DKTP_MESSAGE_STRINGS[(size_t)message];
	}

	return dsc;
}

void dktp_log_error(dktp_messages emsg, qsc_socket_exceptions err, const char* msg)
{
	DKTP_ASSERT(msg != NULL);

	char mtmp[DKTP_ERROR_STRING_WIDTH * 2] = { 0 };
	const char* perr;
	const char* phdr;
	const char* pmsg;

	pmsg = dktp_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
			qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
			dktp_logger_write(mtmp);
		}
		else
		{
			dktp_logger_write(pmsg);
		}
	}

	phdr = dktp_get_error_description(dktp_messages_socket_message);
	perr = qsc_socket_error_to_string(err);

	if (pmsg != NULL && perr != NULL)
	{
		qsc_stringutils_clear_string(mtmp);
		qsc_stringutils_copy_string(mtmp, sizeof(mtmp), phdr);
		qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), perr);
		dktp_logger_write(mtmp);
	}
}

void dktp_log_message(dktp_messages emsg)
{
	const char* msg = dktp_get_error_description(emsg);

	if (msg != NULL)
	{
		dktp_logger_write(msg);
	}
}

void dktp_log_system_error(dktp_errors err)
{
	char mtmp[DKTP_ERROR_STRING_WIDTH * 2] = { 0 };
	const char* perr;
	const char* pmsg;

	pmsg = dktp_error_to_string(err);
	perr = dktp_get_error_description(dktp_messages_system_message);

	qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
	qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), perr);

	dktp_logger_write(mtmp);
}

void dktp_log_write(dktp_messages emsg, const char* msg)
{
	DKTP_ASSERT(msg != NULL);

	const char* pmsg = dktp_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			char mtmp[DKTP_ERROR_STRING_WIDTH + 1U] = { 0 };

			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);

			if ((qsc_stringutils_string_size(msg) + qsc_stringutils_string_size(mtmp)) < sizeof(mtmp))
			{
				qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
				dktp_logger_write(mtmp);
			}
		}
		else
		{
			dktp_logger_write(pmsg);
		}
	}
}

void dktp_packet_clear(dktp_network_packet* packet)
{
	if (packet->msglen != 0U)
	{
		qsc_memutils_clear(packet->pmessage, packet->msglen);
	}

	packet->flag = (uint8_t)dktp_flag_none;
	packet->msglen = 0U;
	packet->sequence = 0U;
	packet->utctime = 0U;
}

dktp_errors dktp_packet_decrypt(dktp_connection_state* cns, uint8_t* message, size_t* msglen, const dktp_network_packet* packetin)
{
	DKTP_ASSERT(cns != NULL);
	DKTP_ASSERT(packetin != NULL);
	DKTP_ASSERT(message != NULL);
	DKTP_ASSERT(msglen != NULL);

	uint8_t hdr[DKTP_HEADER_SIZE] = { 0U };
	dktp_errors qerr;

	qerr = dktp_error_invalid_input;
	*msglen = 0U;

	if (cns != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		if (packetin->sequence == cns->rxseq + 1U)
		{
			if (cns->exflag == dktp_flag_session_established)
			{
				if (dktp_packet_time_valid(packetin) == true)
				{
					/* serialize the header and add it to the ciphers associated data */
					dktp_packet_header_serialize(packetin, hdr);

					qsc_rcs_set_associated(&cns->rxcpr, hdr, DKTP_HEADER_SIZE);
					*msglen = (size_t)packetin->msglen - DKTP_MACTAG_SIZE;

					/* authenticate then decrypt the data */
					if (qsc_rcs_transform(&cns->rxcpr, message, packetin->pmessage, *msglen) == true)
					{
						cns->rxseq += 1U;
						qerr = dktp_error_none;
					}
					else
					{
						*msglen = 0U;
						qerr = dktp_error_authentication_failure;
					}
				}
				else
				{
					qerr = dktp_error_message_time_invalid;
				}
			}
			else
			{
				qerr = dktp_error_channel_down;
			}
		}
		else
		{
			qerr = dktp_error_packet_unsequenced;
		}
	}

	return qerr;
}

dktp_errors dktp_packet_encrypt(dktp_connection_state* cns, dktp_network_packet* packetout, const uint8_t* message, size_t msglen)
{
	DKTP_ASSERT(cns != NULL);
	DKTP_ASSERT(message != NULL);
	DKTP_ASSERT(packetout != NULL);

	dktp_errors qerr;

	qerr = dktp_error_invalid_input;

	if (cns != NULL && message != NULL && packetout != NULL)
	{
		if (cns->exflag == dktp_flag_session_established && msglen != 0)
		{
			uint8_t hdr[DKTP_HEADER_SIZE] = { 0U };

#if defined(DKTP_ASYMMETRIC_RATCHET)
			qsc_async_mutex_lock(cns->txlock);
#endif
			/* assemble the encryption packet */
			cns->txseq += 1U;
			dktp_header_create(packetout, dktp_flag_encrypted_message, cns->txseq, (uint32_t)msglen + DKTP_MACTAG_SIZE);

			/* serialize the header and add it to the ciphers associated data */
			dktp_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&cns->txcpr, hdr, DKTP_HEADER_SIZE);
			/* encrypt the message */
			qsc_rcs_transform(&cns->txcpr, packetout->pmessage, message, msglen);
#if defined(DKTP_ASYMMETRIC_RATCHET)
			qsc_async_mutex_unlock(cns->txlock);
#endif
			qerr = dktp_error_none;
		}
		else
		{
			qerr = dktp_error_channel_down;
		}
	}

	return qerr;
}

void dktp_packet_error_message(dktp_network_packet* packet, dktp_errors error)
{
	DKTP_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = dktp_flag_error_condition;
		packet->msglen = DKTP_ERROR_MESSAGE_SIZE;
		packet->sequence = DKTP_ERROR_SEQUENCE;
		packet->pmessage[0U] = (uint8_t)error;
		dktp_packet_set_utc_time(packet);
	}
}

void dktp_packet_header_deserialize(const uint8_t* header, dktp_network_packet* packet)
{
	DKTP_ASSERT(header != NULL);
	DKTP_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		packet->flag = header[0U];
		pos = DKTP_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(header + pos);
		pos += DKTP_MSGLEN_SIZE;
		packet->sequence = qsc_intutils_le8to64(header + pos);
		pos += DKTP_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(header + pos);
	}
}

void dktp_packet_header_serialize(const dktp_network_packet* packet, uint8_t* header)
{
	DKTP_ASSERT(header != NULL);
	DKTP_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		header[0U] = packet->flag;
		pos = DKTP_FLAG_SIZE;
		qsc_intutils_le32to8(header + pos, packet->msglen);
		pos += DKTP_MSGLEN_SIZE;
		qsc_intutils_le64to8(header + pos, packet->sequence);
		pos += DKTP_SEQUENCE_SIZE;
		qsc_intutils_le64to8(header + pos, packet->utctime);
	}
}

void dktp_packet_set_utc_time(dktp_network_packet* packet)
{
	packet->utctime = qsc_timestamp_datetime_utc();
}

bool dktp_packet_time_valid(const dktp_network_packet* packet)
{
	DKTP_ASSERT(packet != NULL);

	uint64_t ltime;
	bool res;

	res = false;

	if (packet != NULL)
	{
		ltime = qsc_timestamp_datetime_utc();

		/* two-way variance to account for differences in system clocks */
		if (ltime > 0U && ltime < UINT64_MAX &&
			UINT64_MAX - packet->utctime >= DKTP_PACKET_TIME_THRESHOLD &&
			packet->utctime >= DKTP_PACKET_TIME_THRESHOLD)
		{
			res = (ltime >= packet->utctime - DKTP_PACKET_TIME_THRESHOLD && ltime <= packet->utctime + DKTP_PACKET_TIME_THRESHOLD);
		}
	}

	return res;
}

void dktp_local_peer_key_deserialize(dktp_local_peer_key* lpk, const uint8_t slpk[DKTP_LOCAL_PEER_KEY_ENCODED_SIZE])
{
	DKTP_ASSERT(lpk != NULL);

	size_t pos;

	qsc_memutils_copy(lpk->config, slpk, DKTP_CONFIG_SIZE);
	pos = DKTP_CONFIG_SIZE;
	lpk->expiration = qsc_intutils_le8to64((slpk + pos));
	pos += DKTP_TIMESTAMP_SIZE;
	qsc_memutils_copy(lpk->keyid, (slpk + pos), DKTP_KEYID_SIZE);
	pos += DKTP_KEYID_SIZE;
	qsc_memutils_copy(lpk->peerid, (slpk + pos), DKTP_KEYID_SIZE);
	pos += DKTP_KEYID_SIZE;
	qsc_memutils_copy(lpk->pss, (slpk + pos), DKTP_SECRET_SIZE);
	pos += DKTP_SECRET_SIZE;
	qsc_memutils_copy(lpk->sigkey, (slpk + pos), DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
	pos += DKTP_ASYMMETRIC_SIGNING_KEY_SIZE;
	qsc_memutils_copy(lpk->verkey, (slpk + pos), DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
}

void dktp_local_peer_key_erase(dktp_local_peer_key* lpk)
{
	qsc_memutils_clear(lpk->config, DKTP_CONFIG_SIZE);
	qsc_memutils_clear(lpk->keyid, DKTP_KEYID_SIZE);
	qsc_memutils_clear(lpk->peerid, DKTP_KEYID_SIZE);
	qsc_memutils_secure_erase(lpk->pss, DKTP_SECRET_SIZE);
	qsc_memutils_secure_erase(lpk->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_secure_erase(lpk->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
	lpk->expiration = 0;
}

void dktp_local_peer_key_serialize(uint8_t slpk[DKTP_LOCAL_PEER_KEY_ENCODED_SIZE], const dktp_local_peer_key* lpk)
{
	DKTP_ASSERT(lpk != NULL);

	size_t pos;

	qsc_memutils_copy(slpk, lpk->config, DKTP_CONFIG_SIZE);
	pos = DKTP_CONFIG_SIZE;
	qsc_intutils_le64to8((slpk + pos), lpk->expiration);
	pos += DKTP_TIMESTAMP_SIZE;
	qsc_memutils_copy((slpk + pos), lpk->keyid, DKTP_KEYID_SIZE);
	pos += DKTP_KEYID_SIZE;
	qsc_memutils_copy((slpk + pos), lpk->peerid, DKTP_KEYID_SIZE);
	pos += DKTP_KEYID_SIZE;
	qsc_memutils_copy((slpk + pos), lpk->pss, DKTP_SECRET_SIZE);
	pos += DKTP_SECRET_SIZE;
	qsc_memutils_copy((slpk + pos), lpk->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
	pos += DKTP_ASYMMETRIC_SIGNING_KEY_SIZE;
	qsc_memutils_copy((slpk + pos), lpk->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
}

bool dktp_remote_peer_key_compare(const dktp_remote_peer_key* a, const dktp_remote_peer_key* b)
{
	bool res;

	res = false;

	if (a->expiration == b->expiration)
	{
		if (qsc_memutils_are_equal(a->config, b->config, DKTP_CONFIG_SIZE) == true)
		{
			if (qsc_memutils_are_equal(a->keyid, b->keyid, DKTP_KEYID_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->pss, b->pss, DKTP_SECRET_SIZE) == true)
				{
					res = qsc_memutils_are_equal(a->verkey, b->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
				}
			}
		}
	}

	return res;
}

void dktp_remote_peer_key_deserialize(dktp_remote_peer_key* rpk, const uint8_t srpk[DKTP_REMOTE_PEER_KEY_ENCODED_SIZE])
{
	DKTP_ASSERT(rpk != NULL);

	size_t pos;

	qsc_memutils_copy(rpk->config, srpk, DKTP_CONFIG_SIZE);
	pos = DKTP_CONFIG_SIZE;
	rpk->expiration = qsc_intutils_le8to64((srpk + pos));
	pos += DKTP_TIMESTAMP_SIZE;
	qsc_memutils_copy(rpk->keyid, (srpk + pos), DKTP_KEYID_SIZE);
	pos += DKTP_KEYID_SIZE;
	qsc_memutils_copy(rpk->pss, (srpk + pos), DKTP_SECRET_SIZE);
	pos += DKTP_SECRET_SIZE;
	qsc_memutils_copy(rpk->verkey, (srpk + pos), DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
}

void dktp_remote_peer_key_erase(dktp_remote_peer_key* rpk)
{
	qsc_memutils_clear(rpk->config, DKTP_CONFIG_SIZE);
	qsc_memutils_clear(rpk->keyid, DKTP_KEYID_SIZE);
	qsc_memutils_secure_erase(rpk->pss, DKTP_SECRET_SIZE);
	qsc_memutils_secure_erase(rpk->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
	rpk->expiration = 0;
}

void dktp_remote_peer_key_serialize(uint8_t srpk[DKTP_REMOTE_PEER_KEY_ENCODED_SIZE], const dktp_remote_peer_key* rpk)
{
	DKTP_ASSERT(rpk != NULL);

	size_t pos;

	qsc_memutils_copy(srpk, rpk->config, DKTP_CONFIG_SIZE);
	pos = DKTP_CONFIG_SIZE;
	qsc_intutils_le64to8((srpk + pos), rpk->expiration);
	pos += DKTP_TIMESTAMP_SIZE;
	qsc_memutils_copy((srpk + pos), rpk->keyid, DKTP_KEYID_SIZE);
	pos += DKTP_KEYID_SIZE;
	qsc_memutils_copy((srpk + pos), rpk->pss, DKTP_SECRET_SIZE);
	pos += DKTP_SECRET_SIZE;
	qsc_memutils_copy((srpk + pos), rpk->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
}

void dktp_stream_to_packet(const uint8_t* pstream, dktp_network_packet* packet)
{
	DKTP_ASSERT(packet != NULL);
	DKTP_ASSERT(pstream != NULL);

	size_t pos;

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0U];
		pos = DKTP_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(pstream + pos);
		pos += DKTP_MSGLEN_SIZE;
		packet->sequence = qsc_intutils_le8to64(pstream + pos);
		pos += DKTP_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(pstream + pos);
		pos += DKTP_TIMESTAMP_SIZE;
		qsc_memutils_copy(packet->pmessage, pstream + pos, packet->msglen);
	}
}

size_t dktp_packet_to_stream(const dktp_network_packet* packet, uint8_t* pstream)
{
	DKTP_ASSERT(packet != NULL);
	DKTP_ASSERT(pstream != NULL);

	size_t pos;
	size_t res;

	res = 0U;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0U] = packet->flag;
		pos = DKTP_FLAG_SIZE;
		qsc_intutils_le32to8(pstream + pos, packet->msglen);
		pos += DKTP_MSGLEN_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->sequence);
		pos += DKTP_SEQUENCE_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->utctime);
		pos += DKTP_TIMESTAMP_SIZE;
		qsc_memutils_copy(pstream + pos, packet->pmessage, packet->msglen);
		res = (size_t)DKTP_HEADER_SIZE + packet->msglen;
	}

	return res;
}
