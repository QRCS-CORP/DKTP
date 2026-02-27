#include "client.h"
#include "kex.h"
#include "logger.h"
#include "acp.h"
#include "async.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "socketserver.h"
#include "timestamp.h"

/** \cond */
typedef struct client_receiver_state
{
	dktp_connection_state* pcns;
	void (*callback)(dktp_connection_state*, const uint8_t*, size_t);
} client_receiver_state;

typedef struct listener_receiver_state
{
	dktp_connection_state* pcns;
	void (*callback)(dktp_connection_state*, const uint8_t*, size_t);
} listener_receiver_state;

typedef struct listener_receive_loop_args
{
	listener_receiver_state* prcv;
} listener_receive_loop_args;
/** \endcond */

#if defined(DKTP_ASYMMETRIC_RATCHET)
/** \cond */
#define DKTP_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE (DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE + DKTP_MACTAG_SIZE)
#define DKTP_ASYMMETRIC_RATCHET_REQUEST_PACKET_SIZE (DKTP_HEADER_SIZE + DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE + DKTP_MACTAG_SIZE)
#define DKTP_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE (DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE + DKTP_MACTAG_SIZE)
#define DKTP_ASYMMETRIC_RATCHET_RESPONSE_PACKET_SIZE (DKTP_HEADER_SIZE + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE + DKTP_MACTAG_SIZE)

//static dktp_asymmetric_cipher_keypair* m_ckeyset;
//static dktp_asymmetric_signature_keypair* m_skeyset;
/** \endcond */
#endif

/* Private Functions */

/** \cond */
static void client_state_initialize(dktp_kex_client_state* kcs, dktp_connection_state* cns, const dktp_local_peer_key* lpk, const dktp_remote_peer_key* rpk)
{
	qsc_memutils_copy(kcs->verkey, lpk->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_copy(kcs->sigkey, lpk->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kcs->keyid, rpk->keyid, DKTP_KEYID_SIZE);
	qsc_memutils_copy(kcs->rverkey, rpk->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_copy(kcs->pssl, lpk->pss, DKTP_SECRET_SIZE);
	qsc_memutils_copy(kcs->pssr, rpk->pss, DKTP_SECRET_SIZE);
	kcs->expiration = rpk->expiration;
#if defined(DKTP_ASYMMETRIC_RATCHET)
	cns->txlock = qsc_async_mutex_create();
#endif
	cns->target.instance = qsc_acp_uint32();
	qsc_rcs_dispose(&cns->rxcpr);
	qsc_rcs_dispose(&cns->txcpr);
	cns->exflag = dktp_flag_none;
	cns->cid = 0U;
	cns->rxseq = 0U;
	cns->txseq = 0U;
	cns->receiver = false;
}

static void listener_state_initialize(dktp_kex_server_state* kss, listener_receiver_state* rcv, const dktp_local_peer_key* lpk, const dktp_remote_peer_key* rpk)
{
	qsc_memutils_copy(kss->keyid, lpk->keyid, DKTP_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, lpk->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kss->verkey, lpk->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_copy(kss->rverkey, rpk->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
	kss->expiration = lpk->expiration;
	qsc_memutils_secure_erase((uint8_t*)&rcv->pcns->rxcpr, sizeof(qsc_rcs_state));
	qsc_memutils_secure_erase((uint8_t*)&rcv->pcns->txcpr, sizeof(qsc_rcs_state));
	qsc_memutils_copy(kss->pssl, lpk->pss, DKTP_SECRET_SIZE);
	qsc_memutils_copy(kss->pssr, rpk->pss, DKTP_SECRET_SIZE);
	rcv->pcns->exflag = dktp_flag_none;
	rcv->pcns->cid = 0U;
	rcv->pcns->rxseq = 0U;
	rcv->pcns->txseq = 0U;
	rcv->pcns->receiver = true;
}

#if defined(DKTP_ASYMMETRIC_RATCHET)
static void asymmetric_ratchet_update(qsc_rcs_state* cpr, uint8_t* pss, const uint8_t* ssec, bool encrypt)
{
	uint8_t prnd[DKTP_SYMMETRIC_KEY_SIZE + DKTP_SYMMETRIC_NONCE_SIZE] = { 0U };

	/* compute the new cipher key and nonce */
	qsc_cshake512_compute(prnd, sizeof(prnd), ssec, DKTP_SECRET_SIZE, (uint8_t*)DKTP_DOMAIN_IDENTITY_STRING, DKTP_DOMAIN_IDENTITY_SIZE, pss, DKTP_SECRET_SIZE);

	/* initialize and raise host channel */
	qsc_rcs_keyparams kp;
	kp.key = prnd;
	kp.keylen = DKTP_SYMMETRIC_KEY_SIZE;
	kp.nonce = ((uint8_t*)prnd + DKTP_SYMMETRIC_KEY_SIZE);
	kp.info = NULL;
	kp.infolen = 0U;
	qsc_rcs_initialize(cpr, &kp, encrypt);
	qsc_memutils_secure_erase((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));

	/* update the pre-shared secret */
	qsc_cshake512_compute(pss, DKTP_SECRET_SIZE, prnd, DKTP_SECRET_SIZE, NULL, 0, pss, DKTP_SECRET_SIZE);
	qsc_memutils_secure_erase(prnd, sizeof(prnd));

}

static bool asymmetric_ratchet_response(dktp_connection_state* cns, const dktp_network_packet* packetin)
{
	size_t mlen;
	bool res;

	res = false;
	cns->rxseq += 1U;

	if (packetin->sequence == cns->rxseq && packetin->msglen == DKTP_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE)
	{
		if (dktp_packet_time_valid(packetin) == true)
		{
			uint8_t imsg[DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE] = { 0U };
			uint8_t hdr[DKTP_HEADER_SIZE] = { 0U };

			/* serialize the header and add it to the ciphers associated data */
			dktp_packet_header_serialize(packetin, hdr);
			qsc_rcs_set_associated(&cns->rxcpr, hdr, DKTP_HEADER_SIZE);
			mlen = packetin->msglen - (size_t)DKTP_MACTAG_SIZE;

			/* authenticate then decrypt the data */
			if (qsc_rcs_transform(&cns->rxcpr, imsg, packetin->pmessage, mlen) == true)
			{
				uint8_t rhash[DKTP_HASH_SIZE] = { 0U };
				const uint8_t* rpub = imsg + DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE;

				/* verify the signature */
				if (dktp_signature_verify(rhash, &mlen, imsg, DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE, cns->verkey) == true)
				{
					uint8_t lhash[DKTP_HASH_SIZE] = { 0U };

					/* hash the public key */
					qsc_sha3_compute512(lhash, rpub, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);

					/* compare the signed hash with the local hash */
					if (qsc_intutils_verify(rhash, lhash, DKTP_HASH_SIZE) == 0)
					{
						dktp_network_packet pkt = { 0 };
						uint8_t omsg[DKTP_ASYMMETRIC_RATCHET_RESPONSE_PACKET_SIZE] = { 0U };
						uint8_t mtmp[DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE] = { 0 };
						uint8_t khash[DKTP_HASH_SIZE] = { 0U };
						uint8_t ssec[DKTP_SYMMETRIC_KEY_SIZE] = { 0U };
						size_t slen;

						mlen = DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE;

						/* encapsulate a secret with the public key */
						dktp_cipher_encapsulate(ssec, mtmp + mlen, rpub, qsc_acp_generate);

						/* compute a hash of the cipher-text */
						qsc_sha3_compute512(khash, mtmp + mlen, DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE);

						/* sign the hash */
						mlen = 0U;
						dktp_signature_sign(mtmp, &mlen, khash, sizeof(khash), cns->sigkey, qsc_acp_generate);

						/* create the outbound packet */
#if defined(DKTP_ASYMMETRIC_RATCHET)
						qsc_async_mutex_lock(cns->txlock);
#endif
						cns->txseq += 1U;
						pkt.flag = dktp_flag_asymmetric_ratchet_response;
						pkt.msglen = DKTP_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE;
						pkt.sequence = cns->txseq;
						mlen += DKTP_HEADER_SIZE + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE;

						/* serialize the header */
						dktp_packet_header_serialize(&pkt, omsg);
						/* add the header to the ciphers associated data */
						qsc_rcs_set_associated(&cns->txcpr, omsg, DKTP_HEADER_SIZE);
						/* encrypt the message */
						qsc_rcs_transform(&cns->txcpr, omsg + DKTP_HEADER_SIZE, mtmp, sizeof(mtmp));
						mlen += DKTP_MACTAG_SIZE;
#if defined(DKTP_ASYMMETRIC_RATCHET)
						qsc_async_mutex_unlock(cns->txlock);
#endif
						/* send the encrypted message */
						slen = qsc_socket_send(&cns->target, omsg, mlen, qsc_socket_send_flag_none);

						if (slen == mlen)
						{
							/* pass the secret to the symmetric ratchet */
							// receiver
							asymmetric_ratchet_update(&cns->rxcpr, cns->pssr, ssec, false);
							res = true;
						}

						qsc_memutils_secure_erase(ssec, sizeof(ssec));
					}
				}
			}
		}
	}

	return res;
}

static bool asymmetric_ratchet_finalize(dktp_connection_state* cns, const dktp_network_packet* packetin)
{
	uint8_t hdr[DKTP_HEADER_SIZE] = { 0 };
	uint8_t imsg[DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE] = { 0 };
	uint8_t rhash[DKTP_HASH_SIZE] = { 0 };
	uint8_t ssec[DKTP_SYMMETRIC_KEY_SIZE] = { 0 };
	size_t mlen;
	size_t mpos;
	bool res;

	cns->rxseq += 1U;

	res = false;
	mlen = 0U;
	mpos = DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE;

	if (packetin->sequence == cns->rxseq && packetin->msglen == DKTP_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE)
	{
		if (dktp_packet_time_valid(packetin) == true)
		{
			/* serialize the header and add it to the ciphers associated data */
			dktp_packet_header_serialize(packetin, hdr);
			qsc_rcs_set_associated(&cns->rxcpr, hdr, DKTP_HEADER_SIZE);
			mlen = packetin->msglen - (size_t)DKTP_MACTAG_SIZE;

			/* authenticate then decrypt the data */
			if (qsc_rcs_transform(&cns->rxcpr, imsg, packetin->pmessage, mlen) == true)
			{
				/* verify the signature using the senders public key */
				if (dktp_signature_verify(rhash, &mlen, imsg, mpos, cns->verkey) == true)
				{
					uint8_t lhash[DKTP_HASH_SIZE] = { 0U };

					/* compute a hash of cipher-text */
					qsc_sha3_compute512(lhash, imsg + mpos, DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE);

					/* verify the embedded hash against a hash of the cipher-text */
					if (qsc_intutils_verify(rhash, lhash, DKTP_HASH_SIZE) == 0)
					{
#if defined(DKTP_ASYMMETRIC_RATCHET)
						qsc_async_mutex_lock(cns->txlock);
#endif
						/* decapsulate the secret */
						res = dktp_cipher_decapsulate(ssec, imsg + mpos, cns->deckey);

						if (res == true)
						{
							/* pass the secret to the symmetric ratchet */
							asymmetric_ratchet_update(&cns->txcpr, cns->pssl, ssec, true);
						}

						qsc_memutils_secure_erase(ssec, sizeof(ssec));
						qsc_memutils_secure_erase(cns->deckey, DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE);
						qsc_memutils_secure_erase(cns->enckey, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);

#if defined(DKTP_ASYMMETRIC_RATCHET)
						qsc_async_mutex_unlock(cns->txlock);
#endif
					}
				}
			}
		}
	}

	return res;
}
#endif

static void client_kex_reset(dktp_kex_client_state* kcs)
{
	DKTP_ASSERT(kcs != NULL);

	if (kcs != NULL)
	{
		qsc_memutils_secure_erase(kcs->deckey, DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE);
		qsc_memutils_secure_erase(kcs->enckey, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
		qsc_memutils_clear(kcs->keyid, DKTP_KEYID_SIZE);
		qsc_memutils_secure_erase(kcs->pssl, DKTP_SECRET_SIZE);
		qsc_memutils_secure_erase(kcs->pssr, DKTP_SECRET_SIZE);
		qsc_memutils_secure_erase(kcs->rverkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
		qsc_memutils_clear(kcs->schash, DKTP_HASH_SIZE);
		qsc_memutils_secure_erase(kcs->secl, DKTP_SECRET_SIZE);
		qsc_memutils_secure_erase(kcs->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_secure_erase(kcs->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
		kcs->expiration = 0U;
	}
}

static void server_kex_reset(dktp_kex_server_state* kss)
{
	DKTP_ASSERT(kss != NULL);

	if (kss != NULL)
	{
		qsc_memutils_secure_erase(kss->deckey, DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE);
		qsc_memutils_secure_erase(kss->enckey, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
		qsc_memutils_clear(kss->keyid, DKTP_KEYID_SIZE);
		qsc_memutils_secure_erase(kss->pssl, DKTP_SECRET_SIZE);
		qsc_memutils_secure_erase(kss->pssr, DKTP_SECRET_SIZE);
		qsc_memutils_secure_erase(kss->rverkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
		qsc_memutils_clear(kss->schash, DKTP_HASH_SIZE);
		qsc_memutils_secure_erase(kss->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_secure_erase(kss->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
		kss->expiration = 0U;
	}
}

static void client_connection_dispose(client_receiver_state* prcv)
{
	/* send a close notification to the server */
	if (qsc_socket_is_connected(&prcv->pcns->target) == true)
	{
		dktp_connection_close(prcv->pcns, dktp_error_none, true);
	}

	/* dispose of resources */
	dktp_connection_state_dispose(prcv->pcns);
}

static void client_receive_loop(void* prcv)
{
	DKTP_ASSERT(prcv != NULL);

	dktp_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	client_receiver_state* pprcv;
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	dktp_errors err;

	pprcv = (client_receiver_state*)prcv;
	qsc_memutils_copy(cadd, (const char*)pprcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(DKTP_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (pprcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0U;
			slen = 0U;
			qsc_memutils_clear(rbuf, DKTP_HEADER_SIZE);

			plen = qsc_socket_peek(&pprcv->pcns->target, rbuf, DKTP_HEADER_SIZE);

			if (plen == DKTP_HEADER_SIZE)
			{
				dktp_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0U && pkt.msglen <= DKTP_MESSAGE_MAX)
				{
					uint8_t* rtmp;

					plen = pkt.msglen + DKTP_HEADER_SIZE;
					rtmp = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rtmp != NULL)
					{
						rbuf = rtmp;
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&pprcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0U)
						{
							pkt.pmessage = rbuf + DKTP_HEADER_SIZE;

							if (pkt.flag == dktp_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;
								slen -= DKTP_MACTAG_SIZE;
								rmsg = (uint8_t*)qsc_memutils_malloc(slen);

								if (rmsg != NULL)
								{
									qsc_memutils_clear(rmsg, slen);
									err = dktp_packet_decrypt(pprcv->pcns, rmsg, &mlen, &pkt);

									if (err == dktp_error_none)
									{
										pprcv->callback(pprcv->pcns, rmsg, mlen);
									}
									else
									{
										/* close the connection on authentication failure */
										dktp_log_write(dktp_messages_decryption_fail, cadd);
										break;
									}

									qsc_memutils_clear(rmsg, slen);
									qsc_memutils_alloc_free(rmsg);
								}
								else
								{
									/* close the connection on memory allocation failure */
									dktp_log_write(dktp_messages_allocate_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == dktp_flag_connection_terminate)
							{
								dktp_log_write(dktp_messages_disconnect, cadd);
								break;
							}
							else if (pkt.flag == dktp_flag_keep_alive_request)
							{
								const size_t klen = DKTP_HEADER_SIZE + DKTP_TIMESTAMP_SIZE;
								/* copy the keep-alive packet and send it back */
								pkt.flag = dktp_flag_keep_alive_response;
								dktp_packet_header_serialize(&pkt, rbuf);
								qsc_socket_send(&pprcv->pcns->target, rbuf, klen, qsc_socket_send_flag_none);
							}
#if defined(DKTP_ASYMMETRIC_RATCHET)
							else if (pkt.flag == dktp_flag_asymmetric_ratchet_request)
							{
								if (asymmetric_ratchet_response(pprcv->pcns, &pkt) == false)
								{
									dktp_log_write(dktp_messages_asymmetric_ratchet, (const char*)pprcv->pcns->target.address);
									break;
								}
							}
							else if (pkt.flag == dktp_flag_asymmetric_ratchet_response)
							{
								if (asymmetric_ratchet_finalize(pprcv->pcns, &pkt) == false)
								{
									dktp_log_write(dktp_messages_asymmetric_ratchet, (const char*)pprcv->pcns->target.address);
									break;
								}
							}
#endif
							else
							{
								qsc_socket_exceptions serr = qsc_socket_get_last_error();

								if (serr != qsc_socket_exception_success)
								{
									dktp_log_error(dktp_messages_receive_fail, serr, cadd);

									/* fatal socket errors */
									if (serr == qsc_socket_exception_circuit_reset ||
										serr == qsc_socket_exception_circuit_terminated ||
										serr == qsc_socket_exception_circuit_timeout ||
										serr == qsc_socket_exception_dropped_connection ||
										serr == qsc_socket_exception_network_failure ||
										serr == qsc_socket_exception_shut_down)
									{
										dktp_log_write(dktp_messages_connection_fail, cadd);
										break;
									}
								}
							}
						}
						else
						{
							dktp_log_write(dktp_messages_receive_fail, cadd);
							break;
						}

						qsc_memutils_clear(rbuf, sizeof(plen));
					}
				}
				else
				{
					/* close the connection on memory allocation failure */
					dktp_log_write(dktp_messages_allocate_fail, cadd);
					break;
				}
			}
			else
			{
				dktp_log_write(dktp_messages_receive_fail, cadd);
				break;
			}
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		dktp_log_write(dktp_messages_allocate_fail, cadd);
	}
}

static void listener_receive_loop(listener_receiver_state* prcv)
{
	DKTP_ASSERT(prcv != NULL);

	dktp_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	dktp_errors err;

	err = dktp_error_general_failure;
	qsc_memutils_copy(cadd, (const char*)prcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(DKTP_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0U;
			slen = 0U;
			qsc_memutils_clear(rbuf, DKTP_HEADER_SIZE);

			plen = qsc_socket_peek(&prcv->pcns->target, rbuf, DKTP_HEADER_SIZE);

			if (plen == DKTP_HEADER_SIZE)
			{
				dktp_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0U && pkt.msglen <= DKTP_MESSAGE_MAX)
				{
					uint8_t* rtmp;

					plen = pkt.msglen + DKTP_HEADER_SIZE;
					rtmp = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rtmp != NULL)
					{
						rbuf = rtmp;
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0U)
						{
							pkt.pmessage = rbuf + DKTP_HEADER_SIZE;

							if (pkt.flag == dktp_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;
								slen -= DKTP_MACTAG_SIZE;
								rmsg = (uint8_t*)qsc_memutils_malloc(slen);

								if (rmsg != NULL)
								{
									qsc_memutils_clear(rmsg, slen);
									err = dktp_packet_decrypt(prcv->pcns, rmsg, &mlen, &pkt);

									if (err == dktp_error_none)
									{
										prcv->callback(prcv->pcns, rmsg, mlen);
									}
									else
									{
										/* close the connection on authentication failure */
										dktp_log_write(dktp_messages_decryption_fail, cadd);
										break;
									}

									qsc_memutils_clear(rmsg, slen);
									qsc_memutils_alloc_free(rmsg);
								}
								else
								{
									/* close the connection on memory allocation failure */
									dktp_log_write(dktp_messages_allocate_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == dktp_flag_error_condition)
							{
								/* anti-dos: break on error message is conditional
								   on succesful authentication/decryption */
								if (dktp_decrypt_error_message(&err, prcv->pcns, rbuf) == true)
								{
									dktp_log_system_error(err);
									break;
								}
							}
			#if defined(DKTP_ASYMMETRIC_RATCHET)
							else if (pkt.flag == dktp_flag_asymmetric_ratchet_request)
							{
								if (asymmetric_ratchet_response(prcv->pcns, &pkt) == false)
								{
									dktp_log_write(dktp_messages_asymmetric_ratchet, (const char*)prcv->pcns->target.address);
									break;
								}
							}
							else if (pkt.flag == dktp_flag_asymmetric_ratchet_response)
							{
								if (asymmetric_ratchet_finalize(prcv->pcns, &pkt) == false)
								{
									dktp_log_write(dktp_messages_asymmetric_ratchet, (const char*)prcv->pcns->target.address);
									break;
								}
							}
			#endif
							else
							{
								qsc_socket_exceptions serr = qsc_socket_get_last_error();

								if (serr != qsc_socket_exception_success)
								{
									dktp_log_error(dktp_messages_receive_fail, serr, cadd);

									/* fatal socket errors */
									if (serr == qsc_socket_exception_circuit_reset ||
										serr == qsc_socket_exception_circuit_terminated ||
										serr == qsc_socket_exception_circuit_timeout ||
										serr == qsc_socket_exception_dropped_connection ||
										serr == qsc_socket_exception_network_failure ||
										serr == qsc_socket_exception_shut_down)
									{
										dktp_log_write(dktp_messages_connection_fail, cadd);
									}
								}
							}
						}
						else
						{
							dktp_log_write(dktp_messages_receive_fail, cadd);
							break;
						}
					}
				}
				else
				{
					/* close the connection on memory allocation failure */
					dktp_log_write(dktp_messages_allocate_fail, cadd);
					break;
				}
			}
			else
			{
				dktp_log_write(dktp_messages_receive_fail, cadd);
				break;
			}
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		dktp_log_write(dktp_messages_allocate_fail, cadd);
	}
}

static void listener_receive_loop_wrapper(void* state)
{
	listener_receive_loop_args* args = (listener_receive_loop_args*)state;

	if (args != NULL)
	{
		listener_receive_loop(args->prcv);
	}
}

static dktp_errors listener_start(dktp_local_peer_key* lpk, 
	dktp_remote_peer_key* rpk, 
	listener_receiver_state* prcv, 
	void (*send_func)(dktp_connection_state*))
{
	DKTP_ASSERT(lpk != NULL);
	DKTP_ASSERT(prcv != NULL);
	DKTP_ASSERT(send_func != NULL);

	listener_receive_loop_args largs = { 0 };
	dktp_kex_server_state* pkss;
	dktp_errors err;

	dktp_logger_initialize(NULL);
	err = dktp_error_invalid_input;
	pkss = (dktp_kex_server_state*)qsc_memutils_malloc(sizeof(dktp_kex_server_state));

	if (pkss != NULL)
	{
		qsc_memutils_clear((uint8_t*)pkss, sizeof(dktp_kex_server_state));

		/* initialize the kex */
		listener_state_initialize(pkss, prcv, lpk, rpk);
		err = dktp_kex_server_key_exchange(pkss, prcv->pcns);

		if (err == dktp_error_none)
		{
			/* update the pre-shared keys after the exchange */
			qsc_memutils_copy(lpk->pss, pkss->pssl, DKTP_SECRET_SIZE);
			qsc_memutils_copy(rpk->pss, pkss->pssr, DKTP_SECRET_SIZE);

#if defined(DKTP_ASYMMETRIC_RATCHET)
			/* store the local signing key and the remote verify key for asymmetyric ratchet option */
			qsc_memutils_copy(prcv->pcns->sigkey, lpk->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
			qsc_memutils_copy(prcv->pcns->verkey, pkss->rverkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
			/* copy the pre-shared secrets if ratchet enabled */
			qsc_memutils_copy(prcv->pcns->pssl, pkss->pssl, DKTP_SECRET_SIZE);
			qsc_memutils_copy(prcv->pcns->pssr, pkss->pssr, DKTP_SECRET_SIZE);
#endif
		}

		/* dispose of the kex state */
		server_kex_reset(pkss);
		qsc_memutils_alloc_free(pkss);
		pkss = NULL;

		if (err == dktp_error_none)
		{
			/* initialize the receiver loop on a new thread */
			largs.prcv = prcv;
			qsc_async_thread_create(&listener_receive_loop_wrapper, &largs);

			/* start the send loop on the *main* thread */
			send_func(prcv->pcns);

#if defined(DKTP_ASYMMETRIC_RATCHET)
			/* update the pre-shared secrets */
			qsc_memutils_copy(lpk->pss, prcv->pcns->pssl, DKTP_SECRET_SIZE);
			qsc_memutils_copy(rpk->pss, prcv->pcns->pssr, DKTP_SECRET_SIZE);
			qsc_memutils_secure_erase(prcv->pcns->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
			qsc_memutils_secure_erase(prcv->pcns->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif
		}
	}

	return err;
}

/** \endcond */

/* Public Functions */

/* The Signal ratchet system:
* Signal forwards a set of public cipher keys from the server to client.
* The client uses a public key to encrypt a shared secret and forward the cipher-text to the server.
* The server decrypts the cipher-text, and both client and server use the secret to re-key a symmetric cipher,
* used to encrypt/decrypt text and files.
* This system is very 'top heavy'. 
* It requires the client and server to cache large asymmetric public/private keys,
* changes the key frequently (per message), and large transfers of asymmetric key chains.
* When a server connects to multiple clients, it must track which key-set belongs to which client,
* cache multiple keys while waiting for cipher-text response, scan cached keys for time-outs,
* and generate and send large sets of keys to clients.
* 
* To make this a more efficient model, asymmetric keys should only be cached for as long as they are needed;
* they are created, transmitted, deployed, and the memory released. 
* The symmetric cipher keys can still be replaced, either periodically or with every message, 
* and a periodic injection of entropy with an asymmetric exchange, that can be triggered by the application,
* ex. exceeding a bandwidth count, or per session or even per message, triggers exchange and injection.
* Previous keys can still be protected by running keccak permute on a persistant key state, and using that to
* re-key the symmetric ciphers (possibly with a salt sent over the encrypted channel).
* This will still require key tracking when dealing with server/client, but keys are removed as soon as they are used,
* in a variable collection (item|tag: find/add/remove).
* In a p2p configuration, clients can each sign their piece of the exchange, public key and cipher-text, 
* and no need to track keys as calls are receive-waiting and can be executed in one function.
*/

#if defined(DKTP_ASYMMETRIC_RATCHET)
bool dktp_send_asymmetric_ratchet_request(dktp_connection_state* cns)
{
	DKTP_ASSERT(cns != NULL);

	bool res;
	
	res = false;

	if (cns != NULL)
	{
		dktp_network_packet pkt = { 0 };
		uint8_t khash[DKTP_HASH_SIZE] = { 0U };
		uint8_t pmsg[DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE + DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE] = { 0U };
		uint8_t spct[DKTP_ASYMMETRIC_RATCHET_REQUEST_PACKET_SIZE] = { 0U };
		size_t mlen;
		size_t smlen;
		size_t slen;

#if defined(DKTP_ASYMMETRIC_RATCHET)
		qsc_async_mutex_lock(cns->txlock);
#endif
		cns->txseq += 1U;
		pkt.pmessage = spct + DKTP_HEADER_SIZE;
		pkt.flag = dktp_flag_asymmetric_ratchet_request;
		pkt.msglen = DKTP_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE;
		pkt.sequence = cns->txseq;
		dktp_packet_set_utc_time(&pkt);

		dktp_packet_header_serialize(&pkt, spct);
		mlen = DKTP_HEADER_SIZE;

		/* generate the asymmetric cipher keypair */
		dktp_cipher_generate_keypair(cns->enckey, cns->deckey, qsc_acp_generate);

		/* hash the public key */
		qsc_sha3_compute512(khash, cns->enckey, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);

		/* sign the hash */
		smlen = 0U;
		dktp_signature_sign(pmsg, &smlen, khash, sizeof(khash), cns->sigkey, qsc_acp_generate);
		mlen += smlen;

		/* copy the key to the message */
		qsc_memutils_copy(pmsg + smlen, cns->enckey, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
		mlen += DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE;

		/* encrypt the message */
		qsc_rcs_set_associated(&cns->txcpr, spct, DKTP_HEADER_SIZE);
		qsc_rcs_transform(&cns->txcpr, pkt.pmessage, pmsg, sizeof(pmsg));
		mlen += DKTP_MACTAG_SIZE;

#if defined(DKTP_ASYMMETRIC_RATCHET)
		qsc_async_mutex_unlock(cns->txlock);
#endif
		/* send the ratchet request */
		slen = qsc_socket_send(&cns->target, spct, mlen, qsc_socket_send_flag_none);

		if (slen == mlen)
		{
			res = true;
		}
	}

	return res;
}
#endif

dktp_errors dktp_client_connect_ipv4(dktp_local_peer_key* lpk, 
	dktp_remote_peer_key* rpk, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port,
	void (*send_func)(dktp_connection_state*), 
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t))
{
	DKTP_ASSERT(lpk != NULL);
	DKTP_ASSERT(rpk != NULL);
	DKTP_ASSERT(send_func != NULL);
	DKTP_ASSERT(send_func != NULL);
	DKTP_ASSERT(receive_callback != NULL);

	dktp_kex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_thread trcv;
	qsc_socket_exceptions serr;
	dktp_errors err;

	kcs = NULL;
	prcv = NULL;
	dktp_logger_initialize(NULL);

	if (lpk != NULL && rpk != NULL && address != NULL && send_func != NULL && receive_callback != NULL)
	{
		/* test the link between the local and remote peer keys */
		if (qsc_memutils_are_equal(lpk->peerid, rpk->keyid, DKTP_KEYID_SIZE) == true)
		{
			kcs = (dktp_kex_client_state*)qsc_memutils_malloc(sizeof(dktp_kex_client_state));

			if (kcs != NULL)
			{
				prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

				if (prcv != NULL)
				{
					qsc_memutils_clear(kcs, sizeof(dktp_kex_client_state));
					qsc_memutils_clear(prcv, sizeof(client_receiver_state));

					prcv->pcns = (dktp_connection_state*)qsc_memutils_malloc(sizeof(dktp_connection_state));

					if (prcv->pcns != NULL)
					{
						prcv->callback = receive_callback;
						qsc_socket_client_initialize(&prcv->pcns->target);

						serr = qsc_socket_client_connect_ipv4(&prcv->pcns->target, address, port);

						if (serr == qsc_socket_exception_success)
						{
							/* initialize the client */
							client_state_initialize(kcs, prcv->pcns, lpk, rpk);
							/* perform the simplex key exchange */
							err = dktp_kex_client_key_exchange(kcs, prcv->pcns);
							
							/* update the pre-shared secrets */
							qsc_memutils_copy(lpk->pss, kcs->pssl, DKTP_SECRET_SIZE);
							qsc_memutils_copy(rpk->pss, kcs->pssr, DKTP_SECRET_SIZE);

							/* clear the kex state */
							client_kex_reset(kcs);

							if (err == dktp_error_none)
							{
#if defined(DKTP_ASYMMETRIC_RATCHET)
								/* store the local signing key and the remote verify key for asymmetyric ratchet option */
								qsc_memutils_copy(prcv->pcns->sigkey, lpk->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
								qsc_memutils_copy(prcv->pcns->verkey, rpk->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
								/* load the pre-shared keys for ratchet seeds and updates */
								qsc_memutils_copy(prcv->pcns->pssl, lpk->pss, DKTP_SECRET_SIZE);
								qsc_memutils_copy(prcv->pcns->pssr, rpk->pss, DKTP_SECRET_SIZE);
#endif
								/* start the receive loop on a new thread */
								trcv = qsc_async_thread_create(&client_receive_loop, prcv);

								/* start the send loop on the main thread */
								send_func(prcv->pcns);

								/* terminate the receiver thread */
								(void)qsc_async_thread_terminate(trcv);

#if defined(DKTP_ASYMMETRIC_RATCHET)
								/* update the pre-shared secrets */
								qsc_memutils_copy(lpk->pss, prcv->pcns->pssl, DKTP_SECRET_SIZE);
								qsc_memutils_copy(rpk->pss, prcv->pcns->pssr, DKTP_SECRET_SIZE);
								qsc_memutils_secure_erase(prcv->pcns->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
								qsc_memutils_secure_erase(prcv->pcns->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif
							}
							else
							{
								dktp_log_write(dktp_messages_kex_fail, (const char*)prcv->pcns->target.address);
								err = dktp_error_exchange_failure;
							}

							/* disconnect the socket */
							client_connection_dispose(prcv);
						}
						else
						{
							dktp_log_write(dktp_messages_kex_fail, (const char*)prcv->pcns->target.address);
							err = dktp_error_connection_failure;
						}

						qsc_memutils_secure_erase(prcv->pcns, sizeof(dktp_connection_state));
						qsc_memutils_alloc_free(prcv->pcns);
						prcv->pcns = NULL;
					}
					else
					{
						dktp_log_message(dktp_messages_allocate_fail);
						err = dktp_error_memory_allocation;
					}

					qsc_memutils_secure_erase(prcv, sizeof(client_receiver_state));
					qsc_memutils_alloc_free(prcv);
					prcv = NULL;
				}
				else
				{
					dktp_log_message(dktp_messages_allocate_fail);
					err = dktp_error_memory_allocation;
				}

				qsc_memutils_alloc_free(kcs);
				kcs = NULL;
			}
			else
			{
				dktp_log_message(dktp_messages_allocate_fail);
				err = dktp_error_memory_allocation;
			}
		}
		else
		{
			dktp_log_message(dktp_messages_peer_key_mismatch);
			err = dktp_error_peer_key_mismatch;
		}
	}
	else
	{
		dktp_log_message(dktp_messages_invalid_request);
		err = dktp_error_invalid_input;
	}

	return err;
}

dktp_errors dktp_client_connect_ipv6(dktp_local_peer_key* lpk, 
	dktp_remote_peer_key* rpk,
	const qsc_ipinfo_ipv6_address* address, uint16_t port,
	void (*send_func)(dktp_connection_state*),
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t))
{
	DKTP_ASSERT(lpk != NULL);
	DKTP_ASSERT(rpk != NULL);
	DKTP_ASSERT(send_func != NULL);
	DKTP_ASSERT(send_func != NULL);
	DKTP_ASSERT(receive_callback != NULL);

	dktp_kex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_thread trcv;
	qsc_socket_exceptions serr;
	dktp_errors err;

	kcs = NULL;
	prcv = NULL;
	dktp_logger_initialize(NULL);

	if (lpk != NULL && rpk != NULL && address != NULL && send_func != NULL && receive_callback != NULL)
	{
		/* test the link between the local and remote peer keys */
		if (qsc_memutils_are_equal(lpk->peerid, rpk->keyid, DKTP_KEYID_SIZE) == true)
		{
			kcs = (dktp_kex_client_state*)qsc_memutils_malloc(sizeof(dktp_kex_client_state));

			if (kcs != NULL)
			{
				prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

				if (prcv != NULL)
				{
					qsc_memutils_clear(kcs, sizeof(dktp_kex_client_state));
					qsc_memutils_clear(prcv, sizeof(client_receiver_state));

					prcv->pcns = (dktp_connection_state*)qsc_memutils_malloc(sizeof(dktp_connection_state));

					if (prcv->pcns != NULL)
					{
						prcv->callback = receive_callback;
						qsc_socket_client_initialize(&prcv->pcns->target);

						serr = qsc_socket_client_connect_ipv6(&prcv->pcns->target, address, port);

						if (serr == qsc_socket_exception_success)
						{
							/* initialize the client */
							client_state_initialize(kcs, prcv->pcns, lpk, rpk);
							/* perform the simplex key exchange */
							err = dktp_kex_client_key_exchange(kcs, prcv->pcns);
							
							/* update the pre-shared secrets */
							qsc_memutils_copy(lpk->pss, kcs->pssl, DKTP_SECRET_SIZE);
							qsc_memutils_copy(rpk->pss, kcs->pssr, DKTP_SECRET_SIZE);

							/* clear the kex state */
							client_kex_reset(kcs);

							if (err == dktp_error_none)
							{
#if defined(DKTP_ASYMMETRIC_RATCHET)
								/* store the local signing key and the remote verify key for asymmetyric ratchet option */
								qsc_memutils_copy(prcv->pcns->sigkey, lpk->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
								qsc_memutils_copy(prcv->pcns->verkey, rpk->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
								/* load the pre-shared keys for ratchet seeds and updates */
								qsc_memutils_copy(prcv->pcns->pssl, lpk->pss, DKTP_SECRET_SIZE);
								qsc_memutils_copy(prcv->pcns->pssr, rpk->pss, DKTP_SECRET_SIZE);
#endif
								/* start the receive loop on a new thread */
								trcv = qsc_async_thread_create(&client_receive_loop, prcv);

								/* start the send loop on the main thread */
								send_func(prcv->pcns);

								/* terminate the receiver thread */
								(void)qsc_async_thread_terminate(trcv);

#if defined(DKTP_ASYMMETRIC_RATCHET)
								/* update the pre-shared secrets */
								qsc_memutils_copy(lpk->pss, prcv->pcns->pssl, DKTP_SECRET_SIZE);
								qsc_memutils_copy(rpk->pss, prcv->pcns->pssr, DKTP_SECRET_SIZE);
								qsc_memutils_secure_erase(prcv->pcns->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
								qsc_memutils_secure_erase(prcv->pcns->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif

								/* disconnect the socket */
								client_connection_dispose(prcv);
							}
							else
							{
								dktp_log_write(dktp_messages_kex_fail, (const char*)prcv->pcns->target.address);
								err = dktp_error_exchange_failure;
							}
						}
						else
						{
							dktp_log_write(dktp_messages_kex_fail, (const char*)prcv->pcns->target.address);
							err = dktp_error_connection_failure;
						}

						qsc_memutils_secure_erase(prcv->pcns, sizeof(dktp_connection_state));
						qsc_memutils_alloc_free(prcv->pcns);
						prcv->pcns = NULL;
					}
					else
					{
						dktp_log_message(dktp_messages_allocate_fail);
						err = dktp_error_memory_allocation;
					}

					qsc_memutils_secure_erase(prcv, sizeof(client_receiver_state));
					qsc_memutils_alloc_free(prcv);
					prcv = NULL;
				}
				else
				{
					dktp_log_message(dktp_messages_allocate_fail);
					err = dktp_error_memory_allocation;
				}

				qsc_memutils_alloc_free(kcs);
				kcs = NULL;
			}
			else
			{
				dktp_log_message(dktp_messages_allocate_fail);
				err = dktp_error_memory_allocation;
			}
		}
		else
		{
			dktp_log_message(dktp_messages_peer_key_mismatch);
			err = dktp_error_peer_key_mismatch;
		}
	}
	else
	{
		dktp_log_message(dktp_messages_invalid_request);
		err = dktp_error_invalid_input;
	}

	return err;
}

dktp_errors dktp_client_listen_ipv4(dktp_local_peer_key* lpk, 
	dktp_remote_peer_key* rpk, 
	void (*send_func)(dktp_connection_state*), 
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t))
{
	DKTP_ASSERT(lpk != NULL);
	DKTP_ASSERT(rpk != NULL);
	DKTP_ASSERT(send_func != NULL);
	DKTP_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	dktp_errors err;

	dktp_logger_initialize(NULL);
	prcv = NULL;

	if (lpk != NULL && rpk != NULL && send_func != NULL && receive_callback != NULL)
	{
		/* test the link between the local and remote peer keys */
		if (qsc_memutils_are_equal(lpk->peerid, rpk->keyid, DKTP_KEYID_SIZE) == true)
		{
			prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state));

			if (prcv != NULL)
			{
				prcv->pcns = (dktp_connection_state*)qsc_memutils_malloc(sizeof(dktp_connection_state));

				if (prcv->pcns != NULL)
				{
					qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(dktp_connection_state));
					prcv->callback = receive_callback;

					addt = qsc_ipinfo_ipv4_address_any();
					qsc_socket_server_initialize(&prcv->pcns->target);
					qsc_socket_server_initialize(&srvs);

					serr = qsc_socket_server_listen_ipv4(&srvs, &prcv->pcns->target, &addt, DKTP_CLIENT_PORT);

					if (serr == qsc_socket_exception_success)
					{
						err = listener_start(lpk, rpk, prcv, send_func);
					}
					else
					{
						dktp_log_message(dktp_messages_connection_fail);
						err = dktp_error_connection_failure;
					}

					qsc_memutils_secure_erase(prcv->pcns, sizeof(dktp_connection_state));
					qsc_memutils_alloc_free(prcv->pcns);
					prcv->pcns = NULL;
				}
				else
				{
					dktp_log_message(dktp_messages_allocate_fail);
					err = dktp_error_memory_allocation;
				}

				qsc_memutils_secure_erase(prcv, sizeof(listener_receiver_state));
				qsc_memutils_alloc_free(prcv);
				prcv = NULL;
			}
			else
			{
				dktp_log_message(dktp_messages_allocate_fail);
				err = dktp_error_memory_allocation;
			}
		}
		else
		{
			dktp_log_message(dktp_messages_peer_key_mismatch);
			err = dktp_error_peer_key_mismatch;
		}
	}
	else
	{
		dktp_log_message(dktp_messages_invalid_request);
		err = dktp_error_invalid_input;
	}

	return err;
}

dktp_errors dktp_client_listen_ipv6(dktp_local_peer_key* lpk,
	dktp_remote_peer_key* rpk, 
	void (*send_func)(dktp_connection_state*),
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t))
{
	DKTP_ASSERT(lpk != NULL);
	DKTP_ASSERT(rpk != NULL);
	DKTP_ASSERT(send_func != NULL);
	DKTP_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	dktp_errors err;

	dktp_logger_initialize(NULL);
	prcv = NULL;

	if (lpk != NULL && rpk != NULL && send_func != NULL && receive_callback != NULL)
	{
		/* test the link between the local and remote peer keys */
		if (qsc_memutils_are_equal(lpk->peerid, rpk->keyid, DKTP_KEYID_SIZE) == true)
		{
			prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state));

			if (prcv != NULL)
			{
				prcv->pcns = (dktp_connection_state*)qsc_memutils_malloc(sizeof(dktp_connection_state));

				if (prcv->pcns != NULL)
				{
					qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(dktp_connection_state));
					prcv->callback = receive_callback;

					addt = qsc_ipinfo_ipv6_address_any();
					qsc_socket_server_initialize(&prcv->pcns->target);
					qsc_socket_server_initialize(&srvs);

					serr = qsc_socket_server_listen_ipv6(&srvs, &prcv->pcns->target, &addt, DKTP_CLIENT_PORT);

					if (serr == qsc_socket_exception_success)
					{
						err = listener_start(lpk, rpk, prcv, send_func);
					}
					else
					{
						dktp_log_message(dktp_messages_connection_fail);
						err = dktp_error_connection_failure;
					}

					qsc_memutils_secure_erase(prcv->pcns, sizeof(dktp_connection_state));
					qsc_memutils_alloc_free(prcv->pcns);
					prcv->pcns = NULL;
				}
				else
				{
					dktp_log_message(dktp_messages_allocate_fail);
					err = dktp_error_memory_allocation;
				}

				qsc_memutils_secure_erase(prcv, sizeof(listener_receiver_state));
				qsc_memutils_alloc_free(prcv);
				prcv = NULL;
			}
			else
			{
				dktp_log_message(dktp_messages_allocate_fail);
				err = dktp_error_memory_allocation;
			}
		}
		else
		{
			dktp_log_message(dktp_messages_peer_key_mismatch);
			err = dktp_error_peer_key_mismatch;
		}
	}
	else
	{
		dktp_log_message(dktp_messages_invalid_request);
		err = dktp_error_invalid_input;
	}

	return err;
}
