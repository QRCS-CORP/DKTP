#include "server.h"
#include "connections.h"
#include "kex.h"
#include "logger.h"
#include "acp.h"
#include "async.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"

/** \cond */
typedef struct server_receiver_state
{
	dktp_connection_state* pcns;
	const dktp_local_peer_key* pprik;
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t);
	void (*disconnect_callback)(dktp_connection_state*);
} server_receiver_state;
/** \endcond */

/** \cond */
static bool m_server_pause;
static bool m_server_run;

static void server_state_initialize(dktp_kex_server_state* kss, const server_receiver_state* prcv)
{
	qsc_memutils_copy(kss->keyid, prcv->pprik->keyid, DKTP_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, prcv->pprik->sigkey, DKTP_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kss->verkey, prcv->pprik->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
	kss->expiration = prcv->pprik->expiration;
}

static void server_poll_sockets(void)
{
	size_t clen;
	qsc_mutex mtx;

	clen = dktp_connections_size();

	for (size_t i = 0U; i < clen; ++i)
	{
		const dktp_connection_state* cns = dktp_connections_index(i);

		if (cns != NULL && dktp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == false)
			{
				dktp_connections_reset(cns->cid);
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

static void server_receive_loop(void* prcv)
{
	DKTP_ASSERT(prcv != NULL);

	dktp_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	dktp_kex_server_state* pkss;
	server_receiver_state* pprcv;
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	dktp_errors qerr;

	pprcv = (server_receiver_state*)prcv;
	qsc_memutils_copy(cadd, (const char*)pprcv->pcns->target.address, sizeof(cadd));
	pkss = (dktp_kex_server_state*)qsc_memutils_malloc(sizeof(dktp_kex_server_state));

	if (pkss != NULL)
	{
		server_state_initialize(pkss, pprcv);
		qerr = dktp_kex_server_key_exchange(pkss, pprcv->pcns);
		qsc_memutils_alloc_free(pkss);
		pkss = NULL;

		if (qerr == dktp_error_none)
		{
			rbuf = (uint8_t*)qsc_memutils_malloc(DKTP_HEADER_SIZE);

			if (rbuf != NULL)
			{
				while (pprcv->pcns->target.connection_status == qsc_socket_state_connected)
				{
					mlen = 0U;
					slen = 0U;

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
							}
						}

						if (rbuf != NULL)
						{
							qsc_memutils_clear(rbuf, plen);
							mlen = qsc_socket_receive(&pprcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);
							
							if (mlen != 0U)
							{
								pkt.pmessage = rbuf + DKTP_HEADER_SIZE;

								if (pkt.flag == dktp_flag_encrypted_message)
								{
									uint8_t* mstr;

									slen = pkt.msglen + DKTP_MACTAG_SIZE;
									mstr = (uint8_t*)qsc_memutils_malloc(slen);

									if (mstr != NULL)
									{
										qsc_memutils_clear(mstr, slen);

										qerr = dktp_packet_decrypt(pprcv->pcns, mstr, &mlen, &pkt);

										if (qerr == dktp_error_none)
										{
											pprcv->receive_callback(pprcv->pcns, mstr, mlen);
										}
										else
										{
											/* close the connection on authentication failure */
											dktp_log_write(dktp_messages_decryption_fail, cadd);
											break;
										}

										qsc_memutils_clear(mstr, slen);
										qsc_memutils_alloc_free(mstr);
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
								else
								{
									/* unknown message type, we fail out of caution but could ignore */
									dktp_log_write(dktp_messages_receive_fail, cadd);
									break;
								}
							}
							else
							{
								qsc_socket_exceptions err = qsc_socket_get_last_error();

								if (err != qsc_socket_exception_success)
								{
									dktp_log_error(dktp_messages_receive_fail, err, cadd);

									/* fatal socket errors */
									if (err == qsc_socket_exception_circuit_reset ||
										err == qsc_socket_exception_circuit_terminated ||
										err == qsc_socket_exception_circuit_timeout ||
										err == qsc_socket_exception_dropped_connection ||
										err == qsc_socket_exception_network_failure ||
										err == qsc_socket_exception_shut_down)
									{
										dktp_log_write(dktp_messages_connection_fail, cadd);
										break;
									}
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
				}

				qsc_memutils_alloc_free(rbuf);
			}
			else
			{
				/* close the connection on memory allocation failure */
				dktp_log_write(dktp_messages_allocate_fail, cadd);
			}

			if (pprcv->disconnect_callback != NULL)
			{
				pprcv->disconnect_callback(pprcv->pcns);
			}
		}
		else
		{
			dktp_log_message(dktp_messages_kex_fail);
		}

		if (pprcv != NULL)
		{
			dktp_connections_reset(pprcv->pcns->cid);
			qsc_memutils_alloc_free(pprcv);
			pprcv = NULL;
		}
	}
	else
	{
		dktp_log_message(dktp_messages_allocate_fail);
	}
}

static dktp_errors server_start(const dktp_local_peer_key* lpk, 
	const qsc_socket* source, 
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(dktp_connection_state*))
{
	DKTP_ASSERT(lpk != NULL);
	DKTP_ASSERT(source != NULL);
	DKTP_ASSERT(receive_callback != NULL);

	qsc_socket_exceptions res;
	dktp_errors qerr;

	qerr = dktp_error_none;
	m_server_pause = false;
	m_server_run = true;
	dktp_logger_initialize(NULL);
	dktp_connections_initialize(DKTP_CONNECTIONS_INIT, DKTP_CONNECTIONS_MAX);

	do
	{
		dktp_connection_state* cns = dktp_connections_next();

		if (cns != NULL)
		{
			res = qsc_socket_accept(source, &cns->target);

			if (res == qsc_socket_exception_success)
			{
				server_receiver_state* prcv = (server_receiver_state*)qsc_memutils_malloc(sizeof(server_receiver_state));

				if (prcv != NULL)
				{
					cns->target.connection_status = qsc_socket_state_connected;
					prcv->pcns = cns;
					prcv->pprik = lpk;
					prcv->disconnect_callback = disconnect_callback;
					prcv->receive_callback = receive_callback;

					dktp_log_write(dktp_messages_connect_success, (const char*)cns->target.address);
					/* start the receive loop on a new thread */
					qsc_async_thread_create(&server_receive_loop, prcv);
					server_poll_sockets();
				}
				else
				{
					dktp_connections_reset(cns->cid);
					qerr = dktp_error_memory_allocation;
					dktp_log_message(dktp_messages_sockalloc_fail);
				}
			}
			else
			{
				dktp_connections_reset(cns->cid);
				qerr = dktp_error_accept_fail;
				dktp_log_message(dktp_messages_accept_fail);
			}
		}
		else
		{
			qerr = dktp_error_hosts_exceeded;
			dktp_log_message(dktp_messages_queue_empty);
		}

		while (m_server_pause == true)
		{
			qsc_async_thread_sleep(DKTP_SERVER_PAUSE_INTERVAL);
		}
	} 
	while (m_server_run == true);

	return qerr;
}
/** \endcond */

/* Public Functions */

void dktp_server_broadcast(const uint8_t* message, size_t msglen)
{
	size_t clen;
	size_t mlen;
	qsc_mutex mtx;
	dktp_network_packet pkt = { 0 };
	uint8_t msgstr[DKTP_CONNECTION_MTU] = { 0U };

	clen = dktp_connections_size();

	for (size_t i = 0U; i < clen; ++i)
	{
		dktp_connection_state* cns = dktp_connections_index(i);

		if (cns != NULL && dktp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == true)
			{
				dktp_packet_encrypt(cns, &pkt, message, msglen);
				mlen = dktp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

void dktp_server_pause(void)
{
	m_server_pause = true;
}

void dktp_server_quit(void)
{
	size_t clen;
	qsc_mutex mtx;

	clen = dktp_connections_size();

	for (size_t i = 0U; i < clen; ++i)
	{
		dktp_connection_state* cns = dktp_connections_index(i);

		if (cns != NULL && dktp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == true)
			{
				qsc_socket_close_socket(&cns->target);
			}

			dktp_connections_reset(cns->cid);

			qsc_async_mutex_unlock_ex(mtx);
		}
	}

	dktp_connections_dispose();
	m_server_run = false;
}

void dktp_server_resume(void)
{
	m_server_pause = false;
}

dktp_errors dktp_server_start_ipv4(qsc_socket* source, 
	const dktp_local_peer_key* lpk,
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(dktp_connection_state*))
{
	DKTP_ASSERT(lpk != NULL);
	DKTP_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions res;
	dktp_errors qerr;

	addt = qsc_ipinfo_ipv4_address_any();
	qsc_socket_server_initialize(source);
	res = qsc_socket_create(source, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

	if (res == qsc_socket_exception_success)
	{
		res = qsc_socket_bind_ipv4(source, &addt, DKTP_SERVER_PORT);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

			if (res == qsc_socket_exception_success)
			{
				qerr = server_start(lpk, source, receive_callback, disconnect_callback);
			}
			else
			{
				qerr = dktp_error_listener_fail;
				dktp_log_message(dktp_messages_listener_fail);
			}
		}
		else
		{
			qerr = dktp_error_connection_failure;
			dktp_log_message(dktp_messages_bind_fail);
		}
	}
	else
	{
		qerr = dktp_error_connection_failure;
		dktp_log_message(dktp_messages_create_fail);
	}

	return qerr;
}

dktp_errors dktp_server_start_ipv6(qsc_socket* source,
	const dktp_local_peer_key* lpk,
	void (*receive_callback)(dktp_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(dktp_connection_state*))
{
	DKTP_ASSERT(lpk != NULL);
	DKTP_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions res;
	dktp_errors qerr;

	addt = qsc_ipinfo_ipv6_address_any();
	qsc_socket_server_initialize(source);
	res = qsc_socket_create(source, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

	if (res == qsc_socket_exception_success)
	{
		res = qsc_socket_bind_ipv6(source, &addt, DKTP_SERVER_PORT);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

			if (res == qsc_socket_exception_success)
			{
				qerr = server_start(lpk, source, receive_callback, disconnect_callback);
			}
			else
			{
				qerr = dktp_error_listener_fail;
				dktp_log_message(dktp_messages_listener_fail);
			}
		}
		else
		{
			qerr = dktp_error_connection_failure;
			dktp_log_message(dktp_messages_bind_fail);
		}
	}
	else
	{
		qerr = dktp_error_connection_failure;
		dktp_log_message(dktp_messages_create_fail);
	}

	return qerr;
}
