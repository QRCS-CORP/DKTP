#include "kex.h"
#include "acp.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "rcs.h"
#include "sha3.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timestamp.h"

#define DKTP_KEX_SEQTIME_SIZE 16U

#define KEX_SIMPLEX_CONNECT_REQUEST_MESSAGE_SIZE (DKTP_KEYID_SIZE + DKTP_CONFIG_SIZE)
#define KEX_SIMPLEX_CONNECT_REQUEST_PACKET_SIZE (DKTP_HEADER_SIZE + KEX_SIMPLEX_CONNECT_REQUEST_MESSAGE_SIZE)
#define KEX_SIMPLEX_CONNECT_RESPONSE_MESSAGE_SIZE (DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + DKTP_HASH_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_SIMPLEX_CONNECT_RESPONSE_PACKET_SIZE (DKTP_HEADER_SIZE + KEX_SIMPLEX_CONNECT_RESPONSE_MESSAGE_SIZE)

#define KEX_SIMPLEX_EXCHANGE_REQUEST_MESSAGE_SIZE (DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE)
#define KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE (DKTP_HEADER_SIZE + KEX_SIMPLEX_EXCHANGE_REQUEST_MESSAGE_SIZE)
#define KEX_SIMPLEX_EXCHANGE_RESPONSE_MESSAGE_SIZE (0)
#define KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE (DKTP_HEADER_SIZE + KEX_SIMPLEX_EXCHANGE_RESPONSE_MESSAGE_SIZE)

#define KEX_CONNECT_REQUEST_MESSAGE_SIZE (DKTP_KEYID_SIZE + DKTP_CONFIG_SIZE + DKTP_HASH_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_CONNECT_REQUEST_PACKET_SIZE (DKTP_HEADER_SIZE + KEX_CONNECT_REQUEST_MESSAGE_SIZE)
#define KEX_CONNECT_RESPONSE_MESSAGE_SIZE (DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + DKTP_HASH_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_CONNECT_RESPONSE_PACKET_SIZE (DKTP_HEADER_SIZE + KEX_CONNECT_RESPONSE_MESSAGE_SIZE)

#define KEX_EXCHANGE_REQUEST_MESSAGE_SIZE (DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + DKTP_HASH_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_EXCHANGE_REQUEST_PACKET_SIZE (DKTP_HEADER_SIZE + KEX_EXCHANGE_REQUEST_MESSAGE_SIZE)
#define KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE (DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_HASH_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_EXCHANGE_RESPONSE_PACKET_SIZE (DKTP_HEADER_SIZE + KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE)

#define KEX_ESTABLISH_REQUEST_MESSAGE_SIZE (DKTP_HASH_SIZE + DKTP_MACTAG_SIZE)
#define KEX_ESTABLISH_REQUEST_PACKET_SIZE (DKTP_HEADER_SIZE + KEX_ESTABLISH_REQUEST_MESSAGE_SIZE)
#define KEX_ESTABLISH_RESPONSE_MESSAGE_SIZE (DKTP_HASH_SIZE + DKTP_MACTAG_SIZE)
#define KEX_ESTABLISH_RESPONSE_PACKET_SIZE (DKTP_HEADER_SIZE + KEX_ESTABLISH_RESPONSE_MESSAGE_SIZE)

static void kex_send_network_error(const qsc_socket* sock, dktp_errors error)
{
	DKTP_ASSERT(sock != NULL);

	if (qsc_socket_is_connected(sock) == true)
	{
		dktp_network_packet resp = { 0 };
		uint8_t spct[DKTP_HEADER_SIZE + DKTP_ERROR_MESSAGE_SIZE] = { 0U };

		resp.pmessage = spct + DKTP_HEADER_SIZE;
		dktp_packet_error_message(&resp, error);
		dktp_packet_header_serialize(&resp, spct);
		qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);
	}
}

static void kex_extract_seqtime(uint8_t* output, const dktp_network_packet* packet)
{
	qsc_intutils_le64to8(output, packet->sequence);
	qsc_intutils_le64to8(output + DKTP_SEQUENCE_SIZE, packet->utctime);
}

/*
Legend:
← ↔ →		-Assignment and direction symbols
=, !=, ?=	-Equality operators; assign, not equals, evaluate
C			-The client host, initiates the exchange
S			-The server host, listens for a connection
-Edk		-The asymmetric decapsulation function and secret key
Eek			-The asymmetric encapsulation function and key
Ek, -Ek		-The symmetric encryption and decryption functions and key
G(λ, r)		-The asymmetric cipher key generation with parameter set and random source
H			-The hash function (SHA3)
KDF			-The key expansion function (SHAKE)
Ssk			-Sign data with the secret signature key
Vvk			-Verify a signature using the signature verification key
cfg			-The protocol configuration string
cprrx		-A receive channels symmetric cipher instance
cprtx		-A transmit channels symmetric cipher instance
cpt			-The symmetric ciphers cipher-text
cpta		-The asymmetric ciphers cipher-text
kid			-The peering keys unique identity array
dk, ek		-Asymmetric cipher decapsulation and encapsulation keys
pssl, pssr	-The local and remote pre-shared symmetric keys
secl, secr	-The shared secret derived from asymmetric encapsulation and decapsulation
shpk		-The signed hash of the asymmetric cipher encapsulation-key
sk, vk		-The asymmetric signature signing and verification keys
sph			-The serialized packet header.
st			-The serialized packet sequence number and timestamp.
tckl, tckr	-The tunnel channel keys for the transmit/receive symmetric cipher instances
*/

/*
Connect Request:
The client stores a hash of the configuration string, and both of the public asymmetric signature verification-keys,
which is used as a session cookie during the exchange.
sch = H(cfg || pvka || pvkb)
The client hashes the key identity string, the configuration string, and the serialized packet header, and signs the hash.
sm = Ssk(H(kid || cfg || sph))
The client sends the kid, the config, and the signed hash to the server.
C{ kid || cfg || sm }->S
*/
static dktp_errors kex_client_connect_request(dktp_kex_client_state* kcs, dktp_connection_state* cns, dktp_network_packet* packetout)
{
	DKTP_ASSERT(kcs != NULL);
	DKTP_ASSERT(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	dktp_errors qerr;
	uint64_t tm;

	if (kcs != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_datetime_utc();
		
		if (tm <= kcs->expiration)
		{
			uint8_t phash[DKTP_HASH_SIZE] = { 0U };
			uint8_t shdr[DKTP_HEADER_SIZE] = { 0U };
			size_t mlen;

			/* copy the key-id and configuration string to the message */
			qsc_memutils_copy(packetout->pmessage, kcs->keyid, DKTP_KEYID_SIZE);
			qsc_memutils_copy(((uint8_t*)packetout->pmessage + DKTP_KEYID_SIZE), DKTP_CONFIG_STRING, DKTP_CONFIG_SIZE);
			/* assemble the connection-request packet */
			dktp_header_create(packetout, dktp_flag_connect_request, cns->txseq, KEX_CONNECT_REQUEST_MESSAGE_SIZE);

			/* serialize header, then hash/sign the header and message */
			dktp_packet_header_serialize(packetout, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, DKTP_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetout->pmessage, DKTP_KEYID_SIZE + DKTP_CONFIG_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

			/* sign the hash and add it to the message */
			mlen = 0U;
			dktp_signature_sign(packetout->pmessage + DKTP_KEYID_SIZE + DKTP_CONFIG_SIZE, &mlen, phash, DKTP_HASH_SIZE, kcs->sigkey, qsc_acp_generate);

			/* store a hash of the configuration string, and the public signature keys: pkh = H(cfg || pvka || pvkb) */
			qsc_memutils_clear(kcs->schash, DKTP_HASH_SIZE);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, (const uint8_t*)DKTP_CONFIG_STRING, DKTP_CONFIG_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->keyid, DKTP_KEYID_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->rverkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kcs->schash);

			cns->exflag = dktp_flag_connect_request;
			qerr = dktp_error_none;
		}
		else
		{
			cns->exflag = dktp_flag_none;
			qerr = dktp_error_key_expired;
		}
	}
	else
	{
		cns->exflag = dktp_flag_none;
		qerr = dktp_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Request:
The client verifies the flag, sequence number, valid-time timestamp, and message size of the connect response packet.
The client verifies the signature of the hash, then generates its own hash of the encapsulation key and serialized packet header, 
and compares it with the one contained in the message. 
If the hash matches, the client uses the encapsulation key to encapsulate a shared secret. 
If the hash does not match, the key exchange is aborted.
cond = Vvk(H(ek || sh)) = (true ?= ek : 0)
cpta = Eek(secl)
The client stores the shared secret (secl), which along with a second shared secret and the session cookie, 
which will be used to generate the session keys.
The client generates an asymmetric encryption key-pair, stores the decapsulation key, 
hashes the encapsulation key, ciphertext, and serialized packet header, 
and then signs the hash using its asymmetric signature key.
ek, dk = G(r)
hkc = H(ek || cpta || sh)
shkc = Ssk(hkc)
The client sends a response message containing the signed hash of its encapsulation-key and 
cipher-text and serialized header, and a copy of the cipher-text and encapsulation key.
C{ cpta || ek || shkc }-> S
*/
static dktp_errors kex_client_exchange_request(dktp_kex_client_state* kcs, dktp_connection_state* cns, const dktp_network_packet* packetin, dktp_network_packet* packetout)
{
	DKTP_ASSERT(kcs != NULL);
	DKTP_ASSERT(packetin != NULL);
	DKTP_ASSERT(packetout != NULL);

	uint8_t hm[DKTP_HASH_SIZE] = { 0U };
	size_t mlen;
	size_t slen;
	dktp_errors qerr;

	if (kcs != NULL && packetin != NULL && packetout != NULL)
	{
		slen = 0U;
		mlen = DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE;

		/* verify the asymmetric signature */
		if (dktp_signature_verify(hm, &slen, packetin->pmessage, mlen, kcs->rverkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t hmc[DKTP_HASH_SIZE] = { 0U };
			uint8_t shdr[DKTP_HEADER_SIZE] = { 0U };
			const uint8_t* pubk = packetin->pmessage + mlen;

			/* hash the public encapsulation key and header */
			dktp_packet_header_serialize(packetin, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, DKTP_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, pubk, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, hmc);

			/* verify the public key hash */
			if (qsc_intutils_verify(hmc, hm, DKTP_HASH_SIZE) == 0)
			{
				/* generate, and encapsulate the secret */

				/* store the cipher-text in the message */
				dktp_cipher_encapsulate(kcs->secl, packetout->pmessage, pubk, qsc_acp_generate);

				/* generate the asymmetric encryption key-pair */
				dktp_cipher_generate_keypair(kcs->enckey, kcs->deckey, qsc_acp_generate);

				/* copy the public key to the message */
				qsc_memutils_copy(packetout->pmessage + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE, kcs->enckey, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
					
				/* assemble the exchange-request packet */
				dktp_header_create(packetout, dktp_flag_exchange_request, cns->txseq, KEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

				/* hash the public encapsulation key and packet header */
				dktp_packet_header_serialize(packetout, shdr);
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, DKTP_HEADER_SIZE);
				/* hash the public encapsulation key and cipher-text */
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetout->pmessage, DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, hm);

				/* sign the hash and add it to the message */
				mlen = 0;
				dktp_signature_sign(packetout->pmessage + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE, &mlen, hm, DKTP_HASH_SIZE, kcs->sigkey, qsc_acp_generate);

				qerr = dktp_error_none;
				cns->exflag = dktp_flag_exchange_request;
			}
			else
			{
				cns->exflag = dktp_flag_none;
				qerr = dktp_error_verify_failure;
			}
		}
		else
		{
			cns->exflag = dktp_flag_none;
			qerr = dktp_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = dktp_flag_none;
		qerr = dktp_error_invalid_input;
	}

	return qerr;
}

/*
The client verifies the flag, sequence number, valid-time timestamp, and message size of the exchange response packet.
The client verifies the signature of the hash, then generates its own hash of the cipher-text and packet header, 
and compares it with the one contained in the message. 
If the hash matches, the client decapsulates the shared secret (secb). If the hash comparison fails,
the key exchange is aborted.
cond = Vvk(H(cptb)) = (true ?= cptb : 0)
secb = -Edk(cptb)
The client combines the asymmetric shared secrets with the pre-shared secrets to create the transmit and receive session keys, 
and nonces, independently keying each channel of the communications stream.
kl, nl = KDF(secl, pssr)
kr, nr = KDF(secr, pssl)
The receive and transmit channel ciphers are initialized.
cprrx(kr, nr)
cprtx(kl, nl)
The client encrypts the session cookie and the timestamp/sequence with the tx cipher, adding the serialized packet header 
to the additional data of the cipher MAC.
scht = H(sch || ts)
cm = Ek(scht, sh)
In the event of an error, the client sends an error message to the server, 
aborting the exchange and terminating the connection on both hosts.
C{ cm }-> S
*/
static dktp_errors kex_client_establish_request(dktp_kex_client_state* kcs, dktp_connection_state* cns, const dktp_network_packet* packetin, dktp_network_packet* packetout)
{
	DKTP_ASSERT(kcs != NULL);
	DKTP_ASSERT(packetin != NULL);
	DKTP_ASSERT(packetout != NULL);

	dktp_errors qerr;
	uint8_t hm[DKTP_HASH_SIZE] = { 0U };
	size_t mlen;
	size_t slen;

	if (kcs != NULL && packetin != NULL && packetout != NULL)
	{
		slen = 0U;
		mlen = DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE;

		/* verify the asymmetric signature */
		if (dktp_signature_verify(hm, &slen, packetin->pmessage + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE, mlen, kcs->rverkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t hmc[DKTP_HASH_SIZE] = { 0U };
			uint8_t secr[DKTP_SECRET_SIZE] = { 0U };
			uint8_t shdr[DKTP_HEADER_SIZE] = { 0U };

			/* hash the public encapsulation key and header */
			dktp_packet_header_serialize(packetin, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, DKTP_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetin->pmessage, DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, hmc);

			/* verify the cipher-text hash */
			if (qsc_intutils_verify(hmc, hm, DKTP_HASH_SIZE) == 0)
			{
				if (dktp_cipher_decapsulate(secr, packetin->pmessage, kcs->deckey) == true)
				{
					uint8_t prnd[(QSC_KECCAK_512_RATE * 2U)] = { 0U };		
					uint8_t sch[DKTP_HASH_SIZE] = { 0 };
					uint8_t st[DKTP_KEX_SEQTIME_SIZE] = { 0 };

					/* initialize cSHAKE tckr = H(secl, pssr) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, kcs->secl, DKTP_SECRET_SIZE, NULL, 0, kcs->pssr, DKTP_SECRET_SIZE);
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 2);

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qsc_rcs_keyparams kp = { 0 };
					kp.key = prnd;
					kp.keylen = DKTP_SYMMETRIC_KEY_SIZE;
					kp.nonce = prnd + DKTP_SYMMETRIC_KEY_SIZE;
					kp.info = NULL;
					kp.infolen = 0U;
					qsc_rcs_initialize(&cns->txcpr, &kp, true);

					/* pssl = H(pssl, tckl) */
					qsc_cshake512_compute(kcs->pssl, DKTP_SECRET_SIZE, kcs->pssl, DKTP_SECRET_SIZE, NULL, 0, prnd, DKTP_SECRET_SIZE);

					/* initialize cSHAKE tckl = H(secr, pssl) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, secr, DKTP_SECRET_SIZE, NULL, 0, kcs->pssl, DKTP_SECRET_SIZE);
					qsc_memutils_clear(secr, sizeof(secr));
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 2);

					/* initialize the symmetric cipher, and raise client channel-1 rx */
					kp.key = prnd;
					kp.keylen = DKTP_SYMMETRIC_KEY_SIZE;
					kp.nonce = prnd + DKTP_SYMMETRIC_KEY_SIZE;
					kp.info = NULL;
					kp.infolen = 0U;
					qsc_rcs_initialize(&cns->rxcpr, &kp, false);
					qsc_memutils_clear((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));

					/* pssr = H(pssr, tckr) */
					qsc_cshake512_compute(kcs->pssr, DKTP_SECRET_SIZE, kcs->pssr, DKTP_SECRET_SIZE, NULL, 0, prnd, DKTP_SECRET_SIZE);
					qsc_memutils_clear(prnd, sizeof(prnd));

					/* assemble the establish-request packet */
					dktp_header_create(packetout, dktp_flag_establish_request, cns->txseq, KEX_ESTABLISH_REQUEST_MESSAGE_SIZE);

					/* protocol change: encrypt and add schash to establish request */
					dktp_packet_header_serialize(packetout, shdr);
					qsc_rcs_set_associated(&cns->txcpr, shdr, DKTP_HEADER_SIZE);

					kex_extract_seqtime(st, packetout);
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, st, sizeof(st));
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, (uint8_t*)DKTP_DOMAIN_IDENTITY_STRING, DKTP_DOMAIN_IDENTITY_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->schash, DKTP_HASH_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, sch);

					qsc_rcs_transform(&cns->txcpr, packetout->pmessage, sch, DKTP_HASH_SIZE);

					qerr = dktp_error_none;
					cns->exflag = dktp_flag_establish_request;
				}
				else
				{
					cns->exflag = dktp_flag_none;
					qerr = dktp_error_decapsulation_failure;
				}
			}
			else
			{
				cns->exflag = dktp_flag_none;
				qerr = dktp_error_verify_failure;
			}
		}
		else
		{
			cns->exflag = dktp_flag_none;
			qerr = dktp_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = dktp_flag_none;
		qerr = dktp_error_invalid_input;
	}

	return qerr;
}

/*
Establish Verify:
The client verifies the packet flag, sequence number, valid-time timestamp, and message size of the establish response packet.
The client uses the rx cipher instance, adding the serialized establish response packet header to the AD and decrypting the ciphertext.
The session cookie is hashed along with the timestamp/sequence, and the hash is compared to the decrypted message for equivalence.
If the hashes matches, both sides have confirmed that the encrypted tunnel has been established.
Otherwise the tunnel is in an error state indicated by the message, 
and the tunnel is torn down on both sides. 
The client sets the operational state to session established, and is now ready to process data.
*/
static dktp_errors kex_client_establish_verify(dktp_kex_client_state* kcs, dktp_connection_state* cns, const dktp_network_packet* packetin)
{
	DKTP_ASSERT(kcs != NULL);
	DKTP_ASSERT(packetin != NULL);

	dktp_errors qerr;

	if (kcs != NULL && packetin != NULL)
	{
		uint8_t hm[DKTP_HASH_SIZE];
		uint8_t shdr[DKTP_HEADER_SIZE] = { 0U };

		/* decrypt and verify the server schash */
		dktp_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, DKTP_HEADER_SIZE);

		if (qsc_rcs_transform(&cns->rxcpr, hm, packetin->pmessage, DKTP_HASH_SIZE) == true)
		{
			/* sch = H(schash || st) */
			qsc_keccak_state kstate = { 0 };
			uint8_t sch[DKTP_HASH_SIZE] = { 0 };
			uint8_t st[DKTP_KEX_SEQTIME_SIZE] = { 0 };

			/* sch = H(schash || st) */
			kex_extract_seqtime(st, packetin);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, st, sizeof(st));
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, (uint8_t*)DKTP_DOMAIN_IDENTITY_STRING, DKTP_DOMAIN_IDENTITY_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->schash, DKTP_HASH_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, sch);

			/* verify the server schash */
			if (qsc_intutils_verify(hm, sch, DKTP_HASH_SIZE) == 0)
			{
				cns->exflag = dktp_flag_session_established;
				qerr = dktp_error_none;
			}
			else
			{
				qerr = dktp_error_verify_failure;
			}
		}
		else
		{
			qerr = dktp_error_decryption_failure;
		}
	}
	else
	{
		qerr = dktp_error_invalid_input;
	}

	return qerr;
}

/*
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the connect request packet.
The server responds with either an error message, or a connect response packet.
Any error during the key exchange will generate an error-packet sent to the remote host, 
which will trigger a tear down of the exchange, and the network connection on both sides.
The server first checks the packet header including the valid-time timestamp.
The server then verifies that it has the requested asymmetric signature verification key,
corresponding to the kid sent by the client. The server verifies that it has a compatible protocol configuration. 
The server loads the client's signature verification key, and checks the signature of the message:
hm = Vvk(smh)
If the signature is verified, the server hashes the message kid, config string, and serialized packet header
and compares the signed hash:
hm ?= H(kid || cfg || sph)
The server stores a hash of the configuration string, key identity, and both public signature verification-keys, 
to create the public key hash, which is used as a session cookie.
sch = H(cfg || kid || pvka || pvkb)
The server then generates an asymmetric encryption key-pair, stores the private key, 
hashes the public encapsulation key, and then signs the hash of the public encapsulation key and the serialized 
packet header using the asymmetric signature key.
The public signature verification key can itself be signed by a ‘chain of trust' model, 
like X.509, using a signature verification extension to this protocol.
ek,sk = G(r)
hek = H(ek || sph)
shek = Ssk(pkh)
The server sends a connect response message containing a signed hash of the public asymmetric encapsulation-key, 
and a copy of that key.
S{ shek || ek }-> C
*/
static dktp_errors kex_server_connect_response(dktp_kex_server_state* kss, dktp_connection_state* cns, const dktp_network_packet* packetin, dktp_network_packet* packetout)
{
	DKTP_ASSERT(cns != NULL);
	DKTP_ASSERT(kss != NULL);
	DKTP_ASSERT(packetin != NULL);
	DKTP_ASSERT(packetout != NULL);

	dktp_errors qerr;

	qerr = dktp_error_none;

	if (cns != NULL && kss != NULL && packetin != NULL && packetout != NULL)
	{
		uint64_t tm;

		tm = qsc_timestamp_datetime_utc();

		/* check the keys expiration date */
		if (tm <= kss->expiration)
		{
			char confs[DKTP_CONFIG_SIZE + sizeof(char)] = { 0 };

			/* get a copy of the configuration string */
			qsc_memutils_copy(confs, packetin->pmessage + DKTP_KEYID_SIZE, DKTP_CONFIG_SIZE);

			/* compare the state configuration string to the message configuration string */
			if (qsc_stringutils_compare_strings(confs, DKTP_CONFIG_STRING, DKTP_CONFIG_SIZE) == true)
			{
				uint8_t hm[DKTP_HASH_SIZE] = { 0U };
				size_t mlen;
				size_t slen;

				slen = 0U;
				mlen = DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE;

				/* verify the asymmetric signature */
				if (dktp_signature_verify(hm, &slen, packetin->pmessage + DKTP_KEYID_SIZE + DKTP_CONFIG_SIZE, mlen, kss->rverkey) == true)
				{
					qsc_keccak_state kstate = { 0 };
					uint8_t hmc[DKTP_HASH_SIZE] = { 0U };
					uint8_t shdr[DKTP_HEADER_SIZE] = { 0U };

					/* serialize header, then hash/sign the header and message */
					dktp_packet_header_serialize(packetin, shdr);
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, DKTP_HEADER_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetin->pmessage, DKTP_KEYID_SIZE + DKTP_CONFIG_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, hmc);

					/* verify the message hash */
					if (qsc_intutils_verify(hm, hmc, DKTP_HASH_SIZE) == 0)
					{
						/* store a hash of the session token, the configuration string,
							and the public signature key: sch = H(stok || cfg || pvk) */
						qsc_memutils_clear(kss->schash, DKTP_HASH_SIZE);
						qsc_sha3_initialize(&kstate);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, (const uint8_t*)DKTP_CONFIG_STRING, DKTP_CONFIG_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->keyid, DKTP_KEYID_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->rverkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
						qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kss->schash);

						/* initialize the packet and asymmetric encryption keys */
						qsc_memutils_clear(kss->enckey, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
						qsc_memutils_clear(kss->deckey, DKTP_ASYMMETRIC_DECAPSULATION_KEY_SIZE);

						/* generate the asymmetric encryption key-pair */
						dktp_cipher_generate_keypair(kss->enckey, kss->deckey, qsc_acp_generate);

						/* assemble the connection-response packet */
						dktp_header_create(packetout, dktp_flag_connect_response, cns->txseq, KEX_CONNECT_RESPONSE_MESSAGE_SIZE);

						/* hash the public encapsulation key and header */
						dktp_packet_header_serialize(packetout, shdr);
						qsc_sha3_initialize(&kstate);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, DKTP_HEADER_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->enckey, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
						qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, hm);

						/* sign the hash and add it to the message */
						mlen = 0U;
						dktp_signature_sign(packetout->pmessage, &mlen, hm, DKTP_HASH_SIZE, kss->sigkey, qsc_acp_generate);

						/* copy the public key to the message */
						qsc_memutils_copy(((uint8_t*)packetout->pmessage + mlen), kss->enckey, DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);

						qerr = dktp_error_none;
						cns->exflag = dktp_flag_connect_response;
					}
					else
					{
						cns->exflag = dktp_flag_none;
						qerr = dktp_error_verify_failure;
					}
				}
				else
				{
					cns->exflag = dktp_flag_none;
					qerr = dktp_error_authentication_failure;
				}
			}
			else
			{
				cns->exflag = dktp_flag_none;
				qerr = dktp_error_unknown_protocol;
			}
		}
		else
		{
			cns->exflag = dktp_flag_none;
			qerr = dktp_error_key_expired;
		}
	}
	else
	{
		cns->exflag = dktp_flag_none;
		qerr = dktp_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Response:
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the exchange request packet.
The server verifies the signature of the hash, then generates its own hash of the encapsulation key, ciphertext, and serialized header, 
and compares it with the one contained in the message.
If the hash matches, the server uses the decapsulation key to decapsulate the shared secret.
If the hash comparison fails, the key exchange is aborted.
cond = Vvk(H(ek || cpta)) = (true ?= cph : 0)
The server decapsulates the second shared-secret, and stores the secret (secr).
secr = -Edk(cpta)
The server generates a cipher-text and the second shared secret (secl) using the clients public encapsulation key.
cptb = Eek(secl)
The server combines the asymmetric shared secrets with the pre-shared secrets to create the transmit and receive session keys,
and nonces, independently keying each channel of the communications stream.
kl, nl = KDF(secl, pssr)
kr, nr = KDF(secr, pssl)
The receive and transmit channel ciphers are initialized.
cprrx(kr, nr)
cprtx(kl, nl)
The server hashes the cipher-text and serialized packet header, and signs the hash.
hcpt = H(cptb || sh)
scph = Ssk(cpth)
The server sends the signed hash of the cipher-text, and the cipher-text to the client.
S{ shcp || cptb }-> C
*/
static dktp_errors kex_server_exchange_response(dktp_kex_server_state* kss, dktp_connection_state* cns, const dktp_network_packet* packetin, dktp_network_packet* packetout)
{
	DKTP_ASSERT(kss != NULL);
	DKTP_ASSERT(packetin != NULL);
	DKTP_ASSERT(packetout != NULL);

	dktp_errors qerr;

	if (kss != NULL && packetin != NULL && packetout != NULL)
	{
		uint8_t khash[DKTP_HASH_SIZE] = { 0U };
		size_t mlen;
		size_t slen;

		slen = 0;
		mlen = DKTP_ASYMMETRIC_SIGNATURE_SIZE + DKTP_HASH_SIZE;

		/* verify the asymmetric signature */
		if (dktp_signature_verify(khash, &slen, packetin->pmessage + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE, mlen, kss->rverkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t phash[DKTP_HASH_SIZE] = { 0U };
			uint8_t shdr[DKTP_HEADER_SIZE] = { 0U };

			/* hash the public encapsulation key and header */
			dktp_packet_header_serialize(packetin, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, DKTP_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetin->pmessage, DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

			/* verify the public key hash */
			if (qsc_intutils_verify(phash, khash, DKTP_HASH_SIZE) == 0)
			{
				uint8_t secl[DKTP_SECRET_SIZE] = { 0U };
				uint8_t secr[DKTP_SECRET_SIZE] = { 0U };

				if (dktp_cipher_decapsulate(secr, packetin->pmessage, kss->deckey) == true)
				{
					uint8_t prnd[(QSC_KECCAK_512_RATE * 2U)] = { 0U };

					/* generate, and encapsulate the secret and store the cipher-text in the message */
					dktp_cipher_encapsulate(secl, packetout->pmessage, packetin->pmessage + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE, qsc_acp_generate);

					/* assemble the exstart-request packet */
					dktp_header_create(packetout, dktp_flag_exchange_response, cns->txseq, KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);
					
					/* hash the public encapsulation key and header */
					dktp_packet_header_serialize(packetout, shdr);
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, DKTP_HEADER_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetout->pmessage, DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

					/* sign the hash and add it to the message */
					mlen = 0U;
					dktp_signature_sign(packetout->pmessage + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE, &mlen, phash, DKTP_HASH_SIZE, kss->sigkey, qsc_acp_generate);

					/* initialize cSHAKE tckl = H(secl, pssr) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, secr, DKTP_SECRET_SIZE, NULL, 0, kss->pssl, DKTP_SECRET_SIZE);
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 2);
					qsc_memutils_clear(secr, sizeof(secr));

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qsc_rcs_keyparams kp = { 0 };
					kp.key = prnd;
					kp.keylen = DKTP_SYMMETRIC_KEY_SIZE;
					kp.nonce = prnd + DKTP_SYMMETRIC_KEY_SIZE;
					kp.info = NULL;
					kp.infolen = 0U;
					qsc_rcs_initialize(&cns->rxcpr, &kp, false);

					/* pssr = H(pssr, tckr) */
					qsc_cshake512_compute(kss->pssr, DKTP_SECRET_SIZE, kss->pssr, DKTP_SECRET_SIZE, NULL, 0, prnd, DKTP_SECRET_SIZE);

					/* initialize cSHAKE tckr = H(secr, pssl) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, secl, DKTP_SECRET_SIZE, NULL, 0, kss->pssr, DKTP_SECRET_SIZE);
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 2);
					qsc_memutils_clear(secl, sizeof(secl));

					/* initialize the symmetric cipher, and raise client channel-1 rx */
					kp.key = prnd;
					kp.keylen = DKTP_SYMMETRIC_KEY_SIZE;
					kp.nonce = prnd + DKTP_SYMMETRIC_KEY_SIZE;
					kp.info = NULL;
					kp.infolen = 0U;
					qsc_rcs_initialize(&cns->txcpr, &kp, true);
					qsc_memutils_clear((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));

					/* pssl = H(pssl, tckl) */
					qsc_cshake512_compute(kss->pssl, DKTP_SECRET_SIZE, kss->pssl, DKTP_SECRET_SIZE, NULL, 0, prnd, DKTP_SECRET_SIZE);
					qsc_memutils_clear(prnd, sizeof(prnd));

					qerr = dktp_error_none;
					cns->exflag = dktp_flag_exchange_response;
				}
				else
				{
					cns->exflag = dktp_flag_none;
					qerr = dktp_error_decapsulation_failure;
				}
			}
			else
			{
				cns->exflag = dktp_flag_none;
				qerr = dktp_error_hash_invalid;
			}
		}
		else
		{
			cns->exflag = dktp_flag_none;
			qerr = dktp_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = dktp_flag_none;
		qerr = dktp_error_invalid_input;
	}

	return qerr;
}

/*
Establish Response:
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the establish request packet.
If the flag is set to establish request, the server sends an empty message back to the client 
with the establish response flag set. 
Otherwise the tunnel is in an error state indicated in the message, and the tunnel is torn down on both sides. 
The server sets the operational state to session established, and is now ready to process data.
The server uses the rx cipher to decrypt the message, adding the serialized packet header to the additional data of the cipher MAC. 
The decrypted session cookie is compared to a hash of the local session cookie and timestamp/sequence for equivalence. 
If the cookie is verified, the server hashes the session cookie, and encrypts it with the tx cipher,
adding the serialized establish response packet header to the AD of the tx cipher.
hsch = H(sch || ts)
cm = Ek(hsch, sh)
S{ cm }-> C
*/
static dktp_errors kex_server_establish_response(dktp_kex_server_state* kss, dktp_connection_state* cns, const dktp_network_packet* packetin, dktp_network_packet* packetout)
{
	DKTP_ASSERT(cns != NULL);
	DKTP_ASSERT(packetin != NULL);
	DKTP_ASSERT(packetout != NULL);
	
	dktp_errors qerr;

	qerr = dktp_error_invalid_input;

	if (cns != NULL && packetin != NULL && packetout != NULL)
	{
		uint8_t hm[DKTP_HASH_SIZE];
		uint8_t shdr[DKTP_HEADER_SIZE] = { 0U };

		/* decrypt and verify the schash */
		dktp_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, DKTP_HEADER_SIZE);

		if (qsc_rcs_transform(&cns->rxcpr, hm, packetin->pmessage, DKTP_HASH_SIZE) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t sch[DKTP_HASH_SIZE] = { 0 };
			uint8_t st[DKTP_KEX_SEQTIME_SIZE] = { 0 };

			kex_extract_seqtime(st, packetin);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, st, sizeof(st));
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, (uint8_t*)DKTP_DOMAIN_IDENTITY_STRING, DKTP_DOMAIN_IDENTITY_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->schash, DKTP_HASH_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, sch);

			/* verify the schash */
			if (qsc_intutils_verify(hm, sch, DKTP_HASH_SIZE) == 0)
			{
				/* assemble the establish-response packet */
				dktp_header_create(packetout, dktp_flag_establish_response, cns->txseq, KEX_ESTABLISH_RESPONSE_MESSAGE_SIZE);

				/* hash the schash and send it in the establish response message */
				kex_extract_seqtime(st, packetout);
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, st, sizeof(st));
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, (uint8_t*)DKTP_DOMAIN_IDENTITY_STRING, DKTP_DOMAIN_IDENTITY_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->schash, DKTP_HASH_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, sch);

				dktp_packet_header_serialize(packetout, shdr);
				qsc_rcs_set_associated(&cns->txcpr, shdr, DKTP_HEADER_SIZE);
				qsc_rcs_transform(&cns->txcpr, packetout->pmessage, sch, DKTP_HASH_SIZE);

				qerr = dktp_error_none;
				cns->exflag = dktp_flag_session_established;
			}
			else
			{
				cns->exflag = dktp_flag_none;
				qerr = dktp_error_verify_failure;
			}
		}
		else
		{
			cns->exflag = dktp_flag_none;
			qerr = dktp_error_decryption_failure;
		}
	}

	return qerr;
}

dktp_errors dktp_kex_client_key_exchange(dktp_kex_client_state* kcs, dktp_connection_state* cns)
{
	DKTP_ASSERT(kcs != NULL);
	DKTP_ASSERT(cns != NULL);

	dktp_network_packet reqt = { 0 };
	dktp_network_packet resp = { 0 };
	size_t rlen;
	size_t slen;
	dktp_errors qerr;

	if (kcs != NULL && cns != NULL)
	{
		uint8_t* rbuf;

		rbuf = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);

		if (rbuf != NULL)
		{
			uint8_t* sbuf;

			sbuf = (uint8_t*)qsc_memutils_malloc(KEX_CONNECT_REQUEST_PACKET_SIZE);

			if (sbuf != NULL)
			{
				/* 1. connect stage */
				qsc_memutils_clear(sbuf, KEX_CONNECT_REQUEST_PACKET_SIZE);
				reqt.pmessage = sbuf + DKTP_HEADER_SIZE;

				/* create the connection request packet */
				qerr = kex_client_connect_request(kcs, cns, &reqt);

				if (qerr == dktp_error_none)
				{
					dktp_packet_header_serialize(&reqt, sbuf);
					/* send the connection request */
					slen = qsc_socket_send(&cns->target, sbuf, KEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

					/* check the size sent */
					if (slen == KEX_CONNECT_REQUEST_PACKET_SIZE)
					{
						/* increment the transmit sequence counter */
						cns->txseq += 1U;
						/* reallocate to the message connect response buffer size */
						rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE);

						if (rbuf != NULL)
						{
							/* allocated memory must be set to zero per MISRA */
							qsc_memutils_clear(rbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE);
							resp.pmessage = rbuf + DKTP_HEADER_SIZE;

							/* blocking receive waits for connect response */
							rlen = qsc_socket_receive(&cns->target, rbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

							if (rlen == KEX_CONNECT_RESPONSE_PACKET_SIZE)
							{
								/* convert server response to packet */
								dktp_packet_header_deserialize(rbuf, &resp);
								/* validate the packet header including the timestamp */
								qerr = dktp_header_validate(cns, &resp, dktp_flag_connect_request, dktp_flag_connect_response, cns->rxseq, KEX_CONNECT_RESPONSE_MESSAGE_SIZE);
							}
							else
							{
								qerr = dktp_error_receive_failure;
							}
						}
						else
						{
							qerr = dktp_error_memory_allocation;
						}
					}
					else
					{
						qerr = dktp_error_transmit_failure;
					}
				}

				/* 2. exchange stage */
				if (qerr == dktp_error_none)
				{
					sbuf = (uint8_t*)qsc_memutils_realloc(sbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);

					if (sbuf != NULL)
					{
						qsc_memutils_clear(sbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);
						reqt.pmessage = sbuf + DKTP_HEADER_SIZE;

						/* create the exchange request packet */
						qerr = kex_client_exchange_request(kcs, cns, &resp, &reqt);

						if (qerr == dktp_error_none)
						{
							/* serialize the packet header to the buffer */
							dktp_packet_header_serialize(&reqt, sbuf);

							/* send exchange request */
							slen = qsc_socket_send(&cns->target, sbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

							if (slen == KEX_EXCHANGE_REQUEST_PACKET_SIZE)
							{
								cns->txseq += 1U;
								rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);

								if (rbuf != NULL)
								{
									qsc_memutils_clear(rbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);
									resp.pmessage = rbuf + DKTP_HEADER_SIZE;

									/* wait for exchange response */
									rlen = qsc_socket_receive(&cns->target, rbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

									/* check the received size */
									if (rlen == KEX_EXCHANGE_RESPONSE_PACKET_SIZE)
									{
										/* convert server response to packet */
										dktp_packet_header_deserialize(rbuf, &resp);
										/* validate the header and timestamp */
										qerr = dktp_header_validate(cns, &resp, dktp_flag_exchange_request, dktp_flag_exchange_response, cns->rxseq, KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);
									}
									else
									{
										qerr = dktp_error_receive_failure;
									}
								}
								else
								{
									qerr = dktp_error_memory_allocation;
								}
							}
							else
							{
								qerr = dktp_error_transmit_failure;
							}
						}
					}
					else
					{
						qerr = dktp_error_memory_allocation;
					}
				}

				/* 3. establish stage */
				if (qerr == dktp_error_none)
				{
					sbuf = (uint8_t*)qsc_memutils_realloc(sbuf, KEX_ESTABLISH_REQUEST_PACKET_SIZE);

					if (sbuf != NULL)
					{
						qsc_memutils_clear(sbuf, KEX_ESTABLISH_REQUEST_PACKET_SIZE);
						reqt.pmessage = sbuf + DKTP_HEADER_SIZE;

						/* create the establish request packet */
						qerr = kex_client_establish_request(kcs, cns, &resp, &reqt);

						if (qerr == dktp_error_none)
						{
							dktp_packet_header_serialize(&reqt, sbuf);

							/* send the establish request packet */
							slen = qsc_socket_send(&cns->target, sbuf, KEX_ESTABLISH_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
							/* clear the send buffer */
							qsc_memutils_clear(sbuf, KEX_ESTABLISH_REQUEST_PACKET_SIZE);

							if (slen == KEX_ESTABLISH_REQUEST_PACKET_SIZE)
							{
								cns->txseq += 1U;
								rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, KEX_ESTABLISH_RESPONSE_PACKET_SIZE);

								if (rbuf != NULL)
								{
									qsc_memutils_clear(rbuf, KEX_ESTABLISH_RESPONSE_PACKET_SIZE);
									resp.pmessage = rbuf + DKTP_HEADER_SIZE;

									/* wait for the establish response */
									rlen = qsc_socket_receive(&cns->target, rbuf, KEX_ESTABLISH_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

									if (rlen == KEX_ESTABLISH_RESPONSE_PACKET_SIZE)
									{
										dktp_packet_header_deserialize(rbuf, &resp);
										/* validate the header */
										qerr = dktp_header_validate(cns, &resp, dktp_flag_establish_request, dktp_flag_establish_response, cns->rxseq, KEX_ESTABLISH_RESPONSE_MESSAGE_SIZE);

										if (qerr == dktp_error_none)
										{
											/* verify the exchange  */
											qerr = kex_client_establish_verify(kcs, cns, &resp);
											/* clear receive buffer */
											qsc_memutils_clear(rbuf, KEX_ESTABLISH_RESPONSE_PACKET_SIZE);
										}
										else
										{
											qerr = dktp_error_packet_unsequenced;
										}
									}
									else
									{
										qerr = dktp_error_receive_failure;
									}
								}
								else
								{
									qerr = dktp_error_memory_allocation;
								}
							}
							else
							{
								qerr = dktp_error_transmit_failure;
							}
						}
					}
					else
					{
						qerr = dktp_error_memory_allocation;
					}
				}

				qsc_memutils_alloc_free(sbuf);
			}
			else
			{
				qerr = dktp_error_memory_allocation;
			}

			qsc_memutils_alloc_free(rbuf);
		}
		else
		{
			qerr = dktp_error_memory_allocation;
		}

		if (qerr != dktp_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_send_network_error(&cns->target, qerr);
				qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
			}

			dktp_connection_state_dispose(cns);
		}
	}
	else
	{
		qerr = dktp_error_invalid_input;
	}

	return qerr;
}

dktp_errors dktp_kex_server_key_exchange(dktp_kex_server_state* kss, dktp_connection_state* cns)
{
	DKTP_ASSERT(kss != NULL);
	DKTP_ASSERT(cns != NULL);

	dktp_network_packet reqt = { 0 };
	dktp_network_packet resp = { 0 };
	size_t rlen;
	size_t slen;
	dktp_errors qerr;

	if (kss != NULL && cns != NULL)
	{
		uint8_t* rbuf;

		rbuf = (uint8_t*)qsc_memutils_malloc(KEX_CONNECT_REQUEST_PACKET_SIZE);

		if (rbuf != NULL)
		{
			uint8_t* sbuf;

			sbuf = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);

			if (sbuf != NULL)
			{
				/* 1. connect stage */
				qsc_memutils_clear(rbuf, KEX_CONNECT_REQUEST_PACKET_SIZE);
				resp.pmessage = rbuf + DKTP_HEADER_SIZE;

				/* blocking receive waits for client connect request */
				rlen = qsc_socket_receive(&cns->target, rbuf, KEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

				if (rlen == KEX_CONNECT_REQUEST_PACKET_SIZE)
				{
					/* convert server response to packet */
					dktp_packet_header_deserialize(rbuf, &resp);
					qerr = dktp_header_validate(cns, &resp, dktp_flag_none, dktp_flag_connect_request, cns->rxseq, KEX_CONNECT_REQUEST_MESSAGE_SIZE);

					if (qerr == dktp_error_none)
					{
						sbuf = (uint8_t*)qsc_memutils_realloc(sbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE);

						if (sbuf != NULL)
						{
							qsc_memutils_clear(sbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE);
							reqt.pmessage = sbuf + DKTP_HEADER_SIZE;

							/* create the connection request packet */
							qerr = kex_server_connect_response(kss, cns, &resp, &reqt);

							if (qerr == dktp_error_none)
							{
								dktp_packet_header_serialize(&reqt, sbuf);
								slen = qsc_socket_send(&cns->target, sbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

								if (slen == KEX_CONNECT_RESPONSE_PACKET_SIZE)
								{
									cns->txseq += 1U;
								}
								else
								{
									qerr = dktp_error_transmit_failure;
								}
							}
						}
						else
						{
							qerr = dktp_error_memory_allocation;
						}
					}
				}
				else
				{
					qerr = dktp_error_receive_failure;
				}

				/* 2. exchange stage */
				if (qerr == dktp_error_none)
				{
					rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);

					if (rbuf != NULL)
					{
						qsc_memutils_clear(rbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);
						resp.pmessage = rbuf + DKTP_HEADER_SIZE;

						/* wait for the exchange request */
						rlen = qsc_socket_receive(&cns->target, rbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

						if (rlen == KEX_EXCHANGE_REQUEST_PACKET_SIZE)
						{
							dktp_packet_header_deserialize(rbuf, &resp);
							qerr = dktp_header_validate(cns, &resp, dktp_flag_connect_response, dktp_flag_exchange_request, cns->rxseq, KEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

							if (qerr == dktp_error_none)
							{
								sbuf = (uint8_t*)qsc_memutils_realloc(sbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);

								if (sbuf != NULL)
								{
									qsc_memutils_clear(sbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);
									reqt.pmessage = sbuf + DKTP_HEADER_SIZE;

									/* create the exchange response packet */
									qerr = kex_server_exchange_response(kss, cns, &resp, &reqt);

									if (qerr == dktp_error_none)
									{
										dktp_packet_header_serialize(&reqt, sbuf);
										slen = qsc_socket_send(&cns->target, sbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

										if (slen == KEX_EXCHANGE_RESPONSE_PACKET_SIZE)
										{
											cns->txseq += 1U;
										}
										else
										{
											qerr = dktp_error_transmit_failure;
										}
									}
								}
								else
								{
									qerr = dktp_error_memory_allocation;
								}
							}
						}
						else
						{
							qerr = dktp_error_receive_failure;
						}
					}
					else
					{
						qerr = dktp_error_memory_allocation;
					}
				}

				/* 3. establish stage */
				if (qerr == dktp_error_none)
				{
					rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, KEX_ESTABLISH_REQUEST_PACKET_SIZE);

					if (rbuf != NULL)
					{
						qsc_memutils_clear(rbuf, KEX_ESTABLISH_REQUEST_PACKET_SIZE);
						resp.pmessage = rbuf + DKTP_HEADER_SIZE;

						/* wait for the establish request */
						rlen = qsc_socket_receive(&cns->target, rbuf, KEX_ESTABLISH_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

						if (rlen == KEX_ESTABLISH_REQUEST_PACKET_SIZE)
						{
							dktp_packet_header_deserialize(rbuf, &resp);
							qerr = dktp_header_validate(cns, &resp, dktp_flag_exchange_response, dktp_flag_establish_request, cns->rxseq, KEX_ESTABLISH_REQUEST_MESSAGE_SIZE);

							if (qerr == dktp_error_none)
							{
								sbuf = (uint8_t*)qsc_memutils_realloc(sbuf, KEX_ESTABLISH_RESPONSE_PACKET_SIZE);

								if (sbuf != NULL)
								{
									qsc_memutils_clear(sbuf, KEX_ESTABLISH_RESPONSE_PACKET_SIZE);
									reqt.pmessage = sbuf + DKTP_HEADER_SIZE;

									/* create the establish response packet */
									qerr = kex_server_establish_response(kss, cns, &resp, &reqt);

									/* erase the receive buffer */
									qsc_memutils_clear(rbuf, KEX_ESTABLISH_REQUEST_PACKET_SIZE);

									if (qerr == dktp_error_none)
									{
										dktp_packet_header_serialize(&reqt, sbuf);
										slen = qsc_socket_send(&cns->target, sbuf, KEX_ESTABLISH_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

										/* erase the transmit buffer */
										qsc_memutils_clear(sbuf, KEX_ESTABLISH_RESPONSE_PACKET_SIZE);

										if (slen == KEX_ESTABLISH_RESPONSE_PACKET_SIZE)
										{
											cns->txseq += 1U;
										}
										else
										{
											qerr = dktp_error_transmit_failure;
										}
									}
								}
								else
								{
									qerr = dktp_error_memory_allocation;
								}
							}
						}
						else
						{
							qerr = dktp_error_receive_failure;
						}
					}
					else
					{
						qerr = dktp_error_memory_allocation;
					}
				}

				qsc_memutils_alloc_free(sbuf);
			}
			else
			{
				qerr = dktp_error_memory_allocation;
			}

			qsc_memutils_alloc_free(rbuf);
		}
		else
		{
			qerr = dktp_error_memory_allocation;
		}
	}
	else
	{
		qerr = dktp_error_invalid_input;
	}

	if (qerr != dktp_error_none)
	{
		if (cns->target.connection_status == qsc_socket_state_connected)
		{
			kex_send_network_error(&cns->target, qerr);
			qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
		}

		dktp_connection_state_dispose(cns);
	}

	return qerr;
}

bool dktp_kex_test(void)
{
	dktp_kex_client_state dkcs = { 0 };
	dktp_kex_server_state dkss = { 0 };
	dktp_connection_state cnc = { 0 };
	dktp_connection_state cns = { 0 };
	dktp_network_packet pckclt = { 0 };
	dktp_network_packet pcksrv = { 0 };
	uint8_t mclt[DKTP_HEADER_SIZE + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + DKTP_HASH_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE] = { 0U };
	uint8_t msrv[DKTP_HEADER_SIZE + DKTP_ASYMMETRIC_CIPHER_TEXT_SIZE + DKTP_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + DKTP_HASH_SIZE + DKTP_ASYMMETRIC_SIGNATURE_SIZE] = { 0U };
	dktp_errors qerr;
	bool res;

	pckclt.pmessage = mclt;
	pcksrv.pmessage = msrv;
	dktp_signature_generate_keypair(dkcs.verkey, dkcs.sigkey, qsc_acp_generate);
	dktp_signature_generate_keypair(dkss.verkey, dkss.sigkey, qsc_acp_generate);
	qsc_memutils_copy(dkcs.rverkey, dkss.verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_copy(dkss.rverkey, dkcs.verkey, DKTP_ASYMMETRIC_VERIFY_KEY_SIZE);

	dkcs.expiration = qsc_timestamp_datetime_utc() + DKTP_PUBKEY_DURATION_SECONDS;
	dkss.expiration = dkcs.expiration;

	res = false;
	qerr = kex_client_connect_request(&dkcs, &cnc, &pckclt);

	if (qerr == dktp_error_none)
	{
		qerr = kex_server_connect_response(&dkss, &cns, &pckclt, &pcksrv);

		if (qerr == dktp_error_none)
		{
			qerr = kex_client_exchange_request(&dkcs, &cnc, &pcksrv, &pckclt);

			if (qerr == dktp_error_none)
			{
				qerr = kex_server_exchange_response(&dkss, &cns, &pckclt, &pcksrv);

				if (qerr == dktp_error_none)
				{
					qerr = kex_client_establish_request(&dkcs, &cnc, &pcksrv, &pckclt);

					if (qerr == dktp_error_none)
					{
						qerr = kex_server_establish_response(&dkss, &cns, &pckclt, &pcksrv);

						if (qerr == dktp_error_none)
						{
							qerr = kex_client_establish_verify(&dkcs, &cnc, &pcksrv);

							if (qerr == dktp_error_none)
							{
								res = true;
							}
						}
					}
				}
			}
		}
	}

	return res;
}
