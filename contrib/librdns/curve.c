/*
 * Copyright (c) 2014, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "rdns.h"
#include "dns_private.h"
#include "rdns_curve.h"
#include "ottery.h"
#include "ref.h"
#include "logger.h"

#ifdef TWEETNACL

#include <tweetnacl.h>

void
randombytes(uint8_t *data, uint64_t len)
{
	ottery_rand_bytes (data, len);
}
void sodium_memzero (uint8_t *data, uint64_t len)
{
	volatile uint8_t *p = data;

	while (len--) {
		*p = '\0';
	}
}
void sodium_init(void)
{

}

ssize_t rdns_curve_send (struct rdns_request *req, void *plugin_data);
ssize_t rdns_curve_recv (struct rdns_io_channel *ioc, void *buf, size_t len,
		void *plugin_data, struct rdns_request **req_out);
void rdns_curve_finish_request (struct rdns_request *req, void *plugin_data);
void rdns_curve_dtor (struct rdns_resolver *resolver, void *plugin_data);

struct rdns_curve_entry {
	char *name;
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	UT_hash_handle hh;
};

struct rdns_curve_nm_entry {
	unsigned char k[crypto_box_BEFORENMBYTES];
	struct rdns_curve_entry *entry;
	struct rdns_curve_nm_entry *prev, *next;
};

struct rdns_curve_client_key {
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	struct rdns_curve_nm_entry *nms;
	uint64_t counter;
	unsigned int uses;
	ref_entry_t ref;
};

struct rdns_curve_request {
	struct rdns_request *req;
	struct rdns_curve_client_key *key;
	struct rdns_curve_entry *entry;
	struct rdns_curve_nm_entry *nm;
	unsigned char nonce[crypto_box_NONCEBYTES];
	UT_hash_handle hh;
};

struct rdns_curve_ctx {
	struct rdns_curve_entry *entries;
	struct rdns_curve_client_key *cur_key;
	struct rdns_curve_request *requests;
	double key_refresh_interval;
	void *key_refresh_event;
	struct rdns_resolver *resolver;
};

static struct rdns_curve_client_key *
rdns_curve_client_key_new (struct rdns_curve_ctx *ctx)
{
	struct rdns_curve_client_key *new;
	struct rdns_curve_nm_entry *nm;
	struct rdns_curve_entry *entry, *tmp;

	new = calloc (1, sizeof (struct rdns_curve_client_key));
	crypto_box_keypair (new->pk, new->sk);

	HASH_ITER (hh, ctx->entries, entry, tmp) {
		nm = calloc (1, sizeof (struct rdns_curve_nm_entry));
		nm->entry = entry;
		crypto_box_beforenm (nm->k, entry->pk, new->sk);

		DL_APPEND (new->nms, nm);
	}

	new->counter = ottery_rand_uint64 ();

	return new;
}

static struct rdns_curve_nm_entry *
rdns_curve_find_nm (struct rdns_curve_client_key *key, struct rdns_curve_entry *entry)
{
	struct rdns_curve_nm_entry *nm;

	DL_FOREACH (key->nms, nm) {
		if (nm->entry == entry) {
			return nm;
		}
	}

	return NULL;
}

static void
rdns_curve_client_key_free (struct rdns_curve_client_key *key)
{
	struct rdns_curve_nm_entry *nm, *tmp;

	DL_FOREACH_SAFE (key->nms, nm, tmp) {
		sodium_memzero (nm->k, sizeof (nm->k));
		free (nm);
	}
	sodium_memzero (key->sk, sizeof (key->sk));
	free (key);
}

struct rdns_curve_ctx*
rdns_curve_ctx_new (double key_refresh_interval)
{
	struct rdns_curve_ctx *new;

	new = calloc (1, sizeof (struct rdns_curve_ctx));
	new->key_refresh_interval = key_refresh_interval;

	return new;
}

void
rdns_curve_ctx_add_key (struct rdns_curve_ctx *ctx,
		const char *name, const unsigned char *pubkey)
{
	struct rdns_curve_entry *entry;
	bool success = true;

	entry = malloc (sizeof (struct rdns_curve_entry));
	if (entry != NULL) {
		entry->name = strdup (name);
		if (entry->name == NULL) {
			success = false;
		}
		memcpy (entry->pk, pubkey, sizeof (entry->pk));
		if (success) {
			HASH_ADD_KEYPTR (hh, ctx->entries, entry->name, strlen (entry->name), entry);
		}
	}
}

#define rdns_curve_write_hex(in, out, offset, base) do {					\
    *(out) |= ((in)[(offset)] - (base)) << ((1 - offset) * 4);				\
} while (0)

static bool
rdns_curve_hex_to_byte (const char *in, unsigned char *out)
{
	int i;

	for (i = 0; i <= 1; i ++) {
		if (in[i] >= '0' && in[i] <= '9') {
			rdns_curve_write_hex (in, out, i, '0');
		}
		else if (in[i] >= 'a' && in[i] <= 'f') {
			rdns_curve_write_hex (in, out, i, 'a' - 10);
		}
		else if (in[i] >= 'A' && in[i] <= 'F') {
			rdns_curve_write_hex (in, out, i, 'A' - 10);
		}
		else {
			return false;
		}
	}
	return true;
}

#undef rdns_curve_write_hex

unsigned char *
rdns_curve_key_from_hex (const char *hex)
{
	unsigned int len = strlen (hex), i;
	unsigned char *res = NULL;

	if (len == crypto_box_PUBLICKEYBYTES * 2) {
		res = calloc (1, crypto_box_PUBLICKEYBYTES);
		for (i = 0; i < crypto_box_PUBLICKEYBYTES; i ++) {
			if (!rdns_curve_hex_to_byte (&hex[i * 2], &res[i])) {
				free (res);
				return NULL;
			}
		}
	}

	return res;
}

void
rdns_curve_ctx_destroy (struct rdns_curve_ctx *ctx)
{
	struct rdns_curve_entry *entry, *tmp;

	HASH_ITER (hh, ctx->entries, entry, tmp) {
		free (entry->name);
		free (entry);
	}

	free (ctx);
}

static void
rdns_curve_refresh_key_callback (void *user_data)
{
	struct rdns_curve_ctx *ctx = user_data;
	struct rdns_resolver *resolver;

	resolver = ctx->resolver;
	rdns_info ("refresh dnscurve keys");
	REF_RELEASE (ctx->cur_key);
	ctx->cur_key = rdns_curve_client_key_new (ctx);
	REF_INIT_RETAIN (ctx->cur_key, rdns_curve_client_key_free);
}

void
rdns_curve_register_plugin (struct rdns_resolver *resolver,
		struct rdns_curve_ctx *ctx)
{
	struct rdns_plugin *plugin;

	if (!resolver->async_binded) {
		return;
	}

	plugin = calloc (1, sizeof (struct rdns_plugin));
	if (plugin != NULL) {
		plugin->data = ctx;
		plugin->type = RDNS_PLUGIN_CURVE;
		plugin->cb.curve_plugin.send_cb = rdns_curve_send;
		plugin->cb.curve_plugin.recv_cb = rdns_curve_recv;
		plugin->cb.curve_plugin.finish_cb = rdns_curve_finish_request;
		plugin->dtor = rdns_curve_dtor;
		sodium_init ();
		ctx->cur_key = rdns_curve_client_key_new (ctx);
		REF_INIT_RETAIN (ctx->cur_key, rdns_curve_client_key_free);

		if (ctx->key_refresh_interval > 0) {
			ctx->key_refresh_event = resolver->async->add_periodic (
					resolver->async->data, ctx->key_refresh_interval,
					rdns_curve_refresh_key_callback, ctx);
		}
		ctx->resolver = resolver;
		rdns_resolver_register_plugin (resolver, plugin);
	}
}

ssize_t
rdns_curve_send (struct rdns_request *req, void *plugin_data)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;
	struct rdns_curve_entry *entry;
	struct iovec iov[4];
	unsigned char *m;
	static const char qmagic[] = "Q6fnvWj8";
	struct rdns_curve_request *creq;
	struct rdns_curve_nm_entry *nm;
	ssize_t ret, boxed_len;

	/* Check for key */
	HASH_FIND_STR (ctx->entries, req->io->srv->name, entry);
	if (entry != NULL) {
		nm = rdns_curve_find_nm (ctx->cur_key, entry);
		creq = malloc (sizeof (struct rdns_curve_request));
		if (creq == NULL) {
			return -1;
		}

		boxed_len = req->pos + crypto_box_ZEROBYTES;
		m = malloc (boxed_len);
		if (m == NULL) {
			return -1;
		}

		/* Ottery is faster than sodium native PRG that uses /dev/random only */
		memcpy (creq->nonce, &ctx->cur_key->counter, sizeof (uint64_t));
		ottery_rand_bytes (creq->nonce + sizeof (uint64_t), 12 - sizeof (uint64_t));
		sodium_memzero (creq->nonce + 12, crypto_box_NONCEBYTES - 12);

		sodium_memzero (m, crypto_box_ZEROBYTES);
		memcpy (m + crypto_box_ZEROBYTES, req->packet, req->pos);

		if (crypto_box_afternm (m, m, boxed_len,
				creq->nonce, nm->k) == -1) {
			sodium_memzero (m, boxed_len);
			free (m);
			return -1;
		}

		creq->key = ctx->cur_key;
		REF_RETAIN (ctx->cur_key);
		creq->entry = entry;
		creq->req = req;
		creq->nm = nm;
		HASH_ADD_KEYPTR (hh, ctx->requests, creq->nonce, 12, creq);
		req->curve_plugin_data = creq;

		ctx->cur_key->counter ++;
		ctx->cur_key->uses ++;

		/* Now form a dnscurve packet */
		iov[0].iov_base = (void *)qmagic;
		iov[0].iov_len = sizeof (qmagic) - 1;
		iov[1].iov_base = ctx->cur_key->pk;
		iov[1].iov_len = sizeof (ctx->cur_key->pk);
		iov[2].iov_base = creq->nonce;
		iov[2].iov_len = 12;
		iov[3].iov_base = m + crypto_box_BOXZEROBYTES;
		iov[3].iov_len = boxed_len - crypto_box_BOXZEROBYTES;

		ret = writev (req->io->sock, iov, sizeof (iov) / sizeof (iov[0]));
		sodium_memzero (m, boxed_len);
		free (m);
	}
	else {
		ret = write (req->io->sock, req->packet, req->pos);
		req->curve_plugin_data = NULL;
	}

	return ret;
}

ssize_t
rdns_curve_recv (struct rdns_io_channel *ioc, void *buf, size_t len, void *plugin_data,
		struct rdns_request **req_out)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;
	ssize_t ret, boxlen;
	static const char rmagic[] = "R6fnvWJ8";
	unsigned char *p, *box;
	unsigned char enonce[crypto_box_NONCEBYTES];
	struct rdns_curve_request *creq;
	struct rdns_resolver *resolver;

	resolver = ctx->resolver;
	ret = read (ioc->sock, buf, len);

	if (ret <= 0 || ret < 64) {
		/* Definitely not a DNSCurve packet */
		return ret;
	}

	if (memcmp (buf, rmagic, sizeof (rmagic) - 1) == 0) {
		/* Likely DNSCurve packet */
		p = ((unsigned char *)buf) + 8;
		HASH_FIND (hh, ctx->requests, p, 12, creq);
		if (creq == NULL) {
			rdns_info ("unable to find nonce in the internal hash");
			return ret;
		}
		memcpy (enonce, p, crypto_box_NONCEBYTES);
		p += crypto_box_NONCEBYTES;
		boxlen = ret - crypto_box_NONCEBYTES +
				crypto_box_BOXZEROBYTES -
				sizeof (rmagic) + 1;
		if (boxlen < 0) {
			return ret;
		}
		box = malloc (boxlen);
		sodium_memzero (box, crypto_box_BOXZEROBYTES);
		memcpy (box + crypto_box_BOXZEROBYTES, p,
				boxlen - crypto_box_BOXZEROBYTES);

		if (crypto_box_open_afternm (box, box, boxlen, enonce, creq->nm->k) != -1) {
			memcpy (buf, box + crypto_box_ZEROBYTES,
					boxlen - crypto_box_ZEROBYTES);
			ret = boxlen - crypto_box_ZEROBYTES;
			*req_out = creq->req;
		}
		else {
			rdns_info ("unable open cryptobox of size %d", (int)boxlen);
		}
		free (box);
	}

	return ret;
}

void
rdns_curve_finish_request (struct rdns_request *req, void *plugin_data)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;
	struct rdns_curve_request *creq = req->curve_plugin_data;

	if (creq != NULL) {
		REF_RELEASE (creq->key);
		HASH_DELETE (hh, ctx->requests, creq);
	}
}

void
rdns_curve_dtor (struct rdns_resolver *resolver, void *plugin_data)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;

	if (ctx->key_refresh_event != NULL) {
		resolver->async->del_periodic (resolver->async->data,
				ctx->key_refresh_event);
	}
	REF_RELEASE (ctx->cur_key);
}
#elif defined(USE_RSPAMD_CRYPTOBOX)

#include "cryptobox.h"


#ifndef crypto_box_ZEROBYTES
#define crypto_box_ZEROBYTES 32
#endif
#ifndef crypto_box_BOXZEROBYTES
#define crypto_box_BOXZEROBYTES 16
#endif

ssize_t rdns_curve_send (struct rdns_request *req, void *plugin_data,
						 struct sockaddr *saddr, socklen_t slen);
ssize_t rdns_curve_recv (struct rdns_io_channel *ioc, void *buf, size_t len,
						 void *plugin_data, struct rdns_request **req_out,
						 struct sockaddr *saddr, socklen_t slen);
void rdns_curve_finish_request (struct rdns_request *req, void *plugin_data);
void rdns_curve_dtor (struct rdns_resolver *resolver, void *plugin_data);

struct rdns_curve_entry {
	char *name;
	rspamd_pk_t pk;
	UT_hash_handle hh;
};

struct rdns_curve_nm_entry {
	rspamd_nm_t k;
	struct rdns_curve_entry *entry;
	struct rdns_curve_nm_entry *prev, *next;
};

struct rdns_curve_client_key {
	rspamd_pk_t pk;
	rspamd_sk_t sk;
	struct rdns_curve_nm_entry *nms;
	uint64_t counter;
	unsigned int uses;
	ref_entry_t ref;
};

struct rdns_curve_request {
	struct rdns_request *req;
	struct rdns_curve_client_key *key;
	struct rdns_curve_entry *entry;
	struct rdns_curve_nm_entry *nm;
	rspamd_nonce_t nonce;
	UT_hash_handle hh;
};

struct rdns_curve_ctx {
	struct rdns_curve_entry *entries;
	struct rdns_curve_client_key *cur_key;
	struct rdns_curve_request *requests;
	double key_refresh_interval;
	void *key_refresh_event;
	struct rdns_resolver *resolver;
};

static struct rdns_curve_client_key *
rdns_curve_client_key_new (struct rdns_curve_ctx *ctx)
{
	struct rdns_curve_client_key *new;
	struct rdns_curve_nm_entry *nm;
	struct rdns_curve_entry *entry, *tmp;

	new = calloc (1, sizeof (struct rdns_curve_client_key));
	rspamd_cryptobox_keypair (new->pk, new->sk, RSPAMD_CRYPTOBOX_MODE_25519);

	HASH_ITER (hh, ctx->entries, entry, tmp) {
		nm = calloc (1, sizeof (struct rdns_curve_nm_entry));
		nm->entry = entry;
		rspamd_cryptobox_nm (nm->k, entry->pk, new->sk,
				RSPAMD_CRYPTOBOX_MODE_25519);

		DL_APPEND (new->nms, nm);
	}

	new->counter = ottery_rand_uint64 ();

	return new;
}

static struct rdns_curve_nm_entry *
rdns_curve_find_nm (struct rdns_curve_client_key *key, struct rdns_curve_entry *entry)
{
	struct rdns_curve_nm_entry *nm;

	DL_FOREACH (key->nms, nm) {
		if (nm->entry == entry) {
			return nm;
		}
	}

	return NULL;
}

static void
rdns_curve_client_key_free (struct rdns_curve_client_key *key)
{
	struct rdns_curve_nm_entry *nm, *tmp;

	DL_FOREACH_SAFE (key->nms, nm, tmp) {
		rspamd_explicit_memzero (nm->k, sizeof (nm->k));
		free (nm);
	}

	rspamd_explicit_memzero (key->sk, sizeof (key->sk));
	free (key);
}

struct rdns_curve_ctx*
rdns_curve_ctx_new (double key_refresh_interval)
{
	struct rdns_curve_ctx *new;

	new = calloc (1, sizeof (struct rdns_curve_ctx));
	new->key_refresh_interval = key_refresh_interval;

	return new;
}

void
rdns_curve_ctx_add_key (struct rdns_curve_ctx *ctx,
		const char *name, const unsigned char *pubkey)
{
	struct rdns_curve_entry *entry;
	bool success = true;

	entry = malloc (sizeof (struct rdns_curve_entry));
	if (entry != NULL) {
		entry->name = strdup (name);
		if (entry->name == NULL) {
			success = false;
		}
		memcpy (entry->pk, pubkey, sizeof (entry->pk));
		if (success) {
			HASH_ADD_KEYPTR (hh, ctx->entries, entry->name, strlen (entry->name), entry);
		}
	}
}

#define rdns_curve_write_hex(in, out, offset, base) do {					\
    *(out) |= ((in)[(offset)] - (base)) << ((1 - offset) * 4);				\
} while (0)

static bool
rdns_curve_hex_to_byte (const char *in, unsigned char *out)
{
	int i;

	for (i = 0; i <= 1; i ++) {
		if (in[i] >= '0' && in[i] <= '9') {
			rdns_curve_write_hex (in, out, i, '0');
		}
		else if (in[i] >= 'a' && in[i] <= 'f') {
			rdns_curve_write_hex (in, out, i, 'a' - 10);
		}
		else if (in[i] >= 'A' && in[i] <= 'F') {
			rdns_curve_write_hex (in, out, i, 'A' - 10);
		}
		else {
			return false;
		}
	}
	return true;
}

#undef rdns_curve_write_hex

unsigned char *
rdns_curve_key_from_hex (const char *hex)
{
	unsigned int len = strlen (hex), i;
	unsigned char *res = NULL;

	if (len == rspamd_cryptobox_pk_bytes (RSPAMD_CRYPTOBOX_MODE_25519) * 2) {
		res = calloc (1, rspamd_cryptobox_pk_bytes (RSPAMD_CRYPTOBOX_MODE_25519));
		for (i = 0;
				i < rspamd_cryptobox_pk_bytes (RSPAMD_CRYPTOBOX_MODE_25519);
				i ++) {
			if (!rdns_curve_hex_to_byte (&hex[i * 2], &res[i])) {
				free (res);
				return NULL;
			}
		}
	}

	return res;
}

void
rdns_curve_ctx_destroy (struct rdns_curve_ctx *ctx)
{
	struct rdns_curve_entry *entry, *tmp;

	HASH_ITER (hh, ctx->entries, entry, tmp) {
		free (entry->name);
		free (entry);
	}

	free (ctx);
}

static void
rdns_curve_refresh_key_callback (void *user_data)
{
	struct rdns_curve_ctx *ctx = user_data;
	struct rdns_resolver *resolver;

	resolver = ctx->resolver;
	rdns_info ("refresh dnscurve keys");
	REF_RELEASE (ctx->cur_key);
	ctx->cur_key = rdns_curve_client_key_new (ctx);
	REF_INIT_RETAIN (ctx->cur_key, rdns_curve_client_key_free);
}

void
rdns_curve_register_plugin (struct rdns_resolver *resolver,
		struct rdns_curve_ctx *ctx)
{
	struct rdns_plugin *plugin;

	if (!resolver->async_binded) {
		return;
	}

	plugin = calloc (1, sizeof (struct rdns_plugin));
	if (plugin != NULL) {
		plugin->data = ctx;
		plugin->type = RDNS_PLUGIN_CURVE;
		plugin->cb.curve_plugin.send_cb = rdns_curve_send;
		plugin->cb.curve_plugin.recv_cb = rdns_curve_recv;
		plugin->cb.curve_plugin.finish_cb = rdns_curve_finish_request;
		plugin->dtor = rdns_curve_dtor;
		ctx->cur_key = rdns_curve_client_key_new (ctx);
		REF_INIT_RETAIN (ctx->cur_key, rdns_curve_client_key_free);

		if (ctx->key_refresh_interval > 0) {
			ctx->key_refresh_event = resolver->async->add_periodic (
					resolver->async->data, ctx->key_refresh_interval,
					rdns_curve_refresh_key_callback, ctx);
		}
		ctx->resolver = resolver;
		rdns_resolver_register_plugin (resolver, plugin);
	}
}

ssize_t
rdns_curve_send (struct rdns_request *req, void *plugin_data,
				 struct sockaddr *saddr, socklen_t slen)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;
	struct rdns_curve_entry *entry;
	struct iovec iov[4];
	unsigned char *m;
	static const char qmagic[] = "Q6fnvWj8";
	struct rdns_curve_request *creq;
	struct rdns_curve_nm_entry *nm;
	ssize_t ret, boxed_len;

	/* Check for key */
	HASH_FIND_STR (ctx->entries, req->io->srv->name, entry);
	if (entry != NULL) {
		nm = rdns_curve_find_nm (ctx->cur_key, entry);
		creq = malloc (sizeof (struct rdns_curve_request));
		if (creq == NULL) {
			return -1;
		}

		boxed_len = req->pos + crypto_box_ZEROBYTES;
		m = malloc (boxed_len);
		if (m == NULL) {
			free(creq);
			return -1;
		}

		/* Ottery is faster than sodium native PRG that uses /dev/random only */
		memcpy (creq->nonce, &ctx->cur_key->counter, sizeof (uint64_t));
		ottery_rand_bytes (creq->nonce + sizeof (uint64_t), 12 - sizeof (uint64_t));
		rspamd_explicit_memzero (creq->nonce + 12,
				rspamd_cryptobox_nonce_bytes (RSPAMD_CRYPTOBOX_MODE_25519) - 12);

		rspamd_explicit_memzero (m, crypto_box_ZEROBYTES);
		memcpy (m + crypto_box_ZEROBYTES, req->packet, req->pos);

		rspamd_cryptobox_encrypt_nm_inplace (m + crypto_box_ZEROBYTES,
				boxed_len,
				creq->nonce,
				nm->k,
				m,
				RSPAMD_CRYPTOBOX_MODE_25519);

		creq->key = ctx->cur_key;
		REF_RETAIN (ctx->cur_key);
		creq->entry = entry;
		creq->req = req;
		creq->nm = nm;
		HASH_ADD_KEYPTR (hh, ctx->requests, creq->nonce, 12, creq);
		req->curve_plugin_data = creq;

		ctx->cur_key->counter ++;
		ctx->cur_key->uses ++;

		/* Now form a dnscurve packet */
		iov[0].iov_base = (void *)qmagic;
		iov[0].iov_len = sizeof (qmagic) - 1;
		iov[1].iov_base = ctx->cur_key->pk;
		iov[1].iov_len = sizeof (ctx->cur_key->pk);
		iov[2].iov_base = creq->nonce;
		iov[2].iov_len = 12;
		iov[3].iov_base = m + crypto_box_BOXZEROBYTES;
		iov[3].iov_len = boxed_len - crypto_box_BOXZEROBYTES;

		struct msghdr msg;

		memset (&msg, 0, sizeof (msg));
		msg.msg_namelen = slen;
		msg.msg_name = saddr;
		msg.msg_iov = iov;
		msg.msg_iovlen = sizeof (iov) / sizeof (iov[0]);
		ret = sendmsg (req->io->sock, &msg, 0);
		rspamd_explicit_memzero (m, boxed_len);
		free (m);
	}
	else {
		ret = sendto (req->io->sock, req->packet, req->pos, 0, saddr, slen);
		req->curve_plugin_data = NULL;
	}

	return ret;
}

ssize_t
rdns_curve_recv (struct rdns_io_channel *ioc, void *buf, size_t len, void *plugin_data,
		struct rdns_request **req_out, struct sockaddr *saddr, socklen_t slen)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;
	ssize_t ret, boxlen;
	static const char rmagic[] = "R6fnvWJ8";
	unsigned char *p, *box;
	unsigned char enonce[24];
	struct rdns_curve_request *creq;
	struct rdns_resolver *resolver;

	resolver = ctx->resolver;
	ret = recv (ioc->sock, buf, len, 0);

	if (ret <= 0 || ret < 64) {
		/* Definitely not a DNSCurve packet */
		return ret;
	}

	if (memcmp (buf, rmagic, sizeof (rmagic) - 1) == 0) {
		/* Likely DNSCurve packet */
		p = ((unsigned char *)buf) + 8;
		HASH_FIND (hh, ctx->requests, p, 12, creq);
		if (creq == NULL) {
			rdns_info ("unable to find nonce in the internal hash");
			return ret;
		}

		memcpy (enonce, p, rspamd_cryptobox_nonce_bytes (RSPAMD_CRYPTOBOX_MODE_25519));
		p += rspamd_cryptobox_nonce_bytes (RSPAMD_CRYPTOBOX_MODE_25519);
		boxlen = ret - rspamd_cryptobox_nonce_bytes (RSPAMD_CRYPTOBOX_MODE_25519) +
				crypto_box_BOXZEROBYTES -
				sizeof (rmagic) + 1;
		if (boxlen < 0) {
			return ret;
		}

		box = malloc (boxlen);
		rspamd_explicit_memzero (box, crypto_box_BOXZEROBYTES);
		memcpy (box + crypto_box_BOXZEROBYTES, p,
				boxlen - crypto_box_BOXZEROBYTES);

		if (!rspamd_cryptobox_decrypt_nm_inplace (
				box + rspamd_cryptobox_mac_bytes (RSPAMD_CRYPTOBOX_MODE_25519),
				boxlen - rspamd_cryptobox_mac_bytes (RSPAMD_CRYPTOBOX_MODE_25519),
				enonce, creq->nm->k, box, RSPAMD_CRYPTOBOX_MODE_25519)) {
			memcpy (buf, box + crypto_box_ZEROBYTES,
					boxlen - crypto_box_ZEROBYTES);
			ret = boxlen - crypto_box_ZEROBYTES;
			*req_out = creq->req;
		}
		else {
			rdns_info ("unable open cryptobox of size %d", (int)boxlen);
		}

		free (box);
	}

	return ret;
}

void
rdns_curve_finish_request (struct rdns_request *req, void *plugin_data)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;
	struct rdns_curve_request *creq = req->curve_plugin_data;

	if (creq != NULL) {
		REF_RELEASE (creq->key);
		HASH_DELETE (hh, ctx->requests, creq);
	}
}

void
rdns_curve_dtor (struct rdns_resolver *resolver, void *plugin_data)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;

	if (ctx->key_refresh_event != NULL) {
		resolver->async->del_periodic (resolver->async->data,
				ctx->key_refresh_event);
	}
	REF_RELEASE (ctx->cur_key);
}
#else

/* Fake functions */
struct rdns_curve_ctx* rdns_curve_ctx_new (double rekey_interval)
{
	return NULL;
}
void rdns_curve_ctx_add_key (struct rdns_curve_ctx *ctx,
		const char *name, const unsigned char *pubkey)
{

}
void rdns_curve_ctx_destroy (struct rdns_curve_ctx *ctx)
{

}
void rdns_curve_register_plugin (struct rdns_resolver *resolver,
		struct rdns_curve_ctx *ctx)
{

}

unsigned char *
rdns_curve_key_from_hex (const char *hex)
{
	return NULL;
}
#endif
