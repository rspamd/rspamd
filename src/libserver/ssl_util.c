/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"
#include "libutil/util.h"
#include "libutil/hash.h"
#include "libserver/logger.h"
#include "libserver/cfg_file.h"
#include "ssl_util.h"
#include "unix-std.h"
#include "cryptobox.h"
#include "contrib/libottery/ottery.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

enum rspamd_ssl_state {
	ssl_conn_reset = 0,
	ssl_conn_init,
	ssl_conn_connected,
	ssl_next_read,
	ssl_next_write,
	ssl_next_shutdown,
};

enum rspamd_ssl_shutdown {
	ssl_shut_default = 0,
	ssl_shut_unclean,
};

struct rspamd_ssl_ctx {
	SSL_CTX *s;
	rspamd_lru_hash_t *sessions;
};

struct rspamd_ssl_connection {
	gint fd;
	enum rspamd_ssl_state state;
	enum rspamd_ssl_shutdown shut;
	gboolean verify_peer;
	SSL *ssl;
	struct rspamd_ssl_ctx *ssl_ctx;
	gchar *hostname;
	struct rspamd_io_ev *ev;
	struct rspamd_io_ev *shut_ev;
	struct ev_loop *event_loop;
	rspamd_ssl_handler_t handler;
	rspamd_ssl_error_handler_t err_handler;
	gpointer handler_data;
	gchar log_tag[8];
};

#define msg_debug_ssl(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_ssl_log_id, "ssl", conn->log_tag, \
        G_STRFUNC, \
        __VA_ARGS__)

static void rspamd_ssl_event_handler (gint fd, short what, gpointer ud);

INIT_LOG_MODULE(ssl)

static GQuark
rspamd_ssl_quark (void)
{
	return g_quark_from_static_string ("rspamd-ssl");
}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
#ifndef X509_get_notBefore
#define X509_get_notBefore(x) X509_get0_notBefore(x)
#endif
#ifndef X509_get_notAfter
#define X509_get_notAfter(x) X509_get0_notAfter(x)
#endif
#ifndef ASN1_STRING_data
#define ASN1_STRING_data(x) ASN1_STRING_get0_data(x)
#endif
#endif

/* $OpenBSD: tls_verify.c,v 1.14 2015/09/29 10:17:04 deraadt Exp $ */
/*
 * Copyright (c) 2014 Jeremie Courreges-Anglas <jca@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

static gboolean
rspamd_tls_match_name (const char *cert_name, const char *name)
{
	const char *cert_domain, *domain, *next_dot;

	if (g_ascii_strcasecmp (cert_name, name) == 0) {
		return TRUE;
	}

	/* Wildcard match? */
	if (cert_name[0] == '*') {
		/*
		 * Valid wildcards:
		 * - "*.domain.tld"
		 * - "*.sub.domain.tld"
		 * - etc.
		 * Reject "*.tld".
		 * No attempt to prevent the use of eg. "*.co.uk".
		 */
		cert_domain = &cert_name[1];
		/* Disallow "*"  */
		if (cert_domain[0] == '\0') {
			return FALSE;
		}

		/* Disallow "*foo" */
		if (cert_domain[0] != '.') {
			return FALSE;
		}
		/* Disallow "*.." */
		if (cert_domain[1] == '.') {
			return FALSE;
		}
		next_dot = strchr (&cert_domain[1], '.');
		/* Disallow "*.bar" */
		if (next_dot == NULL) {
			return FALSE;
		}
		/* Disallow "*.bar.." */
		if (next_dot[1] == '.') {
			return FALSE;
		}

		domain = strchr (name, '.');

		/* No wildcard match against a name with no host part. */
		if (name[0] == '.') {
			return FALSE;
		}
		/* No wildcard match against a name with no domain part. */
		if (domain == NULL || strlen (domain) == 1) {
			return FALSE;
		}

		if (g_ascii_strcasecmp (cert_domain, domain) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

/* See RFC 5280 section 4.2.1.6 for SubjectAltName details. */
static gboolean
rspamd_tls_check_subject_altname (X509 *cert, const char *name)
{
	STACK_OF(GENERAL_NAME) *altname_stack = NULL;
	int addrlen, type;
	int count, i;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	} addrbuf;
	gboolean ret = FALSE;

	altname_stack = X509_get_ext_d2i (cert, NID_subject_alt_name, NULL, NULL);

	if (altname_stack == NULL) {
		return FALSE;
	}

	if (inet_pton (AF_INET, name, &addrbuf) == 1) {
		type = GEN_IPADD;
		addrlen = 4;
	}
	else if (inet_pton (AF_INET6, name, &addrbuf) == 1) {
		type = GEN_IPADD;
		addrlen = 16;
	}
	else {
		type = GEN_DNS;
		addrlen = 0;
	}

	count = sk_GENERAL_NAME_num (altname_stack);

	for (i = 0; i < count; i++) {
		GENERAL_NAME *altname;

		altname = sk_GENERAL_NAME_value (altname_stack, i);

		if (altname->type != type) {
			continue;
		}

		if (type == GEN_DNS) {
			const char *data;
			int format, len;

			format = ASN1_STRING_type (altname->d.dNSName);

			if (format == V_ASN1_IA5STRING) {
				data = (const char *)ASN1_STRING_data (altname->d.dNSName);
				len = ASN1_STRING_length (altname->d.dNSName);

				if (len < 0 || len != (gint)strlen (data)) {
					ret = FALSE;
					break;
				}

				/*
				 * Per RFC 5280 section 4.2.1.6:
				 * " " is a legal domain name, but that
				 * dNSName must be rejected.
				 */
				if (strcmp (data, " ") == 0) {
					ret = FALSE;
					break;
				}

				if (rspamd_tls_match_name (data, name)) {
					ret = TRUE;
					break;
				}
			}
		}
		else if (type == GEN_IPADD) {
			const char *data;
			int datalen;

			datalen = ASN1_STRING_length (altname->d.iPAddress);
			data = (const char *)ASN1_STRING_data (altname->d.iPAddress);

			if (datalen < 0) {
				ret = FALSE;
				break;
			}

			/*
			 * Per RFC 5280 section 4.2.1.6:
			 * IPv4 must use 4 octets and IPv6 must use 16 octets.
			 */
			if (datalen == addrlen && memcmp (data, &addrbuf, addrlen) == 0) {
				ret = TRUE;
				break;
			}
		}
	}

	sk_GENERAL_NAME_pop_free (altname_stack, GENERAL_NAME_free);
	return ret;
}

static gboolean
rspamd_tls_check_common_name (X509 *cert, const char *name)
{
	X509_NAME *subject_name;
	char *common_name = NULL;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	} addrbuf;
	int common_name_len;
	gboolean ret = FALSE;

	subject_name = X509_get_subject_name (cert);
	if (subject_name == NULL) {
		goto out;
	}

	common_name_len = X509_NAME_get_text_by_NID (subject_name, NID_commonName, NULL, 0);

	if (common_name_len < 0) {
		goto out;
	}

	common_name = g_malloc0 (common_name_len + 1);
	X509_NAME_get_text_by_NID (subject_name, NID_commonName, common_name,
			common_name_len + 1);

	/* NUL bytes in CN? */
	if (common_name_len != (gint)strlen (common_name)) {
		goto out;
	}

	if (inet_pton (AF_INET, name, &addrbuf) == 1
			|| inet_pton (AF_INET6, name, &addrbuf) == 1) {
		/*
		 * We don't want to attempt wildcard matching against IP
		 * addresses, so perform a simple comparison here.
		 */
		if (strcmp (common_name, name) == 0) {
			ret = TRUE;
		}
		else {
			ret = FALSE;
		}

		goto out;
	}

	if (rspamd_tls_match_name (common_name, name)) {
		ret = TRUE;
	}

out:
	g_free (common_name);

	return ret;
}

static gboolean
rspamd_tls_check_name (X509 *cert, const char *name)
{
	gboolean ret;

	ret = rspamd_tls_check_subject_altname (cert, name);
	if (ret) {
		return ret;
	}

	return rspamd_tls_check_common_name (cert, name);
}

static gboolean
rspamd_ssl_peer_verify (struct rspamd_ssl_connection *c)
{
	X509 *server_cert;
	glong ver_err;
	GError *err = NULL;

	ver_err = SSL_get_verify_result (c->ssl);

	if (ver_err != X509_V_OK) {
		g_set_error (&err, rspamd_ssl_quark (), 400, "certificate validation "
				"failed: %s", X509_verify_cert_error_string (ver_err));
		c->err_handler (c->handler_data, err);
		g_error_free (err);

		return FALSE;
	}

	/* Get server's certificate */
	server_cert =  SSL_get_peer_certificate (c->ssl);
	if (server_cert == NULL) {
		g_set_error (&err, rspamd_ssl_quark (), 401, "peer certificate is absent");
		c->err_handler (c->handler_data, err);
		g_error_free (err);

		return FALSE;
	}

	if (c->hostname) {
		if (!rspamd_tls_check_name (server_cert, c->hostname)) {
			X509_free (server_cert);
			g_set_error (&err, rspamd_ssl_quark (), 403, "peer certificate fails "
					"hostname verification for %s", c->hostname);
			c->err_handler (c->handler_data, err);
			g_error_free (err);

			return FALSE;
		}
	}

	X509_free (server_cert);

	return TRUE;
}

static void
rspamd_tls_set_error (gint retcode, const gchar *stage, GError **err)
{
	GString *reason;
	gchar buf[120];
	gint err_code = 0;

	reason = g_string_sized_new (sizeof (buf));

	if (retcode == SSL_ERROR_SYSCALL) {
		rspamd_printf_gstring (reason, "syscall fail: %s", strerror (errno));
		err_code = 500;
	}
	else {
		while ((err_code = ERR_get_error()) != 0) {
			ERR_error_string (err_code, buf);
			rspamd_printf_gstring (reason, "ssl error: %s,", buf);
		}

		err_code = 400;

		if (reason->len > 0 && reason->str[reason->len - 1] == ',') {
			reason->str[reason->len - 1] = '\0';
			reason->len --;
		}
	}

	g_set_error (err, rspamd_ssl_quark (), err_code,
			"ssl %s error: %s", stage, reason->str);
	g_string_free (reason, TRUE);
}

static void
rspamd_ssl_connection_dtor (struct rspamd_ssl_connection *conn)
{
	msg_debug_ssl ("closing SSL connection %p; %d sessions in the cache",
			conn->ssl, rspamd_lru_hash_size (conn->ssl_ctx->sessions));
	SSL_free (conn->ssl);

	if (conn->hostname) {
		g_free (conn->hostname);
	}

	/*
	 * Try to workaround for the race between timeout and ssl error
	 */
	if (conn->shut_ev != conn->ev && ev_can_stop (&conn->ev->tm)) {
		rspamd_ev_watcher_stop (conn->event_loop, conn->ev);
	}

	if (conn->shut_ev) {
		rspamd_ev_watcher_stop (conn->event_loop, conn->shut_ev);
		g_free (conn->shut_ev);
	}

	close (conn->fd);
	g_free (conn);
}

static void
rspamd_ssl_shutdown (struct rspamd_ssl_connection *conn)
{
	gint ret = 0, nret, retries;
	static const gint max_retries = 5;

	/*
	 * Fucking openssl...
	 * From the manual, 0 means: "The shutdown is not yet finished.
	 * Call SSL_shutdown() for a second time,
	 * if a bidirectional shutdown shall be performed.
	 * The output of SSL_get_error(3) may be misleading,
	 * as an erroneous SSL_ERROR_SYSCALL may be flagged
	 * even though no error occurred."
	 *
	 * What is `second`, what if `second` also returns 0?
	 * What a retarded behaviour!
	 */
	for (retries = 0; retries < max_retries; retries ++) {
		ret = SSL_shutdown (conn->ssl);

		if (ret != 0) {
			break;
		}
	}

	if (ret == 1) {
		/* All done */
		msg_debug_ssl ("ssl shutdown: all done");
		rspamd_ssl_connection_dtor (conn);
	}
	else if (ret < 0) {
		short what;

		nret = SSL_get_error (conn->ssl, ret);
		conn->state = ssl_next_shutdown;

		if (nret == SSL_ERROR_WANT_READ) {
			msg_debug_ssl ("ssl shutdown: need read");
			what = EV_READ;
		}
		else if (nret == SSL_ERROR_WANT_WRITE) {
			msg_debug_ssl ("ssl shutdown: need write");
			what = EV_WRITE;
		}
		else {
			/* Cannot do anything else, fatal error */
			GError *err = NULL;

			rspamd_tls_set_error (nret, "final shutdown", &err);
			msg_debug_ssl ("ssl shutdown: fatal error: %e; retries=%d; ret=%d",
					err, retries, ret);
			g_error_free (err);
			rspamd_ssl_connection_dtor (conn);

			return;
		}

		/* As we own fd, we can try to perform shutdown one more time */
		/* BUGON: but we DO NOT own conn->ev, and it's a big issue */
		static const ev_tstamp shutdown_time = 5.0;

		if (conn->shut_ev == NULL) {
			rspamd_ev_watcher_stop (conn->event_loop, conn->ev);
			conn->shut_ev = g_malloc0 (sizeof (*conn->shut_ev));
			rspamd_ev_watcher_init (conn->shut_ev, conn->fd, what,
					rspamd_ssl_event_handler, conn);
			rspamd_ev_watcher_start (conn->event_loop, conn->shut_ev, shutdown_time);
			/* XXX: can it be done safely ? */
			conn->ev = conn->shut_ev;
		}
		else {
			rspamd_ev_watcher_reschedule (conn->event_loop, conn->shut_ev, what);
		}

		conn->state = ssl_next_shutdown;
	}
	else if (ret == 0) {
		/* What can we do here?? */
		msg_debug_ssl ("ssl shutdown: openssl failed to initiate shutdown after "
				 "%d attempts!", max_retries);
		rspamd_ssl_connection_dtor (conn);
	}
}

static void
rspamd_ssl_event_handler (gint fd, short what, gpointer ud)
{
	struct rspamd_ssl_connection *conn = ud;
	gint ret;
	GError *err = NULL;

	if (what == EV_TIMER) {
		if (conn->state == ssl_next_shutdown) {
			/* No way to restore, just terminate */
			rspamd_ssl_connection_dtor (conn);
		}
		else {
			conn->shut = ssl_shut_unclean;
			rspamd_ev_watcher_stop (conn->event_loop, conn->ev);
			g_set_error (&err, rspamd_ssl_quark (), 408,
					"ssl connection timed out");
			conn->err_handler (conn->handler_data, err);
			g_error_free (err);
		}

		return;
	}

	msg_debug_ssl ("ssl event; what=%d; c->state=%d", (int)what,
			(int)conn->state);

	switch (conn->state) {
	case ssl_conn_init:
		/* Continue connection */
		ret = SSL_connect (conn->ssl);

		if (ret == 1) {
			rspamd_ev_watcher_stop (conn->event_loop, conn->ev);
			/* Verify certificate */
			if ((!conn->verify_peer) || rspamd_ssl_peer_verify (conn)) {
				msg_debug_ssl ("ssl connect: connected");
				conn->state = ssl_conn_connected;
				conn->handler (fd, EV_WRITE, conn->handler_data);
			}
			else {
				return;
			}
		}
		else {
			ret = SSL_get_error (conn->ssl, ret);

			if (ret == SSL_ERROR_WANT_READ) {
				msg_debug_ssl ("ssl connect: need read");
				what = EV_READ;
			}
			else if (ret == SSL_ERROR_WANT_WRITE) {
				msg_debug_ssl ("ssl connect: need write");
				what = EV_WRITE;
			}
			else {
				rspamd_ev_watcher_stop (conn->event_loop, conn->ev);
				rspamd_tls_set_error (ret, "connect", &err);
				conn->err_handler (conn->handler_data, err);
				g_error_free (err);
				return;
			}

			rspamd_ev_watcher_reschedule (conn->event_loop, conn->ev, what);

		}
		break;
	case ssl_next_read:
		rspamd_ev_watcher_reschedule (conn->event_loop, conn->ev, EV_READ);
		conn->state = ssl_conn_connected;
		conn->handler (fd, EV_READ, conn->handler_data);
		break;
	case ssl_next_write:
		rspamd_ev_watcher_reschedule (conn->event_loop, conn->ev, EV_WRITE);
		conn->state = ssl_conn_connected;
		conn->handler (fd, EV_WRITE, conn->handler_data);
		break;
	case ssl_conn_connected:
		rspamd_ev_watcher_reschedule (conn->event_loop, conn->ev, what);
		conn->state = ssl_conn_connected;
		conn->handler (fd, what, conn->handler_data);
		break;
	case ssl_next_shutdown:
		rspamd_ssl_shutdown (conn);
		break;
	default:
		rspamd_ev_watcher_stop (conn->event_loop, conn->ev);
		g_set_error (&err, rspamd_ssl_quark (), 500,
				"ssl bad state error: %d", conn->state);
		conn->err_handler (conn->handler_data, err);
		g_error_free (err);
		break;
	}
}

struct rspamd_ssl_connection *
rspamd_ssl_connection_new (gpointer ssl_ctx, struct ev_loop *ev_base,
		gboolean verify_peer, const gchar *log_tag)
{
	struct rspamd_ssl_connection *conn;
	struct rspamd_ssl_ctx *ctx = (struct rspamd_ssl_ctx *)ssl_ctx;

	g_assert (ssl_ctx != NULL);
	conn = g_malloc0 (sizeof (*conn));
	conn->ssl_ctx = ctx;
	conn->event_loop = ev_base;
	conn->verify_peer = verify_peer;

	if (log_tag) {
		rspamd_strlcpy (conn->log_tag, log_tag, sizeof (conn->log_tag));
	}
	else {
		rspamd_random_hex (conn->log_tag, sizeof (log_tag) - 1);
		conn->log_tag[sizeof (log_tag) - 1] = '\0';
	}

	return conn;
}


gboolean
rspamd_ssl_connect_fd (struct rspamd_ssl_connection *conn, gint fd,
		const gchar *hostname, struct rspamd_io_ev *ev, ev_tstamp timeout,
		rspamd_ssl_handler_t handler, rspamd_ssl_error_handler_t err_handler,
		gpointer handler_data)
{
	gint ret;
	SSL_SESSION *session = NULL;

	g_assert (conn != NULL);

	conn->ssl = SSL_new (conn->ssl_ctx->s);

	if (hostname) {
		session = rspamd_lru_hash_lookup (conn->ssl_ctx->sessions, hostname,
				ev_now (conn->event_loop));

	}

	if (session) {
		SSL_set_session (conn->ssl, session);
	}

	SSL_set_app_data (conn->ssl, conn);
	msg_debug_ssl ("new ssl connection %p; session reused=%s",
			conn->ssl, SSL_session_reused (conn->ssl) ? "true" : "false");

	if (conn->state != ssl_conn_reset) {
		return FALSE;
	}

	/* We dup fd to allow graceful closing */
	gint nfd = dup (fd);

	if (nfd == -1) {
		return FALSE;
	}

	conn->fd = nfd;
	conn->ev = ev;
	conn->handler = handler;
	conn->err_handler = err_handler;
	conn->handler_data = handler_data;

	if (SSL_set_fd (conn->ssl, conn->fd) != 1) {
		close (conn->fd);

		return FALSE;
	}

	if (hostname) {
		conn->hostname = g_strdup (hostname);
#ifdef HAVE_SSL_TLSEXT_HOSTNAME
		SSL_set_tlsext_host_name (conn->ssl, conn->hostname);
#endif
	}

	conn->state = ssl_conn_init;

	ret = SSL_connect (conn->ssl);

	if (ret == 1) {
		conn->state = ssl_conn_connected;

		msg_debug_ssl ("connected, start write event");
		rspamd_ev_watcher_stop (conn->event_loop, ev);
		rspamd_ev_watcher_init (ev, nfd, EV_WRITE, rspamd_ssl_event_handler, conn);
		rspamd_ev_watcher_start (conn->event_loop, ev, timeout);
	}
	else {
		ret = SSL_get_error (conn->ssl, ret);

		if (ret == SSL_ERROR_WANT_READ) {
			msg_debug_ssl ("not connected, want read");
		}
		else if (ret == SSL_ERROR_WANT_WRITE) {
			msg_debug_ssl ("not connected, want write");
		}
		else {
			GError *err = NULL;

			conn->shut = ssl_shut_unclean;
			rspamd_tls_set_error (ret, "initial connect", &err);
			msg_debug_ssl ("not connected, fatal error %e", err);
			g_error_free (err);


			return FALSE;
		}

		rspamd_ev_watcher_stop (conn->event_loop, ev);
		rspamd_ev_watcher_init (ev, nfd, EV_WRITE|EV_READ,
				rspamd_ssl_event_handler, conn);
		rspamd_ev_watcher_start (conn->event_loop, ev, timeout);
	}

	return TRUE;
}

gssize
rspamd_ssl_read (struct rspamd_ssl_connection *conn, gpointer buf,
		gsize buflen)
{
	gint ret;
	short what;
	GError *err = NULL;

	g_assert (conn != NULL);

	if (conn->state != ssl_conn_connected && conn->state != ssl_next_read) {
		errno = EINVAL;
		g_set_error (&err, rspamd_ssl_quark (), 400,
				"ssl state error: cannot read data");
		conn->shut = ssl_shut_unclean;
		conn->err_handler (conn->handler_data, err);
		g_error_free (err);

		return -1;
	}

	ret = SSL_read (conn->ssl, buf, buflen);
	msg_debug_ssl ("ssl read: %d", ret);

	if (ret > 0) {
		conn->state = ssl_conn_connected;
		return ret;
	}
	else if (ret == 0) {
		ret = SSL_get_error (conn->ssl, ret);

		if (ret == SSL_ERROR_ZERO_RETURN || ret == SSL_ERROR_SYSCALL) {
			conn->state = ssl_conn_reset;
			return 0;
		}
		else {
			conn->shut = ssl_shut_unclean;
			rspamd_tls_set_error (ret, "read", &err);
			conn->err_handler (conn->handler_data, err);
			g_error_free (err);
			errno = EINVAL;

			return -1;
		}
	}
	else {
		ret = SSL_get_error (conn->ssl, ret);
		conn->state = ssl_next_read;
		what = 0;

		if (ret == SSL_ERROR_WANT_READ) {
			msg_debug_ssl ("ssl read: need read");
			what |= EV_READ;
		}
		else if (ret == SSL_ERROR_WANT_WRITE) {
			msg_debug_ssl ("ssl read: need write");
			what |= EV_WRITE;
		}
		else {
			conn->shut = ssl_shut_unclean;
			rspamd_tls_set_error (ret, "read", &err);
			conn->err_handler (conn->handler_data, err);
			g_error_free (err);
			errno = EINVAL;

			return -1;
		}

		rspamd_ev_watcher_reschedule (conn->event_loop, conn->ev, what);
		errno = EAGAIN;
	}

	return -1;
}

gssize
rspamd_ssl_write (struct rspamd_ssl_connection *conn, gconstpointer buf,
		gsize buflen)
{
	gint ret;
	short what;
	GError *err = NULL;

	g_assert (conn != NULL);

	if (conn->state != ssl_conn_connected && conn->state != ssl_next_write) {
		errno = EINVAL;
		return -1;
	}

	ret = SSL_write (conn->ssl, buf, buflen);
	msg_debug_ssl ("ssl write: ret=%d, buflen=%z", ret, buflen);

	if (ret > 0) {
		conn->state = ssl_conn_connected;
		return ret;
	}
	else if (ret == 0) {
		ret = SSL_get_error (conn->ssl, ret);

		if (ret == SSL_ERROR_ZERO_RETURN) {
			rspamd_tls_set_error (ret, "write", &err);
			conn->err_handler (conn->handler_data, err);
			g_error_free (err);
			errno = ECONNRESET;
			conn->state = ssl_conn_reset;

			return -1;
		}
		else {
			conn->shut = ssl_shut_unclean;
			rspamd_tls_set_error (ret, "write", &err);
			conn->err_handler (conn->handler_data, err);
			g_error_free (err);
			errno = EINVAL;

			return -1;
		}
	}
	else {
		ret = SSL_get_error (conn->ssl, ret);
		conn->state = ssl_next_write;

		if (ret == SSL_ERROR_WANT_READ) {
			msg_debug_ssl ("ssl write: need read");
			what = EV_READ;
		}
		else if (ret == SSL_ERROR_WANT_WRITE) {
			msg_debug_ssl ("ssl write: need write");
			what = EV_WRITE;
		}
		else {
			conn->shut = ssl_shut_unclean;
			rspamd_tls_set_error (ret, "write", &err);
			conn->err_handler (conn->handler_data, err);
			g_error_free (err);
			errno = EINVAL;

			return -1;
		}

		rspamd_ev_watcher_reschedule (conn->event_loop, conn->ev, what);
		errno = EAGAIN;
	}

	return -1;
}

gssize
rspamd_ssl_writev (struct rspamd_ssl_connection *conn, struct iovec *iov,
		gsize iovlen)
{
	/*
	 * Static is needed to avoid issue:
	 * https://github.com/openssl/openssl/issues/6865
	 */
	static guchar ssl_buf[16384];
	guchar *p;
	struct iovec *cur;
	gsize i, remain;

	remain = sizeof (ssl_buf);
	p = ssl_buf;

	for (i = 0; i < iovlen; i ++) {
		cur = &iov[i];

		if (cur->iov_len > 0) {
			if (remain >= cur->iov_len) {
				memcpy (p, cur->iov_base, cur->iov_len);
				p += cur->iov_len;
				remain -= cur->iov_len;
			}
			else {
				memcpy (p, cur->iov_base, remain);
				p += remain;
				remain = 0;
				break;
			}
		}
	}

	return rspamd_ssl_write (conn, ssl_buf, p - ssl_buf);
}

/**
 * Removes connection data
 * @param conn
 */
void
rspamd_ssl_connection_free (struct rspamd_ssl_connection *conn)
{
	if (conn) {
		if (conn->shut == ssl_shut_unclean) {
			/* Ignore return result and close socket */
			msg_debug_ssl ("unclean shutdown");
			SSL_set_quiet_shutdown (conn->ssl, 1);
			(void)SSL_shutdown (conn->ssl);
			rspamd_ssl_connection_dtor (conn);
		}
		else {
			msg_debug_ssl ("normal shutdown");
			rspamd_ssl_shutdown (conn);
		}
	}
}

static int
rspamd_ssl_new_client_session (SSL *ssl, SSL_SESSION *sess)
{
	struct rspamd_ssl_connection *conn;

	conn = SSL_get_app_data (ssl);

	if (conn->hostname) {
		rspamd_lru_hash_insert (conn->ssl_ctx->sessions,
				g_strdup (conn->hostname), SSL_get1_session (ssl),
				ev_now (conn->event_loop), SSL_CTX_get_timeout (conn->ssl_ctx->s));
		msg_debug_ssl ("saved new session for %s: %p", conn->hostname, conn);
	}

	return 0;
}

static struct rspamd_ssl_ctx *
rspamd_init_ssl_ctx_common (void)
{
	struct rspamd_ssl_ctx *ret;
	SSL_CTX *ssl_ctx;
	gint ssl_options;
	static const guint client_cache_size = 1024;

	rspamd_openssl_maybe_init ();

	ret = g_malloc0 (sizeof (*ret));
	ssl_options = SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3;
	ssl_ctx = SSL_CTX_new (SSLv23_method ());

#ifdef SSL_OP_NO_COMPRESSION
	ssl_options |= SSL_OP_NO_COMPRESSION;
#elif OPENSSL_VERSION_NUMBER >= 0x00908000L
	sk_SSL_COMP_zero (SSL_COMP_get_compression_methods ());
#endif

	SSL_CTX_set_options (ssl_ctx, ssl_options);

#ifdef TLS1_3_VERSION
	SSL_CTX_set_min_proto_version (ssl_ctx, 0);
	SSL_CTX_set_max_proto_version (ssl_ctx, TLS1_3_VERSION);
#endif

#ifdef SSL_SESS_CACHE_CLIENT
	SSL_CTX_set_session_cache_mode (ssl_ctx, SSL_SESS_CACHE_CLIENT
											 | SSL_SESS_CACHE_NO_INTERNAL_STORE);
#endif

	ret->s = ssl_ctx;
	ret->sessions = rspamd_lru_hash_new_full (client_cache_size,
			g_free, (GDestroyNotify)SSL_SESSION_free, rspamd_str_hash,
			rspamd_str_equal);
	SSL_CTX_set_app_data (ssl_ctx, ret);
	SSL_CTX_sess_set_new_cb (ssl_ctx, rspamd_ssl_new_client_session);

	return ret;
}

gpointer
rspamd_init_ssl_ctx (void)
{
	struct rspamd_ssl_ctx *ssl_ctx = rspamd_init_ssl_ctx_common ();

	SSL_CTX_set_verify (ssl_ctx->s, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth (ssl_ctx->s, 4);

	return ssl_ctx;
}

gpointer rspamd_init_ssl_ctx_noverify (void)
{
	struct rspamd_ssl_ctx *ssl_ctx_noverify = rspamd_init_ssl_ctx_common ();

	SSL_CTX_set_verify (ssl_ctx_noverify->s, SSL_VERIFY_NONE, NULL);

	return ssl_ctx_noverify;
}

void
rspamd_openssl_maybe_init (void)
{
	static gboolean openssl_initialized = FALSE;

	if (!openssl_initialized) {
		ERR_load_crypto_strings ();
		SSL_load_error_strings ();

		OpenSSL_add_all_algorithms ();
		OpenSSL_add_all_digests ();
		OpenSSL_add_all_ciphers ();

#if OPENSSL_VERSION_NUMBER >= 0x1000104fL && !defined(LIBRESSL_VERSION_NUMBER)
		ENGINE_load_builtin_engines ();
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
		SSL_library_init ();
#else
		OPENSSL_init_ssl (0, NULL);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
		OPENSSL_config (NULL);
#endif
		if (RAND_status () == 0) {
			guchar seed[128];

			/* Try to use ottery to seed rand */
			ottery_rand_bytes (seed, sizeof (seed));
			RAND_seed (seed, sizeof (seed));
			rspamd_explicit_memzero (seed, sizeof (seed));
		}

		openssl_initialized = TRUE;
	}
}

void
rspamd_ssl_ctx_config (struct rspamd_config *cfg, gpointer ssl_ctx)
{
	struct rspamd_ssl_ctx *ctx = (struct rspamd_ssl_ctx *)ssl_ctx;
	static const char default_secure_ciphers[] = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";

	if (cfg->ssl_ca_path) {
		if (SSL_CTX_load_verify_locations (ctx->s, cfg->ssl_ca_path,
				NULL) != 1) {
			msg_err_config ("cannot load CA certs from %s: %s",
					cfg->ssl_ca_path,
					ERR_error_string (ERR_get_error (), NULL));
		}
	}
	else {
		msg_debug_config ("ssl_ca_path is not set, using default CA path");
		SSL_CTX_set_default_verify_paths (ctx->s);
	}

	if (cfg->ssl_ciphers) {
		if (SSL_CTX_set_cipher_list (ctx->s, cfg->ssl_ciphers) != 1) {
			msg_err_config (
					"cannot set ciphers set to %s: %s; fallback to %s",
					cfg->ssl_ciphers,
					ERR_error_string (ERR_get_error (), NULL),
					default_secure_ciphers);
			/* Default settings */
			SSL_CTX_set_cipher_list (ctx->s, default_secure_ciphers);
		}
	}
}

void
rspamd_ssl_ctx_free (gpointer ssl_ctx)
{
	struct rspamd_ssl_ctx *ctx = (struct rspamd_ssl_ctx *)ssl_ctx;

	rspamd_lru_hash_destroy (ctx->sessions);
	SSL_CTX_free (ctx->s);
	g_free (ssl_ctx);
}