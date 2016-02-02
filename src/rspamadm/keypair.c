/*
 * Copyright (c) 2015, Vsevolod Stakhov
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

#include "config.h"
#include "rspamadm.h"
#include "cryptobox.h"
#include "printf.h"
#include "http.h"
#include "ucl.h"
#include "keypair_private.h"
#include "libutil/str_util.h"

static gboolean hex_encode = FALSE;
static gboolean raw = FALSE;
static gboolean openssl = FALSE;
static gboolean ucl = FALSE;
static gboolean sign = FALSE;

static void rspamadm_keypair (gint argc, gchar **argv);
static const char *rspamadm_keypair_help (gboolean full_help);

struct rspamadm_command keypair_command = {
		.name = "keypair",
		.flags = 0,
		.help = rspamadm_keypair_help,
		.run = rspamadm_keypair
};

static GOptionEntry entries[] = {
		{"hex",  'x', 0, G_OPTION_ARG_NONE,   &hex_encode,
				"Use hex encoding",                         NULL},
		{"raw", 'r', 0, G_OPTION_ARG_NONE, &raw,
				"Print just keys, no description", NULL},
		{"openssl", 'o', 0, G_OPTION_ARG_NONE, &openssl,
				"Generate openssl nistp256 keypair not curve25519 one", NULL},
		{"sign", 's', 0, G_OPTION_ARG_NONE, &sign,
				"Generate keypair for digital signing", NULL},
		{"ucl", 'u', 0, G_OPTION_ARG_NONE, &ucl,
				"Generate ucl config", NULL},
		{NULL,       0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_keypair_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Create key pairs for httpcrypt\n\n"
				"Usage: rspamadm keypair [-x -r]\n"
				"Where options are:\n\n"
				"-x: encode with hex instead of base32\n"
				"-r: print raw base32/hex\n"
				"-o: generate openssl nistp256 keypair\n"
				"-s: generate keypair suitable for signatures\n"
				"-u: generate ucl config for keypair\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Create encryption key pairs";
	}

	return help_str;
}

static void
rspamadm_keypair (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	gpointer keypair;
	GString *keypair_out;
	gint how;
	ucl_object_t *ucl_out, *elt;
	struct ucl_emitter_functions *ucl_emit_subr;
	guchar *sig_sk, *sig_pk;
	gchar *sig_sk_encoded, *sig_pk_encoded, *pk_id_encoded;
	guchar kh[rspamd_cryptobox_HASHBYTES];
	const gchar *encoding;

	context = g_option_context_new (
			"keypair - create encryption keys");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	if (openssl) {
		if (!rspamd_cryptobox_openssl_mode (TRUE)) {
			fprintf (stderr, "cannot enable openssl mode (incompatible openssl)\n");
			exit (1);
		}
	}

	if (!sign) {
		keypair = rspamd_http_connection_gen_key ();
		if (keypair == NULL) {
			exit (EXIT_FAILURE);
		}

		how = 0;

		if (hex_encode) {
			how |= RSPAMD_KEYPAIR_HEX;
			encoding = "hex";
		}
		else {
			how |= RSPAMD_KEYPAIR_BASE32;
			encoding = "base32";
		}

		if (ucl) {
			ucl_out = ucl_object_typed_new (UCL_OBJECT);
			elt = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (ucl_out, elt, "keypair", 0, false);

			/* pubkey part */
			keypair_out = rspamd_http_connection_print_key (keypair,
					RSPAMD_KEYPAIR_PUBKEY|how);
			ucl_object_insert_key (elt,
					ucl_object_fromlstring (keypair_out->str, keypair_out->len),
					"pubkey", 0, false);
			g_string_free (keypair_out, TRUE);

			/* privkey part */
			keypair_out = rspamd_http_connection_print_key (keypair,
					RSPAMD_KEYPAIR_PRIVKEY|how);
			ucl_object_insert_key (elt,
					ucl_object_fromlstring (keypair_out->str, keypair_out->len),
					"privkey", 0, false);
			g_string_free (keypair_out, TRUE);

			keypair_out = rspamd_http_connection_print_key (keypair,
					RSPAMD_KEYPAIR_ID|how);
			ucl_object_insert_key (elt,
					ucl_object_fromlstring (keypair_out->str, keypair_out->len),
					"id", 0, false);
			ucl_object_insert_key (elt,
					ucl_object_fromstring (encoding),
					"encoding", 0, false);

			ucl_emit_subr = ucl_object_emit_file_funcs (stdout);
			ucl_object_emit_full (ucl_out, UCL_EMIT_CONFIG, ucl_emit_subr);
			ucl_object_emit_funcs_free (ucl_emit_subr);
			ucl_object_unref (ucl_out);
		}
		else {
			how |= RSPAMD_KEYPAIR_PUBKEY | RSPAMD_KEYPAIR_PRIVKEY;

			if (!raw) {
				how |= RSPAMD_KEYPAIR_HUMAN|RSPAMD_KEYPAIR_ID;
			}

			keypair_out = rspamd_http_connection_print_key (keypair, how);
			rspamd_printf ("%v", keypair_out);
		}

		rspamd_http_connection_key_unref (keypair);
		rspamd_explicit_memzero (keypair_out->str, keypair_out->len);
		g_string_free (keypair_out, TRUE);
	}
	else {
		sig_sk = g_malloc (rspamd_cryptobox_sk_sig_bytes ());
		sig_pk = g_malloc (rspamd_cryptobox_pk_sig_bytes ());

		rspamd_cryptobox_keypair_sig (sig_pk, sig_sk);
		rspamd_cryptobox_hash (kh, sig_pk, rspamd_cryptobox_pk_sig_bytes (),
							NULL, 0);

		if (hex_encode) {
			encoding = "hex";
			sig_pk_encoded = rspamd_encode_hex (sig_pk,
					rspamd_cryptobox_pk_sig_bytes ());
			sig_sk_encoded = rspamd_encode_hex (sig_sk,
					rspamd_cryptobox_sk_sig_bytes ());
			pk_id_encoded = rspamd_encode_hex (kh, sizeof (kh));
		}
		else {
			encoding = "base32";
			sig_pk_encoded = rspamd_encode_base32 (sig_pk,
					rspamd_cryptobox_pk_sig_bytes ());
			sig_sk_encoded = rspamd_encode_base32 (sig_sk,
					rspamd_cryptobox_sk_sig_bytes ());
			pk_id_encoded = rspamd_encode_base32 (kh, sizeof (kh));
		}

		if (ucl) {
			ucl_out = ucl_object_typed_new (UCL_OBJECT);
			elt = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (ucl_out, elt, "keypair", 0, false);

			/* pubkey part */
			ucl_object_insert_key (elt,
					ucl_object_fromstring (sig_pk_encoded),
					"pubkey", 0, false);

			/* privkey part */
			ucl_object_insert_key (elt,
					ucl_object_fromstring (sig_sk_encoded),
					"privkey", 0, false);

			ucl_object_insert_key (elt,
					ucl_object_fromstring (pk_id_encoded),
					"id", 0, false);

			ucl_object_insert_key (elt,
					ucl_object_fromstring (encoding),
					"encoding", 0, false);

			ucl_emit_subr = ucl_object_emit_file_funcs (stdout);
			ucl_object_emit_full (ucl_out, UCL_EMIT_CONFIG, ucl_emit_subr);
			ucl_object_emit_funcs_free (ucl_emit_subr);
			ucl_object_unref (ucl_out);
		}
		else {
			rspamd_printf ("Public key: %s\nPrivate key: %s\nKey ID: %s\n",
					sig_pk_encoded,
					sig_sk_encoded,
					pk_id_encoded);
		}

		rspamd_explicit_memzero (sig_sk, rspamd_cryptobox_sk_sig_bytes ());
		rspamd_explicit_memzero (sig_sk_encoded, strlen (sig_sk_encoded));

		g_free (sig_pk);
		g_free (sig_sk);
		g_free (sig_pk_encoded);
		g_free (sig_sk_encoded);
		g_free (pk_id_encoded);
	}
}
