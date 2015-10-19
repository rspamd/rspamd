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

static gboolean hex_encode = FALSE;
static gboolean raw = FALSE;
static gboolean openssl = FALSE;

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
		{"openssl", 's', 0, G_OPTION_ARG_NONE, &openssl,
				"Generate openssl nistp256 keypair not curve25519 one", NULL},
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
				"-s: generate openssl nistp256 keypair\n"
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

	keypair = rspamd_http_connection_gen_key ();
	if (keypair == NULL) {
		exit (EXIT_FAILURE);
	}

	how = RSPAMD_KEYPAIR_PUBKEY | RSPAMD_KEYPAIR_PRIVKEY;

	if (hex_encode) {
		how |= RSPAMD_KEYPAIR_HEX;
	}
	else {
		how |= RSPAMD_KEYPAIR_BASE32;
	}

	if (!raw) {
		how |= RSPAMD_KEYPAIR_HUMAN|RSPAMD_KEYPAIR_ID;
	}

	keypair_out = rspamd_http_connection_print_key (keypair, how);
	rspamd_printf ("%v", keypair_out);

	rspamd_http_connection_key_unref (keypair);
	rspamd_explicit_memzero (keypair_out->str, keypair_out->len);
}
