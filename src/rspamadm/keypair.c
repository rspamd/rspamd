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
#include "rspamadm.h"
#include "cryptobox.h"
#include "printf.h"
#include "http.h"

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
		.run = rspamadm_keypair,
		.lua_subrs = NULL,
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
	struct rspamd_cryptobox_keypair *kp;
	gint how = 0;
	ucl_object_t *ucl_out;
	struct ucl_emitter_functions *ucl_emit_subr;
	GString *out;
	enum rspamd_cryptobox_keypair_type type = RSPAMD_KEYPAIR_KEX;
	enum rspamd_cryptobox_mode mode = RSPAMD_CRYPTOBOX_MODE_25519;

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
		mode = RSPAMD_CRYPTOBOX_MODE_NIST;
	}
	if (hex_encode) {
		how |= RSPAMD_KEYPAIR_HEX;
	}
	else {
		how |= RSPAMD_KEYPAIR_BASE32;
	}

	if (sign) {
		type = RSPAMD_KEYPAIR_SIGN;
	}

	kp = rspamd_keypair_new (type, mode);

	if (ucl) {
		ucl_out = rspamd_keypair_to_ucl (kp, hex_encode);
		ucl_emit_subr = ucl_object_emit_file_funcs (stdout);
		ucl_object_emit_full (ucl_out, UCL_EMIT_CONFIG, ucl_emit_subr, NULL);
		ucl_object_emit_funcs_free (ucl_emit_subr);
		ucl_object_unref (ucl_out);
	}
	else {
		how |= RSPAMD_KEYPAIR_PUBKEY | RSPAMD_KEYPAIR_PRIVKEY;

		if (!raw) {
			how |= RSPAMD_KEYPAIR_HUMAN|RSPAMD_KEYPAIR_ID;
		}

		out = rspamd_keypair_print (kp, how);
		rspamd_printf ("%v", out);
		g_string_free (out, TRUE);
	}

	rspamd_keypair_unref (kp);
}
