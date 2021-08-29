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
#include "printf.h"
#include "str_util.h"
#include "libcryptobox/cryptobox.h"
#include "contrib/libottery/ottery.h"
#include "lua/lua_common.h"
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

static gchar *privkey_file = NULL;
static gchar *selector = NULL;
static gchar *domain = NULL;
static guint bits = 1024;
static gchar *type = "rsa";

static void rspamadm_dkim_keygen (gint argc, gchar **argv,
								  const struct rspamadm_command *cmd);
static const char *rspamadm_dkim_keygen_help (gboolean full_help,
											  const struct rspamadm_command *cmd);
static void rspamadm_dkim_keygen_lua_subrs (gpointer pL);

struct rspamadm_command dkim_keygen_command = {
		.name = "dkim_keygen",
		.flags = 0,
		.help = rspamadm_dkim_keygen_help,
		.run = rspamadm_dkim_keygen,
		.lua_subrs = rspamadm_dkim_keygen_lua_subrs,
};

static GOptionEntry entries[] = {
		{"domain",  'd', 0, G_OPTION_ARG_STRING, &domain,
				"Use the specified domain", NULL},
		{"selector",  's', 0, G_OPTION_ARG_STRING, &selector,
				"Use the specified selector", NULL},
		{"privkey",  'k', 0, G_OPTION_ARG_STRING, &privkey_file,
				"Save private key in the specified file", NULL},
		{"bits",  'b', 0, G_OPTION_ARG_INT, &bits,
				"Set key length to N bits (1024 by default)", NULL},
		{"type",  't', 0, G_OPTION_ARG_STRING, &type,
				"Key type: rsa or ed25519 (rsa by default)", NULL},
		{NULL,       0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_dkim_keygen_help (gboolean full_help, const struct rspamadm_command *cmd)
{
	const char *help_str;

	if (full_help) {
		help_str = "Create key pairs for dkim signing\n\n"
				"Usage: rspamadm dkim_keygen -s selector -d domain [-k privkey] [-b bits]\n"
				"Where options are:\n\n"
				"-d: use the specified domain\n"
				"-s: use the specified selector\n"
				"-k: save private key to file instead of printing it to stdout\n"
				"-b: set number of bits instead of 1024\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Create dkim key pairs";
	}

	return help_str;
}

static void
rspamd_dkim_generate_rsa_keypair (const gchar *domain, const gchar *selector,
								  const gchar *priv_fname, const gchar *pub_fname,
								  guint keylen)
{
	BIGNUM *e;
	RSA *r;
	BIO *pubout, *privout;
	EVP_PKEY *pk;
	gint rc;
	glong publen;
	gsize b64_len;
	gchar *pubdata, *b64_data;
	FILE *pubfile = NULL;

	if (bits > 4096 || bits < 512) {
		fprintf (stderr, "Bits number must be in the interval 512...4096\n");
		exit (EXIT_FAILURE);
	}

	e = BN_new ();
	r = RSA_new ();
	pk = EVP_PKEY_new ();
	g_assert (BN_set_word (e, RSA_F4) == 1);
	g_assert (RSA_generate_key_ex (r, bits, e, NULL) == 1);
	g_assert (EVP_PKEY_set1_RSA (pk, r) == 1);

	if (priv_fname) {
		privout = BIO_new_file (priv_fname, "w");

		if (privout == NULL) {
			rspamd_fprintf (stderr, "cannot open output file %s: %s\n",
					priv_fname, strerror (errno));
			exit (EXIT_FAILURE);
		}
	} else {
		privout = BIO_new_fp (stdout, 0);
	}

	rc = PEM_write_bio_PrivateKey (privout, pk, NULL, NULL, 0, NULL, NULL);

	if (rc != 1) {
		rspamd_fprintf (stderr, "cannot write key to the output file %s: %s\n",
				priv_fname ? priv_fname : "stdout", strerror (errno));
		exit (EXIT_FAILURE);
	}

	BIO_free (privout);
	fflush (stdout);

	pubout = BIO_new (BIO_s_mem ());

	rc = i2d_RSA_PUBKEY_bio (pubout, r);
	publen = BIO_get_mem_data (pubout, &pubdata);

	g_assert (publen > 0);
	b64_data = rspamd_encode_base64 (pubdata, publen, -1, &b64_len);

	if (pub_fname) {
		pubfile = fopen (pub_fname, "w");

		if (pubfile == NULL) {
			rspamd_fprintf (stderr, "cannot open output file %s: %s\n",
					pub_fname, strerror (errno));
			exit (EXIT_FAILURE);
		}
	} else {
		pubfile = stdout;
	}

	if (b64_len < 255 - 2) {
		rspamd_fprintf (pubfile, "%s._domainkey IN TXT ( \"v=DKIM1; k=rsa; \"\n"
								 "\t\"p=%s\" ) ;\n",
				selector ? selector : "selector",
				b64_data);
	} else {
		guint i;
		gint step = 253, remain = b64_len;

		rspamd_fprintf (pubfile, "%s._domainkey IN TXT ( \"v=DKIM1; k=rsa; \"\n",
				selector ? selector : "selector");

		for (i = 0; i < b64_len; i += step, remain -= step) {
			if (i == 0) {
				rspamd_fprintf (pubfile, "\t\"p=%*s\"\n", MIN(step, remain), &b64_data[i]);
			} else {
				step = 255;
				rspamd_fprintf (pubfile, "\t\"%*s\"\n", MIN(step, remain), &b64_data[i]);
			}
		}

		rspamd_fprintf (pubfile, ") ; \n");
	}

	if (pubfile != stdout) {
		fclose (pubfile);
	}

	g_free (b64_data);
	BIO_free (pubout);
	EVP_PKEY_free (pk);
	RSA_free (r);
	BN_free (e);
}

static void
rspamd_dkim_generate_ed25519_keypair (const gchar *domain, const gchar *selector,
								  const gchar *priv_fname, const gchar *pub_fname,
								  guint keylen, gboolean seeded)
{
	rspamd_sig_sk_t ed_sk;
	rspamd_sig_pk_t ed_pk;
	gchar *base64_pk, *base64_sk;
	FILE *pubfile = NULL, *privfile = NULL;

	rspamd_cryptobox_keypair_sig (ed_pk, ed_sk, RSPAMD_CRYPTOBOX_MODE_25519);
	if (seeded) {
		/* Just encode seed, not the full sk */
		base64_sk = rspamd_encode_base64_common (ed_sk, 32, 0, NULL, FALSE,
				RSPAMD_TASK_NEWLINES_LF);
	}
	else {
		base64_sk = rspamd_encode_base64_common (ed_sk,
				rspamd_cryptobox_sk_sig_bytes (RSPAMD_CRYPTOBOX_MODE_25519),
				0, NULL, FALSE,
				RSPAMD_TASK_NEWLINES_LF);
	}
	base64_pk = rspamd_encode_base64_common (ed_pk, sizeof (ed_pk), 0, NULL, FALSE,
			RSPAMD_TASK_NEWLINES_LF);

	/* Cleanup sensitive data */
	rspamd_explicit_memzero (ed_sk, sizeof (ed_sk));

	if (priv_fname) {
		privfile = fopen (priv_fname, "w");

		if (privfile == NULL) {
			rspamd_fprintf (stderr, "cannot open output file %s: %s\n",
					priv_fname, strerror (errno));
			rspamd_explicit_memzero (base64_sk, strlen (base64_sk));
			g_free (base64_sk);
			g_free (base64_pk);
			exit (EXIT_FAILURE);
		}
	}
	else {
		privfile = stdout;
	}

	if (rspamd_fprintf (privfile, "%s\n", base64_sk) == -1) {
		rspamd_fprintf (stderr, "cannot write to output file %s: %s\n",
				priv_fname, strerror (errno));
		rspamd_explicit_memzero (base64_sk, strlen (base64_sk));
		g_free (base64_sk);
		g_free (base64_pk);

		if (privfile != stdout) {
			fclose (privfile);
		}

		exit (EXIT_FAILURE);
	}

	if (privfile != stdout) {
		fclose (privfile);
	}

	if (pub_fname) {
		pubfile = fopen (pub_fname, "w");

		if (pubfile == NULL) {
			rspamd_fprintf (stderr, "cannot open output file %s: %s\n",
					pub_fname, strerror (errno));
			rspamd_explicit_memzero (base64_sk, strlen (base64_sk));
			g_free (base64_sk);
			g_free (base64_pk);
			exit (EXIT_FAILURE);
		}
	}
	else {
		pubfile = stdout;
	}

	rspamd_fprintf (pubfile, "%s._domainkey IN TXT ( \"v=DKIM1; k=ed25519; \"\n"
							 "\t\"p=%s\" ) ;\n",
			selector ? selector : "selector",
			base64_pk);

	if (pubfile != stdout) {
		fclose (pubfile);
	}

	rspamd_explicit_memzero (base64_sk, strlen (base64_sk));
	g_free (base64_sk);
	g_free (base64_pk);
}

static void
rspamadm_dkim_generate_keypair (const gchar *domain, const gchar *selector,
		const gchar *priv_fname, const gchar *pub_fname, guint keylen)
{
	if (strcmp (type, "rsa") == 0) {
		rspamd_dkim_generate_rsa_keypair (domain, selector, priv_fname,
				pub_fname, keylen);
	}
	else if (strcmp (type, "ed25519") == 0) {
		rspamd_dkim_generate_ed25519_keypair (domain, selector, priv_fname,
				pub_fname, keylen, FALSE);
	}
	else if (strcmp (type, "ed25519-seed") == 0) {
		rspamd_dkim_generate_ed25519_keypair (domain, selector, priv_fname,
				pub_fname, keylen, TRUE);
	}
	else {
		fprintf (stderr, "invalid key type: %s\n", type);
		exit (EXIT_FAILURE);
	}
}

static gint
rspamadm_dkim_keygen_lua_generate (lua_State *L)
{
	const gchar *domain = luaL_checkstring (L, 1);
	const gchar *selector = luaL_checkstring (L, 2);
	const gchar *privfile = NULL, *pubfile = NULL;
	guint key_bits = 1024;

	if (domain == NULL || selector == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_type (L, 3) == LUA_TSTRING) {
		privfile = lua_tostring (L, 3);
	}

	if (lua_type (L, 4) == LUA_TSTRING) {
		pubfile = lua_tostring (L, 4);
	}

	if (lua_type (L, 5) == LUA_TNUMBER) {
		key_bits = lua_tonumber (L, 5);
	}

	rspamadm_dkim_generate_keypair (domain, selector, privfile, pubfile, key_bits);

	return 0;
}

static void
rspamadm_dkim_keygen_lua_subrs (gpointer pL)
{
	lua_State *L = pL;

	lua_pushstring (L, "dkim_keygen");
	lua_pushcfunction (L, rspamadm_dkim_keygen_lua_generate);
	lua_settable (L, -3);
}

static void
rspamadm_dkim_keygen (gint argc, gchar **argv, const struct rspamadm_command *cmd)
{
	GOptionContext *context;
	GError *error = NULL;

	context = g_option_context_new (
			"dkim_keygen - create dkim keys");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		g_option_context_free (context);
		exit (EXIT_FAILURE);
	}

	g_option_context_free (context);
	rspamadm_dkim_generate_keypair (domain, selector, privkey_file, NULL, bits);
}
