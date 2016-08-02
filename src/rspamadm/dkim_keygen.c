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
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

static gchar *privkey_file = NULL;
static gchar *selector = NULL;
static gchar *domain = NULL;

static void rspamadm_dkim_keygen (gint argc, gchar **argv);
static const char *rspamadm_dkim_keygen_help (gboolean full_help);

struct rspamadm_command dkim_keygen_command = {
		.name = "dkim_keygen",
		.flags = 0,
		.help = rspamadm_dkim_keygen_help,
		.run = rspamadm_dkim_keygen
};

static GOptionEntry entries[] = {
		{"domain",  'd', 0, G_OPTION_ARG_STRING, &domain,
				"Use the specified domain", NULL},
		{"selector",  's', 0, G_OPTION_ARG_STRING, &selector,
				"Use the specified selector", NULL},
		{"privkey",  'k', 0, G_OPTION_ARG_STRING, &privkey_file,
				"Save private key in the specified file", NULL},
		{NULL,       0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_dkim_keygen_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Create key pairs for dkim signing\n\n"
				"Usage: rspamadm dkim_keygen -s selector -d domain [-k privkey]\n"
				"Where options are:\n\n"
				"-d: use the specified domain\n"
				"-s: use the specified selector\n"
				"-k: save private key to file instead of printing it to stdout\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Create dkim key pairs";
	}

	return help_str;
}

static void
rspamadm_dkim_keygen (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	BIGNUM *e;
	RSA *r;
	BIO *pubout, *privout;
	EVP_PKEY *pk;
	gint rc;
	glong publen;
	gchar *pubdata, *b64_data;

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
		exit (1);
	}

	e = BN_new ();
	r = RSA_new ();
	pk = EVP_PKEY_new ();
	g_assert (BN_set_word (e, RSA_F4) == 1);
	g_assert (RSA_generate_key_ex (r, 1024, e, NULL) == 1);
	g_assert (EVP_PKEY_set1_RSA (pk, r) == 1);

	if (privkey_file) {
		privout = BIO_new_file (privkey_file, "w");

		if (privout == NULL) {
			rspamd_fprintf (stderr, "cannot open output file %s: %s\n",
					privkey_file, strerror (errno));
			exit (EXIT_FAILURE);
		}
	}
	else {
		privout = BIO_new_fp (stdout, 0);
	}

	rc = PEM_write_bio_PrivateKey (privout, pk, NULL, NULL, 0, NULL, NULL);

	if (rc != 1) {
		rspamd_fprintf (stderr, "cannot write key to the output file %s: %s\n",
				privkey_file ? privkey_file : "stdout", strerror (errno));
		exit (EXIT_FAILURE);
	}

	BIO_free (privout);
	fflush (stdout);

	pubout = BIO_new (BIO_s_mem());

	rc = i2d_RSA_PUBKEY_bio (pubout, r);
	publen = BIO_get_mem_data (pubout, &pubdata);

	g_assert (publen > 0);
	b64_data = rspamd_encode_base64 (pubdata, publen, -1, NULL);
	rspamd_printf ("%s._domainkey IN TXT ( \"v=DKIM1; k=rsa; \"\n"
			"\t\"p=%s\" ) ;\n",
			selector ? selector : "selector",
			b64_data);

	g_free (b64_data);
	BIO_free (pubout);
	EVP_PKEY_free (pk);
	RSA_free (r);
	BN_free (e);
}
