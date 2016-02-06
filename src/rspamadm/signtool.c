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
#include "ucl.h"
#include "libcryptobox/keypair.h"
#include "libutil/str_util.h"
#include "libutil/util.h"
#include "unix-std.h"

static gboolean openssl = FALSE;
static gboolean verify = FALSE;
static gboolean quiet = FALSE;
static gchar *suffix = NULL;
static gchar *pubkey_file = NULL;
static gchar *pubkey = NULL;
static gchar *keypair_file = NULL;
enum rspamd_cryptobox_mode mode = RSPAMD_CRYPTOBOX_MODE_25519;

static void rspamadm_signtool (gint argc, gchar **argv);
static const char *rspamadm_signtool_help (gboolean full_help);

struct rspamadm_command signtool_command = {
		.name = "signtool",
		.flags = 0,
		.help = rspamadm_signtool_help,
		.run = rspamadm_signtool
};

static GOptionEntry entries[] = {
		{"openssl", 'o', 0, G_OPTION_ARG_NONE, &openssl,
				"Generate openssl nistp256 keypair not curve25519 one", NULL},
		{"verify", 'v', 0, G_OPTION_ARG_NONE, &verify,
				"Verify signatures and not sign", NULL},
		{"suffix", 'S', 0, G_OPTION_ARG_STRING, &suffix,
				"Save signatures in file<suffix> files", NULL},
		{"pubkey", 'p', 0, G_OPTION_ARG_STRING, &pubkey,
				"Base32 encoded pubkey to verify", NULL},
		{"pubfile", 'P', 0, G_OPTION_ARG_FILENAME, &pubkey_file,
				"Load base32 encoded pubkey to verify from the file", NULL},
		{"keypair", 'k', 0, G_OPTION_ARG_STRING, &keypair_file,
				"UCL with keypair to load for signing", NULL},
		{"quiet", 'q', 0, G_OPTION_ARG_NONE, &quiet,
				"Be quiet", NULL},
		{NULL,       0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_signtool_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Manage digital signatures\n\n"
				"Usage: rspamadm signtool [-o] -k <keypair_file> [-v -p <pubkey> | -P <pubkey_file>] [-S <suffix>] file1 ...\n"
				"Where options are:\n\n"
				"-v: verify against pubkey instead of \n"
				"-o: use ECDSA instead of EdDSA\n"
				"-p: load pubkey as base32 string\n"
				"-P: load pubkey paced in file\n"
				"-k: load signing keypair from ucl file\n"
				"-S: append suffix for signatures and store them in files\n"
				"-q: be quiet\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Create encryption key pairs";
	}

	return help_str;
}

static bool
rspamadm_sign_file (const gchar *fname, const guchar *sk)
{
	gint fd_sig, fd_input;
	guchar sig[rspamd_cryptobox_MAX_SIGBYTES], *map;
	gchar sigpath[PATH_MAX];
	struct stat st;

	if (suffix == NULL) {
		suffix = ".sig";
	}

	fd_input = rspamd_file_xopen (fname, O_RDONLY, 0);

	if (fd_input == -1) {
		rspamd_fprintf (stderr, "cannot open %s: %s\n", fname,
				strerror (errno));
		exit (errno);
	}

	g_assert (fstat (fd_input, &st) != -1);

	rspamd_snprintf (sigpath, sizeof (sigpath), "%s%s", fname, suffix);
	fd_sig = rspamd_file_xopen (sigpath, O_WRONLY | O_CREAT | O_TRUNC, 00644);

	if (fd_sig == -1) {
		close (fd_input);
		rspamd_fprintf (stderr, "cannot open %s: %s\n", sigpath,
				strerror (errno));
		exit (errno);
	}

	map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd_input, 0);
	close (fd_input);

	if (map == MAP_FAILED) {
		close (fd_sig);
		rspamd_fprintf (stderr, "cannot map %s: %s\n", fname,
				strerror (errno));
		exit (errno);
	}

	g_assert (rspamd_cryptobox_MAX_SIGBYTES >=
			rspamd_cryptobox_signature_bytes (mode));

	rspamd_cryptobox_sign (sig, NULL, map, st.st_size, sk, mode);
	write (fd_sig, sig, rspamd_cryptobox_signature_bytes (mode));
	close (fd_sig);
	munmap (map, st.st_size);

	if (!quiet) {
		rspamd_fprintf (stdout, "signed %s; stored hash in %s\n",
				fname, sigpath);
	}

	return true;
}

static bool
rspamadm_verify_file (const gchar *fname, const guchar *pk)
{
	gint fd_sig, fd_input;
	guchar *map, *map_sig;
	gchar sigpath[PATH_MAX];
	struct stat st, st_sig;
	bool ret;

	g_assert (rspamd_cryptobox_MAX_SIGBYTES >=
			rspamd_cryptobox_signature_bytes (mode));

	if (suffix == NULL) {
		suffix = ".sig";
	}

	fd_input = rspamd_file_xopen (fname, O_RDONLY, 0);

	if (fd_input == -1) {
		rspamd_fprintf (stderr, "cannot open %s: %s\n", fname,
				strerror (errno));
		exit (errno);
	}

	g_assert (fstat (fd_input, &st) != -1);

	rspamd_snprintf (sigpath, sizeof (sigpath), "%s%s", fname, suffix);
	fd_sig = rspamd_file_xopen (sigpath, O_RDONLY, 0);

	if (fd_sig == -1) {
		close (fd_input);
		rspamd_fprintf (stderr, "cannot open %s: %s\n", sigpath,
				strerror (errno));
		exit (errno);
	}

	map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd_input, 0);
	close (fd_input);

	if (map == MAP_FAILED) {
		close (fd_sig);
		rspamd_fprintf (stderr, "cannot open %s: %s\n", sigpath,
				strerror (errno));
		exit (errno);
	}

	g_assert (fstat (fd_sig, &st_sig) != -1);

	if (st_sig.st_size != rspamd_cryptobox_signature_bytes (mode)) {
		close (fd_sig);
		rspamd_fprintf (stderr, "invalid signature size %s: %ud\n", fname,
				(guint)st_sig.st_size);
		munmap (map, st.st_size);
		exit (errno);
	}

	map_sig = mmap (NULL, st_sig.st_size, PROT_READ, MAP_SHARED, fd_sig, 0);
	close (fd_sig);

	if (map_sig == MAP_FAILED) {
		munmap (map, st.st_size);
		rspamd_fprintf (stderr, "cannot map %s: %s\n", sigpath,
				strerror (errno));
		exit (errno);
	}

	ret = rspamd_cryptobox_verify (map_sig, map, st.st_size, pk, mode);
	munmap (map, st.st_size);
	munmap (map_sig, st_sig.st_size);

	if (!ret) {
		rspamd_fprintf (stderr, "cannot verify %s using %s: invalid signature\n",
				fname, sigpath);
	}
	else if (!quiet) {
		rspamd_fprintf (stdout, "verified %s using %s\n",
				fname, sigpath);
	}

	return ret;
}


static void
rspamadm_signtool (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	struct ucl_parser *parser;
	ucl_object_t *top;
	struct rspamd_cryptobox_pubkey *pk;
	struct rspamd_cryptobox_keypair *kp;
	gsize fsize, flen;
	gint i;

	context = g_option_context_new (
			"keypair - create encryption keys");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		rspamd_fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	if (openssl) {
		mode = RSPAMD_CRYPTOBOX_MODE_NIST;
	}

	if (verify && (!pubkey && !pubkey_file)) {
		rspamd_fprintf (stderr, "no pubkey for verification\n");
		exit (1);
	}
	else if (!verify && (!keypair_file)) {
		rspamd_fprintf (stderr, "no keypair for signing\n");
		exit (1);
	}

	if (verify) {
		g_assert (pubkey || pubkey_file);

		if (pubkey_file) {
			gint fd;
			gchar *map;
			struct stat st;

			fd = open (pubkey_file, O_RDONLY);

			if (fd == -1) {
				rspamd_fprintf (stderr, "cannot open %s: %s\n", pubkey_file,
						strerror (errno));
				exit (errno);
			}

			g_assert (fstat (fd, &st) != -1);
			fsize = st.st_size;
			flen = fsize;
			map = mmap (NULL, fsize, PROT_READ, MAP_SHARED, fd, 0);
			close (fd);

			if (map == MAP_FAILED) {
				rspamd_fprintf (stderr, "cannot read %s: %s\n", pubkey_file,
						strerror (errno));
				exit (errno);
			}

			/* XXX: assume base32 pubkey now */
			while (flen > 0 && g_ascii_isspace (map[flen - 1])) {
				flen --;
			}

			pk = rspamd_pubkey_from_base32 (map, flen,
					RSPAMD_KEYPAIR_SIGN, mode);

			if (pk == NULL) {
				rspamd_fprintf (stderr, "bad size %s: %ud, %ud expected\n", flen,
						 rspamd_cryptobox_pk_sig_bytes (mode));
				exit (errno);
			}

			munmap (map, fsize);
		}
		else {
			pk = rspamd_pubkey_from_base32 (pubkey, strlen (pubkey),
								RSPAMD_KEYPAIR_SIGN, mode);

			if (pk == NULL) {
				rspamd_fprintf (stderr, "bad size %s: %ud, %ud expected\n",
						strlen (pubkey),
						rspamd_cryptobox_pk_sig_bytes (mode));
				exit (errno);
			}
		}

		for (i = 1; i < argc; i++) {
			/* XXX: support cmd line signature */
			if (!rspamadm_verify_file (argv[i], rspamd_pubkey_get_pk (pk, NULL))) {
				exit (EXIT_FAILURE);
			}
		}

		g_free (pk);
	}
	else {
		g_assert (keypair_file != NULL);

		parser = ucl_parser_new (0);

		if (!ucl_parser_add_file (parser, keypair_file) ||
				(top = ucl_parser_get_object (parser)) == NULL) {
			rspamd_fprintf (stderr, "cannot load keypair: %s\n",
					ucl_parser_get_error (parser));
			exit (EINVAL);
		}

		ucl_parser_free (parser);

		kp = rspamd_keypair_from_ucl (top);

		for (i = 1; i < argc; i++) {
			/* XXX: support cmd line signature */
			if (!rspamadm_sign_file (argv[i], rspamd_keypair_component (
					kp, RSPAMD_KEYPAIR_COMPONENT_SK, NULL))) {
				rspamd_keypair_unref (kp);
				exit (EXIT_FAILURE);
			}
		}

		rspamd_keypair_unref (kp);
	}
}
