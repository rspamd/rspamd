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
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

static gboolean openssl = FALSE;
static gboolean verify = FALSE;
static gboolean quiet = FALSE;
static gchar *suffix = NULL;
static gchar *pubkey_file = NULL;
static gchar *pubkey = NULL;
static gchar *pubout = NULL;
static gchar *keypair_file = NULL;
static gchar *editor = NULL;
static gboolean edit = FALSE;
enum rspamd_cryptobox_mode mode = RSPAMD_CRYPTOBOX_MODE_25519;

static void rspamadm_signtool (gint argc, gchar **argv,
							   const struct rspamadm_command *cmd);
static const char *rspamadm_signtool_help (gboolean full_help,
										   const struct rspamadm_command *cmd);

struct rspamadm_command signtool_command = {
		.name = "signtool",
		.flags = 0,
		.help = rspamadm_signtool_help,
		.run = rspamadm_signtool,
		.lua_subrs = NULL,
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
		{"pubout", '\0', 0, G_OPTION_ARG_FILENAME, &pubout,
				"Output public key to the specified file", NULL},
		{"pubfile", 'P', 0, G_OPTION_ARG_FILENAME, &pubkey_file,
				"Load base32 encoded pubkey to verify from the file", NULL},
		{"keypair", 'k', 0, G_OPTION_ARG_STRING, &keypair_file,
				"UCL with keypair to load for signing", NULL},
		{"quiet", 'q', 0, G_OPTION_ARG_NONE, &quiet,
				"Be quiet", NULL},
		{"edit", 'e', 0, G_OPTION_ARG_NONE, &edit,
				"Run editor and sign the edited file", NULL},
		{"editor", '\0', 0, G_OPTION_ARG_STRING, &editor,
				"Use the specified editor instead of $EDITOR environment var", NULL},
		{NULL,       0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_signtool_help (gboolean full_help,
						const struct rspamadm_command *cmd)
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
				"-e: opens file for editing and sign the result\n"
				"--editor: use the specified editor instead of $EDITOR environment var\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Sign and verify files tool";
	}

	return help_str;
}

static gint
rspamadm_edit_file (const gchar *fname)
{
	gchar tmppath[PATH_MAX], run_cmdline[PATH_MAX];
	guchar *map;
	gsize len = 0;
	gint fd_out, retcode, child_argc;
	GPid child_pid;
	gchar *tmpdir, **child_argv = NULL;
	struct stat st;
	GError *err = NULL;

	if (editor == NULL) {
		editor = getenv ("EDITOR");
	}

	if (editor == NULL) {
		rspamd_fprintf (stderr, "cannot find editor: specify $EDITOR "
				"environment variable or pass --editor argument\n");
		exit (EXIT_FAILURE);
	}

	tmpdir = getenv ("TMPDIR");
	if (tmpdir == NULL) {
		tmpdir = "/tmp";
	}

	if (stat (fname, &st) == -1 || st.st_size == 0) {
		/* The source does not exist, but that shouldn't be a problem */
		len = 0;
		map = NULL;

		/* Try to touch source anyway */
		fd_out = rspamd_file_xopen (fname, O_WRONLY | O_CREAT | O_EXCL, 00644,
				0);

		if (fd_out == -1) {
			rspamd_fprintf (stderr, "cannot open %s: %s\n", fname,
					strerror (errno));
			exit (EXIT_FAILURE);
		}

		close (fd_out);
	}
	else {
		map = rspamd_file_xmap (fname, PROT_READ, &len, TRUE);

		if (map == NULL) {
			rspamd_fprintf (stderr, "cannot open %s: %s\n", fname,
					strerror (errno));
			exit (EXIT_FAILURE);
		}
	}

	rspamd_snprintf (tmppath, sizeof (tmppath),
			"%s/rspamd_sign-XXXXXXXXXX", tmpdir);
	mode_t cur_umask = umask (S_IRWXO|S_IRWXG);
	fd_out = mkstemp (tmppath);
	(void)umask (cur_umask);

	if (fd_out == -1) {
		rspamd_fprintf (stderr, "cannot open tempfile %s: %s\n", tmppath,
				strerror (errno));
		exit (EXIT_FAILURE);
	}

	if (len > 0 && write (fd_out, map, len) == -1) {
		rspamd_fprintf (stderr, "cannot write to tempfile %s: %s\n", tmppath,
				strerror (errno));
		unlink (tmppath);
		munmap (map, len);
		close (fd_out);
		exit (EXIT_FAILURE);
	}

	if (len > 0) {
		munmap (map, len);
	}

	fsync (fd_out);
	close (fd_out);

	/* Now we spawn editor with the filename as argument */
	rspamd_snprintf (run_cmdline, sizeof (run_cmdline), "%s %s", editor, tmppath);
	if (!g_shell_parse_argv (run_cmdline, &child_argc,
			&child_argv, &err)) {
		rspamd_fprintf (stderr, "cannot exec %s: %e\n", editor,
				err);
		unlink (tmppath);
		exit (EXIT_FAILURE);
	}

	if (!g_spawn_async (NULL, child_argv, NULL,
			G_SPAWN_CHILD_INHERITS_STDIN|G_SPAWN_SEARCH_PATH|G_SPAWN_DO_NOT_REAP_CHILD,
			NULL, NULL, &child_pid, &err)) {
		rspamd_fprintf (stderr, "cannot exec %s: %e\n", editor,
						err);
		unlink (tmppath);
		exit (EXIT_FAILURE);
	}

	g_strfreev (child_argv);

	for (;;) {
		if (waitpid ((pid_t)child_pid, &retcode, 0) != -1) {
			break;
		}

		if (errno != EINTR) {
			rspamd_fprintf (stderr, "failed to wait for %s: %s\n", editor,
					strerror (errno));
			unlink (tmppath);
			exit (EXIT_FAILURE);
		}
	}

#if GLIB_MAJOR_VERSION >= 2 && GLIB_MINOR_VERSION >= 34
	if (!g_spawn_check_exit_status (retcode, &err)) {
		unlink (tmppath);
		rspamd_fprintf (stderr, "%s returned error code: %d - %e\n", editor,
				retcode, err);
		exit (EXIT_FAILURE);
	}
#else
	if (retcode != 0) {
		unlink (tmppath);
		rspamd_fprintf (stderr, "%s returned error code: %d\n", editor,
				retcode);
		exit (retcode);
	}
#endif

	map = rspamd_file_xmap (tmppath, PROT_READ, &len, TRUE);

	if (map == NULL) {
		rspamd_fprintf (stderr, "cannot map %s: %s\n", tmppath,
				strerror (errno));
		unlink (tmppath);
		exit (EXIT_FAILURE);
	}

	rspamd_snprintf (run_cmdline, sizeof (run_cmdline), "%s.new", fname);
	fd_out = rspamd_file_xopen (run_cmdline, O_RDWR | O_CREAT | O_TRUNC, 00600,
			0);

	if (fd_out == -1) {
		rspamd_fprintf (stderr, "cannot open new file %s: %s\n", run_cmdline,
				strerror (errno));
		unlink (tmppath);
		munmap (map, len);
		exit (EXIT_FAILURE);
	}

	if (write (fd_out, map, len) == -1) {
		rspamd_fprintf (stderr, "cannot write new file %s: %s\n", run_cmdline,
				strerror (errno));
		unlink (tmppath);
		unlink (run_cmdline);
		close (fd_out);
		munmap (map, len);
		exit (EXIT_FAILURE);
	}

	unlink (tmppath);
	(void)lseek (fd_out, 0, SEEK_SET);
	munmap (map, len);

	return fd_out;
}

static bool
rspamadm_sign_file (const gchar *fname, struct rspamd_cryptobox_keypair *kp)
{
	gint fd_sig, fd_input;
	guchar sig[rspamd_cryptobox_MAX_SIGBYTES], *map;
	gchar sigpath[PATH_MAX];
	FILE *pub_fp;
	struct stat st;
	const guchar *sk;

	if (suffix == NULL) {
		suffix = ".sig";
	}

	if (edit) {
		/* We need to open editor and then sign the temporary file */
		fd_input = rspamadm_edit_file (fname);
	}
	else {
		fd_input = rspamd_file_xopen (fname, O_RDONLY, 0, TRUE);
	}

	if (fd_input == -1) {
		rspamd_fprintf (stderr, "cannot open %s: %s\n", fname,
				strerror (errno));
		exit (EXIT_FAILURE);
	}

	g_assert (fstat (fd_input, &st) != -1);

	rspamd_snprintf (sigpath, sizeof (sigpath), "%s%s", fname, suffix);
	fd_sig = rspamd_file_xopen (sigpath, O_WRONLY | O_CREAT | O_TRUNC, 00644, 0);

	if (fd_sig == -1) {
		close (fd_input);
		rspamd_fprintf (stderr, "cannot open %s: %s\n", sigpath,
				strerror (errno));
		exit (EXIT_FAILURE);
	}

	map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd_input, 0);
	close (fd_input);

	if (map == MAP_FAILED) {
		close (fd_sig);
		rspamd_fprintf (stderr, "cannot map %s: %s\n", fname,
				strerror (errno));
		exit (EXIT_FAILURE);
	}

	g_assert (rspamd_cryptobox_MAX_SIGBYTES >=
			rspamd_cryptobox_signature_bytes (mode));

	sk = rspamd_keypair_component (kp, RSPAMD_KEYPAIR_COMPONENT_SK, NULL);
	rspamd_cryptobox_sign (sig, NULL, map, st.st_size, sk, mode);

	if (edit) {
		/* We also need to rename .new file */
		rspamd_snprintf (sigpath, sizeof (sigpath), "%s.new", fname);

		if (rename (sigpath, fname) == -1) {
			rspamd_fprintf (stderr, "cannot rename %s to %s: %s\n", sigpath, fname,
					strerror (errno));
			exit (EXIT_FAILURE);
		}

		unlink (sigpath);
	}

	rspamd_snprintf (sigpath, sizeof (sigpath), "%s%s", fname, suffix);

	if (write (fd_sig, sig, rspamd_cryptobox_signature_bytes (mode)) == -1) {
		rspamd_fprintf (stderr, "cannot write signature to %s: %s\n", sigpath,
				strerror (errno));
		exit (EXIT_FAILURE);
	}

	close (fd_sig);
	munmap (map, st.st_size);

	if (!quiet) {
		rspamd_fprintf (stdout, "signed %s; stored hash in %s\n",
				fname, sigpath);
	}

	if (pubout) {
		GString *b32_pk;

		pub_fp = fopen (pubout, "w");

		if (pub_fp == NULL) {
			rspamd_fprintf (stderr, "cannot write pubkey to %s: %s",
					pubout, strerror (errno));
		}
		else {
			b32_pk = rspamd_keypair_print (kp,
					RSPAMD_KEYPAIR_PUBKEY|RSPAMD_KEYPAIR_BASE32);

			if (b32_pk) {
				rspamd_fprintf (pub_fp, "%v", b32_pk);
				g_string_free (b32_pk, TRUE);
			}

			fclose (pub_fp);
		}
		if (!quiet) {
			rspamd_fprintf (stdout, "stored pubkey in %s\n",
					pubout);
		}
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

	fd_input = rspamd_file_xopen (fname, O_RDONLY, 0, TRUE);

	if (fd_input == -1) {
		rspamd_fprintf (stderr, "cannot open %s: %s\n", fname,
				strerror (errno));
		exit (EXIT_FAILURE);
	}

	g_assert (fstat (fd_input, &st) != -1);

	rspamd_snprintf (sigpath, sizeof (sigpath), "%s%s", fname, suffix);
	fd_sig = rspamd_file_xopen (sigpath, O_RDONLY, 0, TRUE);

	if (fd_sig == -1) {
		close (fd_input);
		rspamd_fprintf (stderr, "cannot open %s: %s\n", sigpath,
				strerror (errno));
		exit (EXIT_FAILURE);
	}

	map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd_input, 0);
	close (fd_input);

	if (map == MAP_FAILED) {
		close (fd_sig);
		rspamd_fprintf (stderr, "cannot open %s: %s\n", sigpath,
				strerror (errno));
		exit (EXIT_FAILURE);
	}

	g_assert (fstat (fd_sig, &st_sig) != -1);

	if (st_sig.st_size != rspamd_cryptobox_signature_bytes (mode)) {
		close (fd_sig);
		rspamd_fprintf (stderr, "invalid signature size %s: %ud\n", fname,
				(guint)st_sig.st_size);
		munmap (map, st.st_size);
		exit (EXIT_FAILURE);
	}

	map_sig = mmap (NULL, st_sig.st_size, PROT_READ, MAP_SHARED, fd_sig, 0);
	close (fd_sig);

	if (map_sig == MAP_FAILED) {
		munmap (map, st.st_size);
		rspamd_fprintf (stderr, "cannot map %s: %s\n", sigpath,
				strerror (errno));
		exit (EXIT_FAILURE);
	}

	ret = rspamd_cryptobox_verify (map_sig, st_sig.st_size,
			map, st.st_size, pk, mode);
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
rspamadm_signtool (gint argc, gchar **argv, const struct rspamadm_command *cmd)
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
		g_option_context_free (context);
		exit (EXIT_FAILURE);
	}

	g_option_context_free (context);

	if (openssl) {
		mode = RSPAMD_CRYPTOBOX_MODE_NIST;
	}

	if (verify && (!pubkey && !pubkey_file)) {
		rspamd_fprintf (stderr, "no pubkey for verification\n");
		exit (EXIT_FAILURE);
	}
	else if (!verify && (!keypair_file)) {
		rspamd_fprintf (stderr, "no keypair for signing\n");
		exit (EXIT_FAILURE);
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
				exit (EXIT_FAILURE);
			}

			g_assert (fstat (fd, &st) != -1);
			fsize = st.st_size;
			flen = fsize;
			map = mmap (NULL, fsize, PROT_READ, MAP_SHARED, fd, 0);
			close (fd);

			if (map == MAP_FAILED) {
				rspamd_fprintf (stderr, "cannot read %s: %s\n", pubkey_file,
						strerror (errno));
				exit (EXIT_FAILURE);
			}

			/* XXX: assume base32 pubkey now */
			while (flen > 0 && g_ascii_isspace (map[flen - 1])) {
				flen --;
			}

			pk = rspamd_pubkey_from_base32 (map, flen,
					RSPAMD_KEYPAIR_SIGN, mode);

			if (pk == NULL) {
				rspamd_fprintf (stderr, "bad size %s: %ud, %ud expected\n",
						pubkey_file,
						(guint)flen,
						rspamd_cryptobox_pk_sig_bytes (mode));
				exit (EXIT_FAILURE);
			}

			munmap (map, fsize);
		}
		else {
			pk = rspamd_pubkey_from_base32 (pubkey, strlen (pubkey),
								RSPAMD_KEYPAIR_SIGN, mode);

			if (pk == NULL) {
				rspamd_fprintf (stderr, "bad size %s: %ud, %ud expected\n",
						pubkey_file,
						(guint)strlen (pubkey),
						rspamd_cryptobox_pk_sig_bytes (mode));
				exit (EXIT_FAILURE);
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
			exit (EXIT_FAILURE);
		}

		ucl_parser_free (parser);

		kp = rspamd_keypair_from_ucl (top);

		if (kp == NULL) {
			rspamd_fprintf (stderr, "invalid signing key\n");
			exit (EXIT_FAILURE);
		}

		if (rspamd_keypair_type (kp) != RSPAMD_KEYPAIR_SIGN) {
			rspamd_fprintf (stderr, "unsuitable for signing key\n");
			exit (EXIT_FAILURE);
		}

		for (i = 1; i < argc; i++) {
			/* XXX: support cmd line signature */
			if (!rspamadm_sign_file (argv[i], kp)) {
				rspamd_keypair_unref (kp);
				exit (EXIT_FAILURE);
			}
		}

		rspamd_keypair_unref (kp);
	}
}
