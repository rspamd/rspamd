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
#include "util.h"
#include "ottery.h"
#include "cryptobox.h"
#include "rspamd.h"
#include "rspamadm.h"
#include "unix-std.h"

static void rspamadm_pw (gint argc, gchar **argv,
						 const struct rspamadm_command *cmd);
static const char *rspamadm_pw_help (gboolean full_help,
									 const struct rspamadm_command *cmd);
static void rspamadm_pw_lua_subrs (gpointer pL);

static gboolean do_encrypt = FALSE;
static gboolean do_check = FALSE;
static gboolean quiet = FALSE;
static gboolean list = FALSE;
static gchar *type = "catena";
static gchar *password = NULL;

struct rspamadm_command pw_command = {
	.name = "pw",
	.flags = 0,
	.help = rspamadm_pw_help,
	.run = rspamadm_pw,
	.lua_subrs = rspamadm_pw_lua_subrs,
};

static GOptionEntry entries[] = {
		{"encrypt", 'e', 0, G_OPTION_ARG_NONE, &do_encrypt,
				"Encrypt password", NULL},
		{"check", 'c', 0, G_OPTION_ARG_NONE, &do_check,
				"Check password", NULL},
		{"quiet", 'q', 0, G_OPTION_ARG_NONE, &quiet,
				"Suppress output", NULL},
		{"password", 'p', 0, G_OPTION_ARG_STRING, &password,
				"Input password", NULL},
		{"type", 't', 0, G_OPTION_ARG_STRING, &type,
				"PBKDF type", NULL},
		{"list", 'l', 0, G_OPTION_ARG_NONE, &list,
				"List available algorithms", NULL},
		{NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_pw_help (gboolean full_help, const struct rspamadm_command *cmd)
{
	const char *help_str;

	if (full_help) {
		help_str = "Manipulate with passwords in rspamd\n\n"
				"Usage: rspamadm pw [command]\n"
				"Where commands are:\n\n"
				"--encrypt: encrypt password (this is a default command)\n"
				"--check: check encrypted password using encrypted password\n"
				"--list: list available pbkdf algorithms\n"
				"--type: select the specified pbkdf type\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Manage rspamd passwords";
	}

	return help_str;
}

static const struct rspamd_controller_pbkdf *
rspamadm_get_pbkdf (void)
{
	const struct rspamd_controller_pbkdf *pbkdf;
	guint i;

	for (i = 0; i < RSPAMD_PBKDF_ID_MAX - 1; i ++) {
		pbkdf = &pbkdf_list[i];

		if (strcmp (type, pbkdf->alias) == 0) {
			return pbkdf;
		}
	}

	rspamd_fprintf (stderr, "Unknown PKDF type: %s\n", type);
	exit (EXIT_FAILURE);

	return NULL;
}

static char *
rspamadm_pw_encrypt (char *password)
{
	const struct rspamd_controller_pbkdf *pbkdf;
	guchar *salt, *key;
	gchar *encoded_salt, *encoded_key;
	GString *result;
	gsize plen;

	pbkdf = rspamadm_get_pbkdf ();
	g_assert (pbkdf != NULL);

	if (password == NULL) {
		plen = 8192;
		password = g_malloc0 (plen);
		plen = rspamd_read_passphrase (password, plen, 0, NULL);
	}
	else {
		plen = strlen (password);
	}

	if (plen == 0) {
		fprintf (stderr, "Invalid password\n");
		exit (EXIT_FAILURE);
	}

	salt = g_alloca (pbkdf->salt_len);
	key = g_alloca (pbkdf->key_len);
	ottery_rand_bytes (salt, pbkdf->salt_len);
	/* Derive key */
	rspamd_cryptobox_pbkdf (password, strlen (password),
			salt, pbkdf->salt_len, key, pbkdf->key_len, pbkdf->complexity,
			pbkdf->type);

	encoded_salt = rspamd_encode_base32 (salt, pbkdf->salt_len, RSPAMD_BASE32_DEFAULT);
	encoded_key = rspamd_encode_base32 (key, pbkdf->key_len, RSPAMD_BASE32_DEFAULT);

	result = g_string_new ("");
	rspamd_printf_gstring (result, "$%d$%s$%s", pbkdf->id, encoded_salt,
			encoded_key);

	g_free (encoded_salt);
	g_free (encoded_key);
	rspamd_explicit_memzero (password, plen);
	g_free (password);
	password = result->str;
	g_string_free (result, FALSE); /* Not freeing memory */

	return password;
}

static const gchar *
rspamd_encrypted_password_get_str (const gchar *password, gsize skip,
		gsize *length)
{
	const gchar *str, *start, *end;
	gsize size;

	start = password + skip;
	end = start;
	size = 0;

	while (*end != '\0' && g_ascii_isalnum (*end)) {
		size++;
		end++;
	}

	if (size) {
		str = start;
		*length = size;
	}
	else {
		str = NULL;
	}

	return str;
}

static void
rspamadm_pw_check (void)
{
	const struct rspamd_controller_pbkdf *pbkdf = NULL;
	GIOChannel *in;
	GString *encrypted_pwd;
	const gchar *salt, *hash;
	const gchar *start, *end;
	guchar *salt_decoded, *key_decoded, *local_key;
	gsize salt_len, key_len, size;
	gchar test_password[8192];
	gsize plen, term = 0, i;
	gint id;
	gboolean ret = FALSE;

	if (password == NULL) {
		encrypted_pwd = g_string_new ("");
		in = g_io_channel_unix_new (STDIN_FILENO);
		rspamd_printf ("Enter encrypted password: ");
		fflush (stdout);
		g_io_channel_read_line_string (in, encrypted_pwd, &term, NULL);

		if (term != 0) {
			g_string_erase (encrypted_pwd, term, encrypted_pwd->len - term);
		}
		g_io_channel_unref (in);
	}
	else {
		encrypted_pwd = g_string_new (password);
	}

	if (encrypted_pwd->str[0] == '$') {
		/* Parse id */
		start = encrypted_pwd->str + 1;
		end = start;
		size = 0;

		while (*end != '\0' && g_ascii_isdigit (*end)) {
			size++;
			end++;
		}

		if (size > 0) {
			gchar *endptr;
			id = strtoul (start, &endptr, 10);

			if ((endptr == NULL || *endptr == *end)) {
				for (i = 0; i < RSPAMD_PBKDF_ID_MAX - 1; i ++) {
					pbkdf = &pbkdf_list[i];

					if (pbkdf->id == id) {
						ret = TRUE;
						break;
					}
				}
			}
		}
	}

	if (!ret) {
		rspamd_fprintf (stderr, "Invalid password format\n");
		exit (EXIT_FAILURE);
	}

	if (encrypted_pwd->len < pbkdf->salt_len + pbkdf->key_len + 3) {
		msg_err ("incorrect salt: password length: %z, must be at least %z characters",
				encrypted_pwd->len, pbkdf->salt_len);
		exit (EXIT_FAILURE);
	}

	/* get salt */
	salt = rspamd_encrypted_password_get_str (encrypted_pwd->str, 3, &salt_len);
	/* get hash */
	hash = rspamd_encrypted_password_get_str (encrypted_pwd->str,
			3 + salt_len + 1,
			&key_len);
	if (salt != NULL && hash != NULL) {

		/* decode salt */
		salt_decoded = rspamd_decode_base32 (salt, salt_len, &salt_len, RSPAMD_BASE32_DEFAULT);

		if (salt_decoded == NULL || salt_len != pbkdf->salt_len) {
			/* We have some unknown salt here */
			msg_err ("incorrect salt: %z, while %z expected",
					salt_len, pbkdf->salt_len);
			exit (EXIT_FAILURE);
		}

		key_decoded = rspamd_decode_base32 (hash, key_len, &key_len, RSPAMD_BASE32_DEFAULT);

		if (key_decoded == NULL || key_len != pbkdf->key_len) {
			/* We have some unknown salt here */
			msg_err ("incorrect key: %z, while %z expected",
					key_len, pbkdf->key_len);
			exit (EXIT_FAILURE);
		}

		plen = rspamd_read_passphrase (test_password, sizeof (test_password),
				0, NULL);
		if (plen == 0) {
			fprintf (stderr, "Invalid password\n");
			exit (EXIT_FAILURE);
		}

		local_key = g_alloca (pbkdf->key_len);
		rspamd_cryptobox_pbkdf (test_password, plen,
				salt_decoded, salt_len,
				local_key, pbkdf->key_len,
				pbkdf->complexity,
				pbkdf->type);
		rspamd_explicit_memzero (test_password, plen);

		if (!rspamd_constant_memcmp (key_decoded, local_key, pbkdf->key_len)) {
			if (!quiet) {
				rspamd_printf ("password incorrect\n");
			}
			exit (EXIT_FAILURE);
		}

		g_free (salt_decoded);
		g_free (key_decoded);
		g_string_free (encrypted_pwd, TRUE);
	}
	else {
		msg_err ("bad encrypted password format");
		exit (EXIT_FAILURE);
	}

	if (!quiet) {
		rspamd_printf ("password correct\n");
	}
}

static gint
rspamadm_pw_lua_encrypt (lua_State *L)
{
	const gchar *pw_in = NULL;
	gchar *ret, *tmp = NULL;

	if (lua_type (L, 1) == LUA_TSTRING) {
		pw_in = lua_tostring (L, 1);
		tmp = g_strdup (pw_in);
	}

	ret = rspamadm_pw_encrypt (tmp);

	lua_pushstring (L, ret);
	g_free (ret);

	return 1;
}


static void
rspamadm_pw_lua_subrs (gpointer pL)
{
	lua_State *L = pL;

	lua_pushstring (L, "pw_encrypt");
	lua_pushcfunction (L, rspamadm_pw_lua_encrypt);
	lua_settable (L, -3);
}

static void
rspamadm_alg_list (void)
{
	const struct rspamd_controller_pbkdf *pbkdf;
	guint i;

	for (i = 0; i < RSPAMD_PBKDF_ID_MAX - 1; i ++) {
		pbkdf = &pbkdf_list[i];

		rspamd_printf ("%s: %s - %s\n", pbkdf->alias, pbkdf->name,
				pbkdf->description);
	}
}

static void
rspamadm_pw (gint argc, gchar **argv, const struct rspamadm_command *cmd)
{
	GOptionContext *context;
	GError *error = NULL;

	context = g_option_context_new ("pw [--encrypt | --check] - manage rspamd passwords");
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

	if (list) {
		rspamadm_alg_list ();
		exit (EXIT_SUCCESS);
	}

	if (!do_encrypt && !do_check) {
		do_encrypt = TRUE;
	}

	if (do_encrypt) {
		gchar *encr = rspamadm_pw_encrypt (password);
		rspamd_printf ("%s\n", encr);
		g_free (encr);
	}
	else if (do_check) {
		rspamadm_pw_check ();
	}
}
