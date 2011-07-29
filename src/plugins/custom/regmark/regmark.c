/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This plugin can be used as registration spam tester. Algorithm of its work:
 * 
 * 1) got string that identifies username, for example alexeyssad
 * 2) do metaphone normalization
 * 3) break this string into peaces: (al) (ex) (ey) (ss) (ad)
 * 4) go throught the tree and increment each node value
 * 5) find the biggest number of occurencies in some level of tree, for example:
 *                           (root)
 *                             |
 *            l1:  (al:4)   (hu:5) (tt:9)
 *            l2: (ex:4)   (is:5)  (hh:9)
 *            l3: (ey:3)   ....
 *            l4: (ss:2)
 *            l5: (ad:1)
 *  then if we have requirement of minimum l3 (6 symbols of original string) then the maximum number would be 3, so we
 *  got name alexey 3 times before.
 *
 *  So input line should look like this:
 *
 *  <string> level
 */

#include "config.h"
#include "cfg_file.h"
#include "main.h"
#include "metaphone.h"
#include "prefix_tree.h"

#define MAX_LEVELS 32

/* Exported functions */
void module_init (struct config_file *cfg);
void* before_connect (void);
gboolean parse_line (const char *line, size_t len, char **output, void *user_data);
void after_connect (char **output, char **log_line, void *user_data);
void module_fin (void);	

/* Internal variables */
static char *filename = NULL;
static prefix_tree_t *tree = NULL;

/* Implementation */

char                           *
get_module_opt (struct config_file *cfg, char *module_name, char *opt_name)
{
	GList                          *cur_opt;
	struct module_opt              *cur;

	cur_opt = g_hash_table_lookup (cfg->modules_opts, module_name);
	if (cur_opt == NULL) {
		return NULL;
	}

	while (cur_opt) {
		cur = cur_opt->data;
		if (strcmp (cur->param, opt_name) == 0) {
			return cur->value;
		}
		cur_opt = g_list_next (cur_opt);
	}

	return NULL;
}

void 
module_init (struct config_file *cfg)
{
	char *value;

	if (cfg && (value = get_module_opt (cfg, "ipmark", "file")) != NULL) {
		filename = g_strdup (value);
	}
	
	if (filename) {
		tree = load_prefix_tree (filename);
		if (! tree) {
			tree = prefix_tree_new (MAX_LEVELS);
		}
	}
	else {
		tree = prefix_tree_new (MAX_LEVELS);
	}

}

void *
before_connect (void)
{
	/* In fact we do not need any session data, so just return NULL */
	return NULL;
}

void
module_fin (void)
{
	if (filename) {
		save_prefix_tree (tree, filename);
		g_free (filename);
		filename = NULL;
	}
	if (tree) {
		prefix_tree_free (tree);
		tree = NULL;
	}
}

gboolean 
parse_line (const char *line, size_t len, char **output, void *user_data)
{
	const char *p = line;
	char *name, *metaname = NULL;
	int levels = 0;
	uintptr_t res = 0;

	while (p - line <= len) {
		if (g_ascii_isspace (*p) || p - line == len) {
			name = g_malloc (p - line + 1);
			rspamd_strlcpy (name, line, p - line + 1);
			if (metaphone (name, 0, &metaname)) {
				/* Skip spaces */
				while (p - line <= len && g_ascii_isspace (*p)) {
					p ++;
				}
				levels = strtol (p, NULL, 10);
				if (levels <= 0) {
					levels = strlen (metaname) / 2;
				}
				if (metaname) {
					res = add_string (tree, metaname, levels);
					*output = g_strdup_printf ("OK: %u" CRLF, (unsigned int)res);
					g_free (metaname);
					g_free (name);
					return TRUE;
				}
				g_free (metaname);
			}
			break;
		}
		p ++;
	}

	if (res == 0) {
		*output = g_strdup ("ERR" CRLF);
	}

	return TRUE;
}


void after_connect (char **output, char **log_line, void *user_data)
{
	/* Placeholder */
	return;
}
