/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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
#include "prefix_tree.h"

static gint 
compare_prefixes (gconstpointer a, gconstpointer b, gpointer unused)
{
	const char *s1 = a, *s2 = b;

	return strcmp (s1, s2);
}

prefix_tree_t* 
prefix_tree_new (int levels)
{
	prefix_tree_t *result = NULL;

	if (levels <= 0) {
		return NULL;
	}
	/* Allocate tree */
	result = g_new (prefix_tree_t, 1);
	result->levels = levels;

	/* Allocate levels */
	result->nodes = g_new0 (prefix_tree_level_t, levels);
	
	return result;
}

static uintptr_t 
add_string_common (prefix_tree_t *tree, const char *input, int skip_levels, gboolean read_only, gboolean get_longest)
{
	int cur_level = 0, num;
	prefix_tree_level_t *cur;
	uintptr_t res = 0;
	char *prefix, tmp[256];
	const char *orig = input;

	if (tree == NULL) {
		return 0;
	}

	while (*input && cur_level < tree->levels) {
		cur = &tree->nodes[cur_level];
		if (*input >= 'A' && *input <= 'Z') {
			num = *input - 'A';
			if (cur_level < skip_levels) {
				input ++;
				cur_level ++;
				continue;
			}
			/* Go throught each level and check specified letter */
			if (cur->leafs[num].data == NULL) {
				/* Create new leaf */
				if (read_only) {
					return res;
				}
				else {
					/* Create new tree */
					prefix = g_malloc (cur_level * sizeof (char) + 1);
					rspamd_strlcpy (prefix, orig, cur_level + 1);
					cur->leafs[num].data = g_tree_new_full (compare_prefixes, NULL, g_free, NULL);
					g_tree_insert (cur->leafs[num].data, prefix, GUINT_TO_POINTER (1));
					return 1;
				}
			}
			else {
				/* Got some node, so check it */
				rspamd_strlcpy (tmp, orig, MIN (sizeof (tmp), cur_level + 1));
				if ((res = (uintptr_t)g_tree_lookup (cur->leafs[num].data, tmp)) != 0) {
					if (! read_only) {
						g_tree_insert (cur->leafs[num].data, g_strdup (tmp), GUINT_TO_POINTER (res + 1));
					}
					return res + 1;
				}
				else {
					if (! read_only) {
						g_tree_insert (cur->leafs[num].data, g_strdup (tmp), GUINT_TO_POINTER (1));
					}
					return 1;
				}
			}
		}
		input ++;
		cur_level ++;
	}

	return res;
}

uintptr_t 
add_string (prefix_tree_t *tree, const char *input, int skip_levels)
{
	return add_string_common (tree, input, skip_levels, FALSE, FALSE);
}

uintptr_t 
check_string (prefix_tree_t *tree, const char *input, int skip_levels)
{
	return add_string_common (tree, input, skip_levels, TRUE, FALSE);
}

uintptr_t 
add_string_longest (prefix_tree_t *tree, const char *input, int skip_levels)
{
	return add_string_common (tree, input, skip_levels, FALSE, TRUE);
}

uintptr_t 
check_string_longest (prefix_tree_t *tree, const char *input, int skip_levels)
{
	return add_string_common (tree, input, skip_levels, TRUE, TRUE);
}

void 
prefix_tree_free (prefix_tree_t *tree)
{
	int i, j;
	if (tree != NULL) {
		for (i = 0; i < tree->levels; i ++) {
			for (j = 0; j < LETTERS_NUMBER; j ++) {
				if (tree->nodes[i].leafs[j].data != NULL) {
					g_tree_destroy (tree->nodes[i].leafs[j].data);
				}
			}
		}
		g_free (tree->nodes);
		g_free (tree);
	}
}

gboolean 
save_prefix_tree (prefix_tree_t *tree, const char *filename)
{
	int fd, r;

	if ((fd = open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1) {
		return FALSE;
	}
	
	if ((r = write (fd, &tree->levels, sizeof (int))) == -1) {
		return FALSE;
	}

	if ((r = write (fd, tree->nodes, tree->levels * sizeof (prefix_tree_level_t))) == -1) {
		return FALSE;
	}

	close (fd);

	return TRUE;
}

prefix_tree_t* 
load_prefix_tree (const char *filename)
{
	int fd, r, levels;
	prefix_tree_t *tree;

	if ((fd = open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1) {
		return NULL;
	}
	

	if ((r = read (fd, &levels, sizeof (int))) == -1) {
		return NULL;
	}

	tree = prefix_tree_new (levels);

	if ((r = read (fd, tree->nodes, tree->levels * sizeof (prefix_tree_level_t))) == -1) {
		prefix_tree_free (tree);
		return NULL;
	}

	close (fd);

	return tree;
}
