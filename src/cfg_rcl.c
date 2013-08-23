/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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

#include "cfg_rcl.h"
#include "main.h"

struct rspamd_rcl_section*
rspamd_rcl_config_init (void)
{
	struct rspamd_rcl_section *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_section));

	/* TODO: add all known rspamd sections here */

	return new;
}

struct rspamd_rcl_section *
rspamd_rcl_config_get_section (struct rspamd_rcl_section *top,
		const char *path)
{
	struct rspamd_rcl_section *cur, *found;
	char **path_components;
	gint ncomponents, i;


	if (path == NULL) {
		return top;
	}

	path_components = g_strsplit_set (path, "/", -1);
	ncomponents = g_strv_length (path_components);

	cur = top;
	for (i = 0; i < ncomponents; i ++) {
		if (cur == NULL) {
			g_strfreev (path_components);
			return NULL;
		}
		HASH_FIND_STR (cur, path_components[i], found);
		if (found == NULL) {
			g_strfreev (path_components);
			return NULL;
		}
		cur = found;
	}

	g_strfreev (path_components);
	return found;
}

gboolean
rspamd_read_rcl_config (struct rspamd_rcl_section *top,
		struct config_file *cfg, rspamd_cl_object_t *obj, GError **err)
{
	rspamd_cl_object_t *found;
	struct rspamd_rcl_section *cur, *tmp;

	if (obj->type != RSPAMD_CL_OBJECT) {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "top configuration must be an object");
		return FALSE;
	}

	/* Iterate over known sections and ignore unknown ones */
	HASH_ITER (hh, top, cur, tmp) {
		HASH_FIND_STR (obj->value.ov, cur->name, found);
		if (found == NULL) {
			if (cur->required) {
				g_set_error (err, CFG_RCL_ERROR, ENOENT, "required section %s is missing", cur->name);
				return FALSE;
			}
		}
		else {
			/* Check type */
			if (cur->strict_type) {
				if (cur->type != found->type) {
					g_set_error (err, CFG_RCL_ERROR, EINVAL, "object in section %s has invalid type", cur->name);
					return FALSE;
				}
			}
			if (!cur->handler (cfg, found, NULL, cur, err)) {
				return FALSE;
			}
		}
	}

	return TRUE;
}
