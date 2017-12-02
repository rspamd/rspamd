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
#ifndef RSPAMD_RSPAMDADM_H
#define RSPAMD_RSPAMDADM_H

#include "config.h"
#include "ucl.h"

extern GHashTable *ucl_vars;

GQuark rspamadm_error (void);

typedef const gchar* (*rspamadm_help_func) (gboolean full_help);
typedef void (*rspamadm_run_func) (gint argc, gchar **argv);
typedef void (*rspamadm_lua_exports_func) (gpointer lua_state);

#define RSPAMADM_FLAG_NOHELP (1 << 0)

struct rspamadm_command {
	const gchar *name;
	guint flags;
	rspamadm_help_func help;
	rspamadm_run_func run;
	rspamadm_lua_exports_func lua_subrs;
};

extern const struct rspamadm_command *commands[];
extern struct rspamadm_command help_command;

const struct rspamadm_command *rspamadm_search_command (const gchar *name);

gboolean rspamadm_execute_lua_ucl_subr (gpointer L, gint argc, gchar **argv,
		const ucl_object_t *res, const gchar *script_name);

#endif
