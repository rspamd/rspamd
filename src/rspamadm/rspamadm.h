/*
 * Copyright (c) 2015, Vsevolod Stakhov
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

#ifndef RSPAMD_RSPAMDADM_H
#define RSPAMD_RSPAMDADM_H

#include "config.h"
#include "ucl.h"

extern GHashTable *ucl_vars;

GQuark rspamadm_error (void);

typedef const gchar* (*rspamadm_help_func) (gboolean full_help);
typedef void (*rspamadm_run_func) (gint argc, gchar **argv);

#define RSPAMADM_FLAG_NOHELP (1 << 0)

struct rspamadm_command {
	const gchar *name;
	guint flags;
	rspamadm_help_func help;
	rspamadm_run_func run;
};

extern const struct rspamadm_command *commands[];
extern struct rspamadm_command help_command;

const struct rspamadm_command *rspamadm_search_command (const gchar *name);

gboolean rspamadm_execute_lua_ucl_subr (gpointer L, gint argc, gchar **argv,
		const ucl_object_t *res, const gchar *script);

#endif
