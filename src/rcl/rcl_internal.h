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

#ifndef RCL_INTERNAL_H_
#define RCL_INTERNAL_H_

#include "rcl.h"
#include "utlist.h"

/**
 * @file rcl_internal.h
 * Internal structures and functions of RCL library
 */

#define RCL_ERROR rcl_error_quark ()
static inline GQuark
rcl_error_quark (void)
{
	return g_quark_from_static_string ("rcl-error-quark");
}

enum rspamd_cl_parser_state {
	RSPAMD_RCL_STATE_INIT = 0,
	RSPAMD_RCL_STATE_OBJECT,
	RSPAMD_RCL_STATE_ARRAY,
	RSPAMD_RCL_STATE_KEY,
	RSPAMD_RCL_STATE_VALUE,
	RSPAMD_RCL_STATE_SCOMMENT,
	RSPAMD_RCL_STATE_MCOMMENT,
	RSPAMD_RCL_STATE_MACRO_NAME,
	RSPAMD_RCL_STATE_MACRO,
	RSPAMD_RCL_STATE_ERROR
};

struct rspamd_cl_macro {
	gchar *name;
	rspamd_cl_macro_handler handler;
	gpointer ud;
	UT_hash_handle hh;
};

struct rspamd_cl_stack {
	rspamd_cl_object_t *obj;
	struct rspamd_cl_stack *next;
};

struct rspamd_cl_chunk {
	const guchar *begin;
	const guchar *end;
	const guchar *pos;
	gsize remain;
	guint line;
	guint column;
	struct rspamd_cl_chunk *next;
};

struct rspamd_cl_parser {
	enum rspamd_cl_parser_state state;
	enum rspamd_cl_parser_state prev_state;
	rspamd_cl_object_t *top_obj;
	rspamd_cl_object_t *cur_obj;
	struct rspamd_cl_macro *macroes;
	struct rspamd_cl_stack *stack;
	struct rspamd_cl_chunk *chunks;
};

/**
 * Unescape json string inplace
 * @param str
 */
void rspamd_cl_unescape_json_string (gchar *str);

#endif /* RCL_INTERNAL_H_ */
