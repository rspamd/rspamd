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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ucl.h"
#include "ucl_internal.h"
#include "ucl_chartable.h"
#ifdef HAVE_FLOAT_H
#include <float.h>
#endif
#ifdef HAVE_MATH_H
#include <math.h>
#endif

/**
 * @file ucl_emitter.c
 * Serialise UCL object to various of output formats
 */

static void ucl_emitter_common_elt (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool first, bool print_key, bool compact);

#define UCL_EMIT_TYPE_OPS(type)		\
	static void ucl_emit_ ## type ## _elt (struct ucl_emitter_context *ctx,	\
		const ucl_object_t *obj, bool first, bool print_key);	\
	static void ucl_emit_ ## type ## _start_obj (struct ucl_emitter_context *ctx,	\
		const ucl_object_t *obj, bool print_key);	\
	static void ucl_emit_ ## type## _start_array (struct ucl_emitter_context *ctx,	\
		const ucl_object_t *obj, bool print_key);	\
	static void ucl_emit_ ##type## _end_object (struct ucl_emitter_context *ctx,	\
		const ucl_object_t *obj);	\
	static void ucl_emit_ ##type## _end_array (struct ucl_emitter_context *ctx,	\
		const ucl_object_t *obj)

/*
 * JSON format operations
 */
UCL_EMIT_TYPE_OPS(json);
UCL_EMIT_TYPE_OPS(json_compact);
UCL_EMIT_TYPE_OPS(config);
UCL_EMIT_TYPE_OPS(yaml);
UCL_EMIT_TYPE_OPS(msgpack);

#define UCL_EMIT_TYPE_CONTENT(type) {	\
	.ucl_emitter_write_elt = ucl_emit_ ## type ## _elt,	\
	.ucl_emitter_start_object = ucl_emit_ ## type ##_start_obj,	\
	.ucl_emitter_start_array = ucl_emit_ ## type ##_start_array,	\
	.ucl_emitter_end_object = ucl_emit_ ## type ##_end_object,	\
	.ucl_emitter_end_array = ucl_emit_ ## type ##_end_array	\
}

static const struct ucl_emitter_operations ucl_standart_emitter_ops[] = {
	[UCL_EMIT_JSON] = UCL_EMIT_TYPE_CONTENT(json),
	[UCL_EMIT_JSON_COMPACT] = UCL_EMIT_TYPE_CONTENT(json_compact),
	[UCL_EMIT_CONFIG] = UCL_EMIT_TYPE_CONTENT(config),
	[UCL_EMIT_YAML] = UCL_EMIT_TYPE_CONTENT(yaml),
	[UCL_EMIT_MSGPACK] = UCL_EMIT_TYPE_CONTENT(msgpack)
};

/*
 * Utility to check whether we need a top object
 */
#define UCL_EMIT_IDENT_TOP_OBJ(ctx, obj) ((ctx)->top != (obj) || \
		((ctx)->id == UCL_EMIT_JSON_COMPACT || (ctx)->id == UCL_EMIT_JSON))


/**
 * Add tabulation to the output buffer
 * @param buf target buffer
 * @param tabs number of tabs to add
 */
static inline void
ucl_add_tabs (const struct ucl_emitter_functions *func, unsigned int tabs,
		bool compact)
{
	if (!compact && tabs > 0) {
		func->ucl_emitter_append_character (' ', tabs * 4, func->ud);
	}
}

/**
 * Print key for the element
 * @param ctx
 * @param obj
 */
static void
ucl_emitter_print_key (bool print_key, struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool compact)
{
	const struct ucl_emitter_functions *func = ctx->func;

	if (!print_key) {
		return;
	}

	if (ctx->id == UCL_EMIT_CONFIG) {
		if (obj->flags & UCL_OBJECT_NEED_KEY_ESCAPE) {
			ucl_elt_string_write_json (obj->key, obj->keylen, ctx);
		}
		else {
			func->ucl_emitter_append_len (obj->key, obj->keylen, func->ud);
		}

		if (obj->type != UCL_OBJECT && obj->type != UCL_ARRAY) {
			func->ucl_emitter_append_len (" = ", 3, func->ud);
		}
		else {
			func->ucl_emitter_append_character (' ', 1, func->ud);
		}
	}
	else if (ctx->id == UCL_EMIT_YAML) {
		if (obj->keylen > 0 && (obj->flags & UCL_OBJECT_NEED_KEY_ESCAPE)) {
			ucl_elt_string_write_json (obj->key, obj->keylen, ctx);
		}
		else if (obj->keylen > 0) {
			func->ucl_emitter_append_len (obj->key, obj->keylen, func->ud);
		}
		else {
			func->ucl_emitter_append_len ("null", 4, func->ud);
		}

		func->ucl_emitter_append_len (": ", 2, func->ud);
	}
	else {
		if (obj->keylen > 0) {
			ucl_elt_string_write_json (obj->key, obj->keylen, ctx);
		}
		else {
			func->ucl_emitter_append_len ("null", 4, func->ud);
		}

		if (compact) {
			func->ucl_emitter_append_character (':', 1, func->ud);
		}
		else {
			func->ucl_emitter_append_len (": ", 2, func->ud);
		}
	}
}

static void
ucl_emitter_finish_object (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool compact, bool is_array)
{
	const struct ucl_emitter_functions *func = ctx->func;

	if (ctx->id == UCL_EMIT_CONFIG && obj != ctx->top) {
		if (obj->type != UCL_OBJECT && obj->type != UCL_ARRAY) {
			if (!is_array) {
				/* Objects are split by ';' */
				func->ucl_emitter_append_len (";\n", 2, func->ud);
			}
			else {
				/* Use commas for arrays */
				func->ucl_emitter_append_len (",\n", 2, func->ud);
			}
		}
		else {
			func->ucl_emitter_append_character ('\n', 1, func->ud);
		}
	}
}

/**
 * End standard ucl object
 * @param ctx emitter context
 * @param compact compact flag
 */
static void
ucl_emitter_common_end_object (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool compact)
{
	const struct ucl_emitter_functions *func = ctx->func;

	if (UCL_EMIT_IDENT_TOP_OBJ(ctx, obj)) {
		ctx->indent --;
		if (compact || obj->len == 0) {
			func->ucl_emitter_append_character ('}', 1, func->ud);
		}
		else {
			if (ctx->id != UCL_EMIT_CONFIG) {
				/* newline is already added for this format */
				func->ucl_emitter_append_character ('\n', 1, func->ud);
			}
			ucl_add_tabs (func, ctx->indent, compact);
			func->ucl_emitter_append_character ('}', 1, func->ud);
		}
	}

	ucl_emitter_finish_object (ctx, obj, compact, false);
}

/**
 * End standard ucl array
 * @param ctx emitter context
 * @param compact compact flag
 */
static void
ucl_emitter_common_end_array (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool compact)
{
	const struct ucl_emitter_functions *func = ctx->func;

	ctx->indent --;
	if (compact || obj->len == 0) {
		func->ucl_emitter_append_character (']', 1, func->ud);
	}
	else {
		if (ctx->id != UCL_EMIT_CONFIG) {
			/* newline is already added for this format */
			func->ucl_emitter_append_character ('\n', 1, func->ud);
		}
		ucl_add_tabs (func, ctx->indent, compact);
		func->ucl_emitter_append_character (']', 1, func->ud);
	}

	ucl_emitter_finish_object (ctx, obj, compact, true);
}

/**
 * Start emit standard UCL array
 * @param ctx emitter context
 * @param obj object to write
 * @param compact compact flag
 */
static void
ucl_emitter_common_start_array (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool print_key, bool compact)
{
	const ucl_object_t *cur;
	ucl_object_iter_t iter = NULL;
	const struct ucl_emitter_functions *func = ctx->func;
	bool first = true;

	ucl_emitter_print_key (print_key, ctx, obj, compact);

	if (compact || obj->len == 0) {
		func->ucl_emitter_append_character ('[', 1, func->ud);
	}
	else {
		func->ucl_emitter_append_len ("[\n", 2, func->ud);
	}

	ctx->indent ++;

	if (obj->type == UCL_ARRAY) {
		/* explicit array */
		while ((cur = ucl_object_iterate (obj, &iter, true)) != NULL) {
			ucl_emitter_common_elt (ctx, cur, first, false, compact);
			first = false;
		}
	}
	else {
		/* implicit array */
		cur = obj;
		while (cur) {
			ucl_emitter_common_elt (ctx, cur, first, false, compact);
			first = false;
			cur = cur->next;
		}
	}
}

/**
 * Start emit standard UCL object
 * @param ctx emitter context
 * @param obj object to write
 * @param compact compact flag
 */
static void
ucl_emitter_common_start_object (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool print_key, bool compact)
{
	ucl_hash_iter_t it = NULL;
	const ucl_object_t *cur, *elt;
	const struct ucl_emitter_functions *func = ctx->func;
	bool first = true;

	ucl_emitter_print_key (print_key, ctx, obj, compact);
	/*
	 * Print <ident_level>{
	 * <ident_level + 1><object content>
	 */
	if (UCL_EMIT_IDENT_TOP_OBJ(ctx, obj)) {
		if (compact || obj->len == 0) {
			func->ucl_emitter_append_character ('{', 1, func->ud);
		}
		else {
			func->ucl_emitter_append_len ("{\n", 2, func->ud);
		}
		ctx->indent ++;
	}

	while ((cur = ucl_hash_iterate (obj->value.ov, &it))) {

		if (ctx->id == UCL_EMIT_CONFIG) {
			LL_FOREACH (cur, elt) {
				ucl_emitter_common_elt (ctx, elt, first, true, compact);
			}
		}
		else {
			/* Expand implicit arrays */
			if (cur->next != NULL) {
				if (!first) {
					if (compact) {
						func->ucl_emitter_append_character (',', 1, func->ud);
					}
					else {
						func->ucl_emitter_append_len (",\n", 2, func->ud);
					}
				}
				ucl_add_tabs (func, ctx->indent, compact);
				ucl_emitter_common_start_array (ctx, cur, true, compact);
				ucl_emitter_common_end_array (ctx, cur, compact);
			}
			else {
				ucl_emitter_common_elt (ctx, cur, first, true, compact);
			}
		}

		first = false;
	}
}

/**
 * Common choice of object emitting
 * @param ctx emitter context
 * @param obj object to print
 * @param first flag to mark the first element
 * @param print_key print key of an object
 * @param compact compact output
 */
static void
ucl_emitter_common_elt (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool first, bool print_key, bool compact)
{
	const struct ucl_emitter_functions *func = ctx->func;
	bool flag;
	struct ucl_object_userdata *ud;
	const ucl_object_t *comment = NULL, *cur_comment;
	const char *ud_out = "";

	if (ctx->id != UCL_EMIT_CONFIG && !first) {
		if (compact) {
			func->ucl_emitter_append_character (',', 1, func->ud);
		}
		else {
			if (ctx->id == UCL_EMIT_YAML && ctx->indent == 0) {
				func->ucl_emitter_append_len ("\n", 1, func->ud);
			} else {
				func->ucl_emitter_append_len (",\n", 2, func->ud);
			}
		}
	}

	ucl_add_tabs (func, ctx->indent, compact);

	if (ctx->comments && ctx->id == UCL_EMIT_CONFIG) {
		comment = ucl_object_lookup_len (ctx->comments, (const char *)&obj,
				sizeof (void *));

		if (comment) {
			if (!(comment->flags & UCL_OBJECT_INHERITED)) {
				DL_FOREACH (comment, cur_comment) {
					func->ucl_emitter_append_len (cur_comment->value.sv,
							cur_comment->len,
							func->ud);
					func->ucl_emitter_append_character ('\n', 1, func->ud);
					ucl_add_tabs (func, ctx->indent, compact);
				}

				comment = NULL;
			}
		}
	}

	switch (obj->type) {
	case UCL_INT:
		ucl_emitter_print_key (print_key, ctx, obj, compact);
		func->ucl_emitter_append_int (ucl_object_toint (obj), func->ud);
		ucl_emitter_finish_object (ctx, obj, compact, !print_key);
		break;
	case UCL_FLOAT:
	case UCL_TIME:
		ucl_emitter_print_key (print_key, ctx, obj, compact);
		func->ucl_emitter_append_double (ucl_object_todouble (obj), func->ud);
		ucl_emitter_finish_object (ctx, obj, compact, !print_key);
		break;
	case UCL_BOOLEAN:
		ucl_emitter_print_key (print_key, ctx, obj, compact);
		flag = ucl_object_toboolean (obj);
		if (flag) {
			func->ucl_emitter_append_len ("true", 4, func->ud);
		}
		else {
			func->ucl_emitter_append_len ("false", 5, func->ud);
		}
		ucl_emitter_finish_object (ctx, obj, compact, !print_key);
		break;
	case UCL_STRING:
		ucl_emitter_print_key (print_key, ctx, obj, compact);
		if (ctx->id == UCL_EMIT_CONFIG) {
			if (ucl_maybe_long_string (obj)) {
				ucl_elt_string_write_multiline (obj->value.sv, obj->len, ctx);
			} else {
				if (obj->flags & UCL_OBJECT_SQUOTED) {
					ucl_elt_string_write_squoted (obj->value.sv, obj->len, ctx);
				} else {
					ucl_elt_string_write_json (obj->value.sv, obj->len, ctx);
				}
			}
		}
		else {
			ucl_elt_string_write_json (obj->value.sv, obj->len, ctx);
		}
		ucl_emitter_finish_object (ctx, obj, compact, !print_key);
		break;
	case UCL_NULL:
		ucl_emitter_print_key (print_key, ctx, obj, compact);
		func->ucl_emitter_append_len ("null", 4, func->ud);
		ucl_emitter_finish_object (ctx, obj, compact, !print_key);
		break;
	case UCL_OBJECT:
		ucl_emitter_common_start_object (ctx, obj, print_key, compact);
		ucl_emitter_common_end_object (ctx, obj, compact);
		break;
	case UCL_ARRAY:
		ucl_emitter_common_start_array (ctx, obj, print_key, compact);
		ucl_emitter_common_end_array (ctx, obj, compact);
		break;
	case UCL_USERDATA:
		ud = (struct ucl_object_userdata *)obj;
		ucl_emitter_print_key (print_key, ctx, obj, compact);
		if (ud->emitter) {
			ud_out = ud->emitter (obj->value.ud);
			if (ud_out == NULL) {
				ud_out = "null";
			}
		}
		ucl_elt_string_write_json (ud_out, strlen (ud_out), ctx);
		ucl_emitter_finish_object (ctx, obj, compact, !print_key);
		break;
	}

	if (comment) {
		DL_FOREACH (comment, cur_comment) {
			func->ucl_emitter_append_len (cur_comment->value.sv,
					cur_comment->len,
					func->ud);
			func->ucl_emitter_append_character ('\n', 1, func->ud);

			if (cur_comment->next) {
				ucl_add_tabs (func, ctx->indent, compact);
			}
		}
	}
}

/*
 * Specific standard implementations of the emitter functions
 */
#define UCL_EMIT_TYPE_IMPL(type, compact)		\
	static void ucl_emit_ ## type ## _elt (struct ucl_emitter_context *ctx,	\
		const ucl_object_t *obj, bool first, bool print_key) {	\
		ucl_emitter_common_elt (ctx, obj, first, print_key, (compact));	\
	}	\
	static void ucl_emit_ ## type ## _start_obj (struct ucl_emitter_context *ctx,	\
		const ucl_object_t *obj, bool print_key) {	\
		ucl_emitter_common_start_object (ctx, obj, print_key, (compact));	\
	}	\
	static void ucl_emit_ ## type## _start_array (struct ucl_emitter_context *ctx,	\
		const ucl_object_t *obj, bool print_key) {	\
		ucl_emitter_common_start_array (ctx, obj, print_key, (compact));	\
	}	\
	static void ucl_emit_ ##type## _end_object (struct ucl_emitter_context *ctx,	\
		const ucl_object_t *obj) {	\
		ucl_emitter_common_end_object (ctx, obj, (compact));	\
	}	\
	static void ucl_emit_ ##type## _end_array (struct ucl_emitter_context *ctx,	\
		const ucl_object_t *obj) {	\
		ucl_emitter_common_end_array (ctx, obj, (compact));	\
	}

UCL_EMIT_TYPE_IMPL(json, false)
UCL_EMIT_TYPE_IMPL(json_compact, true)
UCL_EMIT_TYPE_IMPL(config, false)
UCL_EMIT_TYPE_IMPL(yaml, false)

static void
ucl_emit_msgpack_elt (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool first, bool print_key)
{
	ucl_object_iter_t it;
	struct ucl_object_userdata *ud;
	const char *ud_out;
	const ucl_object_t *cur, *celt;

	switch (obj->type) {
	case UCL_INT:
		ucl_emitter_print_key_msgpack (print_key, ctx, obj);
		ucl_emitter_print_int_msgpack (ctx, ucl_object_toint (obj));
		break;

	case UCL_FLOAT:
	case UCL_TIME:
		ucl_emitter_print_key_msgpack (print_key, ctx, obj);
		ucl_emitter_print_double_msgpack (ctx, ucl_object_todouble (obj));
		break;

	case UCL_BOOLEAN:
		ucl_emitter_print_key_msgpack (print_key, ctx, obj);
		ucl_emitter_print_bool_msgpack (ctx, ucl_object_toboolean (obj));
		break;

	case UCL_STRING:
		ucl_emitter_print_key_msgpack (print_key, ctx, obj);

		if (obj->flags & UCL_OBJECT_BINARY) {
			ucl_emitter_print_binary_string_msgpack (ctx, obj->value.sv,
					obj->len);
		}
		else {
			ucl_emitter_print_string_msgpack (ctx, obj->value.sv, obj->len);
		}
		break;

	case UCL_NULL:
		ucl_emitter_print_key_msgpack (print_key, ctx, obj);
		ucl_emitter_print_null_msgpack (ctx);
		break;

	case UCL_OBJECT:
		ucl_emitter_print_key_msgpack (print_key, ctx, obj);
		ucl_emit_msgpack_start_obj (ctx, obj, print_key);
		it = NULL;

		while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
			LL_FOREACH (cur, celt) {
				ucl_emit_msgpack_elt (ctx, celt, false, true);
				/* XXX:
				 * in msgpack the length of objects is encoded within a single elt
				 * so in case of multi-value keys we are using merely the first
				 * element ignoring others
				 */
				break;
			}
		}

		break;

	case UCL_ARRAY:
		ucl_emitter_print_key_msgpack (print_key, ctx, obj);
		ucl_emit_msgpack_start_array (ctx, obj, print_key);
		it = NULL;

		while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
			ucl_emit_msgpack_elt (ctx, cur, false, false);
		}

		break;

	case UCL_USERDATA:
		ud = (struct ucl_object_userdata *)obj;
		ucl_emitter_print_key_msgpack (print_key, ctx, obj);

		if (ud->emitter) {
			ud_out = ud->emitter (obj->value.ud);
			if (ud_out == NULL) {
				ud_out = "null";
			}
		}
		ucl_emitter_print_string_msgpack (ctx, obj->value.sv, obj->len);
		break;
	}
}

static void
ucl_emit_msgpack_start_obj (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool print_key)
{
	ucl_emitter_print_object_msgpack (ctx, obj->len);
}

static void
ucl_emit_msgpack_start_array (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj, bool print_key)
{
	ucl_emitter_print_array_msgpack (ctx, obj->len);
}

static void
ucl_emit_msgpack_end_object (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj)
{

}

static void
ucl_emit_msgpack_end_array (struct ucl_emitter_context *ctx,
		const ucl_object_t *obj)
{

}

unsigned char *
ucl_object_emit (const ucl_object_t *obj, enum ucl_emitter emit_type)
{
	return ucl_object_emit_len (obj, emit_type, NULL);
}

unsigned char *
ucl_object_emit_len (const ucl_object_t *obj, enum ucl_emitter emit_type,
		size_t *outlen)
{
	unsigned char *res = NULL;
	struct ucl_emitter_functions *func;
	UT_string *s;

	if (obj == NULL) {
		return NULL;
	}

	func = ucl_object_emit_memory_funcs ((void **)&res);

	if (func != NULL) {
		s = func->ud;
		ucl_object_emit_full (obj, emit_type, func, NULL);

		if (outlen != NULL) {
			*outlen = s->i;
		}

		ucl_object_emit_funcs_free (func);
	}

	return res;
}

bool
ucl_object_emit_full (const ucl_object_t *obj, enum ucl_emitter emit_type,
		struct ucl_emitter_functions *emitter,
		const ucl_object_t *comments)
{
	const struct ucl_emitter_context *ctx;
	struct ucl_emitter_context my_ctx;
	bool res = false;

	ctx = ucl_emit_get_standard_context (emit_type);
	if (ctx != NULL) {
		memcpy (&my_ctx, ctx, sizeof (my_ctx));
		my_ctx.func = emitter;
		my_ctx.indent = 0;
		my_ctx.top = obj;
		my_ctx.comments = comments;

		my_ctx.ops->ucl_emitter_write_elt (&my_ctx, obj, true, false);
		res = true;
	}

	return res;
}

static const struct ucl_emitter_context ucl_standard_emitters[] = {
		[UCL_EMIT_JSON] = {
				.name = "json",
				.id = UCL_EMIT_JSON,
				.func = NULL,
				.ops = &ucl_standart_emitter_ops[UCL_EMIT_JSON]
		},
		[UCL_EMIT_JSON_COMPACT] = {
				.name = "json_compact",
				.id = UCL_EMIT_JSON_COMPACT,
				.func = NULL,
				.ops = &ucl_standart_emitter_ops[UCL_EMIT_JSON_COMPACT]
		},
		[UCL_EMIT_CONFIG] = {
				.name = "config",
				.id = UCL_EMIT_CONFIG,
				.func = NULL,
				.ops = &ucl_standart_emitter_ops[UCL_EMIT_CONFIG]
		},
		[UCL_EMIT_YAML] = {
				.name = "yaml",
				.id = UCL_EMIT_YAML,
				.func = NULL,
				.ops = &ucl_standart_emitter_ops[UCL_EMIT_YAML]
		},
		[UCL_EMIT_MSGPACK] = {
				.name = "msgpack",
				.id = UCL_EMIT_MSGPACK,
				.func = NULL,
				.ops = &ucl_standart_emitter_ops[UCL_EMIT_MSGPACK]
		}
};

/**
 * Get standard emitter context for a specified emit_type
 * @param emit_type type of emitter
 * @return context or NULL if input is invalid
 */
const struct ucl_emitter_context *
ucl_emit_get_standard_context (enum ucl_emitter emit_type)
{
	if (emit_type >= UCL_EMIT_JSON && emit_type < UCL_EMIT_MAX) {
		return &ucl_standard_emitters[emit_type];
	}

	return NULL;
}

/**
 * Serialise string
 * @param str string to emit
 * @param buf target buffer
 */
void
ucl_elt_string_write_json (const char *str, size_t size,
						   struct ucl_emitter_context *ctx)
{
	const char *p = str, *c = str;
	size_t len = 0;
	const struct ucl_emitter_functions *func = ctx->func;

	func->ucl_emitter_append_character ('"', 1, func->ud);

	while (size) {
		if (ucl_test_character (*p, (UCL_CHARACTER_JSON_UNSAFE|
									 UCL_CHARACTER_DENIED|
									 UCL_CHARACTER_WHITESPACE_UNSAFE))) {
			if (len > 0) {
				func->ucl_emitter_append_len (c, len, func->ud);
			}
			switch (*p) {
			case '\0':
				func->ucl_emitter_append_len ("\\u0000", 6, func->ud);
				break;
			case '\n':
				func->ucl_emitter_append_len ("\\n", 2, func->ud);
				break;
			case '\r':
				func->ucl_emitter_append_len ("\\r", 2, func->ud);
				break;
			case '\b':
				func->ucl_emitter_append_len ("\\b", 2, func->ud);
				break;
			case '\t':
				func->ucl_emitter_append_len ("\\t", 2, func->ud);
				break;
			case '\f':
				func->ucl_emitter_append_len ("\\f", 2, func->ud);
				break;
			case '\v':
				func->ucl_emitter_append_len ("\\u000B", 6, func->ud);
				break;
			case '\\':
				func->ucl_emitter_append_len ("\\\\", 2, func->ud);
				break;
			case ' ':
				func->ucl_emitter_append_character (' ', 1, func->ud);
				break;
			case '"':
				func->ucl_emitter_append_len ("\\\"", 2, func->ud);
				break;
			default:
				/* Emit unicode unknown character */
				func->ucl_emitter_append_len ("\\uFFFD", 6, func->ud);
				break;
			}
			len = 0;
			c = ++p;
		}
		else {
			p ++;
			len ++;
		}
		size --;
	}

	if (len > 0) {
		func->ucl_emitter_append_len (c, len, func->ud);
	}

	func->ucl_emitter_append_character ('"', 1, func->ud);
}

void
ucl_elt_string_write_squoted (const char *str, size_t size,
							  struct ucl_emitter_context *ctx)
{
	const char *p = str, *c = str;
	size_t len = 0;
	const struct ucl_emitter_functions *func = ctx->func;

	func->ucl_emitter_append_character ('\'', 1, func->ud);

	while (size) {
		if (*p == '\'') {
			if (len > 0) {
				func->ucl_emitter_append_len (c, len, func->ud);
			}

			len = 0;
			c = ++p;
			func->ucl_emitter_append_len ("\\\'", 2, func->ud);
		}
		else {
			p ++;
			len ++;
		}
		size --;
	}

	if (len > 0) {
		func->ucl_emitter_append_len (c, len, func->ud);
	}

	func->ucl_emitter_append_character ('\'', 1, func->ud);
}

void
ucl_elt_string_write_multiline (const char *str, size_t size,
								struct ucl_emitter_context *ctx)
{
	const struct ucl_emitter_functions *func = ctx->func;

	func->ucl_emitter_append_len ("<<EOD\n", sizeof ("<<EOD\n") - 1, func->ud);
	func->ucl_emitter_append_len (str, size, func->ud);
	func->ucl_emitter_append_len ("\nEOD", sizeof ("\nEOD") - 1, func->ud);
}

/*
 * Generic utstring output
 */
static int
ucl_utstring_append_character (unsigned char c, size_t len, void *ud)
{
	UT_string *buf = ud;

	if (len == 1) {
		utstring_append_c (buf, c);
	}
	else {
		utstring_reserve (buf, len + 1);
		memset (&buf->d[buf->i], c, len);
		buf->i += len;
		buf->d[buf->i] = '\0';
	}

	return 0;
}

static int
ucl_utstring_append_len (const unsigned char *str, size_t len, void *ud)
{
	UT_string *buf = ud;

	utstring_append_len (buf, str, len);

	return 0;
}

static int
ucl_utstring_append_int (int64_t val, void *ud)
{
	UT_string *buf = ud;

	utstring_printf (buf, "%jd", (intmax_t)val);
	return 0;
}

static int
ucl_utstring_append_double (double val, void *ud)
{
	UT_string *buf = ud;
	const double delta = 0.0000001;

	if (val == (double)(int)val) {
		utstring_printf (buf, "%.1lf", val);
	}
	else if (fabs (val - (double)(int)val) < delta) {
		/* Write at maximum precision */
		utstring_printf (buf, "%.*lg", DBL_DIG, val);
	}
	else {
		utstring_printf (buf, "%lf", val);
	}

	return 0;
}

/*
 * Generic file output
 */
static int
ucl_file_append_character (unsigned char c, size_t len, void *ud)
{
	FILE *fp = ud;

	while (len --) {
		fputc (c, fp);
	}

	return 0;
}

static int
ucl_file_append_len (const unsigned char *str, size_t len, void *ud)
{
	FILE *fp = ud;

	fwrite (str, len, 1, fp);

	return 0;
}

static int
ucl_file_append_int (int64_t val, void *ud)
{
	FILE *fp = ud;

	fprintf (fp, "%jd", (intmax_t)val);

	return 0;
}

static int
ucl_file_append_double (double val, void *ud)
{
	FILE *fp = ud;
	const double delta = 0.0000001;

	if (val == (double)(int)val) {
		fprintf (fp, "%.1lf", val);
	}
	else if (fabs (val - (double)(int)val) < delta) {
		/* Write at maximum precision */
		fprintf (fp, "%.*lg", DBL_DIG, val);
	}
	else {
		fprintf (fp, "%lf", val);
	}

	return 0;
}

/*
 * Generic file descriptor writing functions
 */
static int
ucl_fd_append_character (unsigned char c, size_t len, void *ud)
{
	int fd = *(int *)ud;
	unsigned char *buf;

	if (len == 1) {
		return write (fd, &c, 1);
	}
	else {
		buf = malloc (len);
		if (buf == NULL) {
			/* Fallback */
			while (len --) {
				if (write (fd, &c, 1) == -1) {
					return -1;
				}
			}
		}
		else {
			memset (buf, c, len);
			if (write (fd, buf, len) == -1) {
				free(buf);
				return -1;
			}
			free (buf);
		}
	}

	return 0;
}

static int
ucl_fd_append_len (const unsigned char *str, size_t len, void *ud)
{
	int fd = *(int *)ud;

	return write (fd, str, len);
}

static int
ucl_fd_append_int (int64_t val, void *ud)
{
	int fd = *(int *)ud;
	char intbuf[64];

	snprintf (intbuf, sizeof (intbuf), "%jd", (intmax_t)val);
	return write (fd, intbuf, strlen (intbuf));
}

static int
ucl_fd_append_double (double val, void *ud)
{
	int fd = *(int *)ud;
	const double delta = 0.0000001;
	char nbuf[64];

	if (val == (double)(int)val) {
		snprintf (nbuf, sizeof (nbuf), "%.1lf", val);
	}
	else if (fabs (val - (double)(int)val) < delta) {
		/* Write at maximum precision */
		snprintf (nbuf, sizeof (nbuf), "%.*lg", DBL_DIG, val);
	}
	else {
		snprintf (nbuf, sizeof (nbuf), "%lf", val);
	}

	return write (fd, nbuf, strlen (nbuf));
}

struct ucl_emitter_functions*
ucl_object_emit_memory_funcs (void **pmem)
{
	struct ucl_emitter_functions *f;
	UT_string *s;

	f = calloc (1, sizeof (*f));

	if (f != NULL) {
		f->ucl_emitter_append_character = ucl_utstring_append_character;
		f->ucl_emitter_append_double = ucl_utstring_append_double;
		f->ucl_emitter_append_int = ucl_utstring_append_int;
		f->ucl_emitter_append_len = ucl_utstring_append_len;
		f->ucl_emitter_free_func = free;
		utstring_new (s);
		f->ud = s;
		*pmem = s->d;
		s->pd = pmem;
	}

	return f;
}

struct ucl_emitter_functions*
ucl_object_emit_file_funcs (FILE *fp)
{
	struct ucl_emitter_functions *f;

	f = calloc (1, sizeof (*f));

	if (f != NULL) {
		f->ucl_emitter_append_character = ucl_file_append_character;
		f->ucl_emitter_append_double = ucl_file_append_double;
		f->ucl_emitter_append_int = ucl_file_append_int;
		f->ucl_emitter_append_len = ucl_file_append_len;
		f->ucl_emitter_free_func = NULL;
		f->ud = fp;
	}

	return f;
}

struct ucl_emitter_functions*
ucl_object_emit_fd_funcs (int fd)
{
	struct ucl_emitter_functions *f;
	int *ip;

	f = calloc (1, sizeof (*f));

	if (f != NULL) {
		ip = malloc (sizeof (fd));
		if (ip == NULL) {
			free (f);
			return NULL;
		}

		memcpy (ip, &fd, sizeof (fd));
		f->ucl_emitter_append_character = ucl_fd_append_character;
		f->ucl_emitter_append_double = ucl_fd_append_double;
		f->ucl_emitter_append_int = ucl_fd_append_int;
		f->ucl_emitter_append_len = ucl_fd_append_len;
		f->ucl_emitter_free_func = free;
		f->ud = ip;
	}

	return f;
}

void
ucl_object_emit_funcs_free (struct ucl_emitter_functions *f)
{
	if (f != NULL) {
		if (f->ucl_emitter_free_func != NULL) {
			f->ucl_emitter_free_func (f->ud);
		}
		free (f);
	}
}


unsigned char *
ucl_object_emit_single_json (const ucl_object_t *obj)
{
	UT_string *buf = NULL;
	unsigned char *res = NULL;

	if (obj == NULL) {
		return NULL;
	}

	utstring_new (buf);

	if (buf != NULL) {
		switch (obj->type) {
		case UCL_OBJECT:
			ucl_utstring_append_len ("object", 6, buf);
			break;
		case UCL_ARRAY:
			ucl_utstring_append_len ("array", 5, buf);
			break;
		case UCL_INT:
			ucl_utstring_append_int (obj->value.iv, buf);
			break;
		case UCL_FLOAT:
		case UCL_TIME:
			ucl_utstring_append_double (obj->value.dv, buf);
			break;
		case UCL_NULL:
			ucl_utstring_append_len ("null", 4, buf);
			break;
		case UCL_BOOLEAN:
			if (obj->value.iv) {
				ucl_utstring_append_len ("true", 4, buf);
			}
			else {
				ucl_utstring_append_len ("false", 5, buf);
			}
			break;
		case UCL_STRING:
			ucl_utstring_append_len (obj->value.sv, obj->len, buf);
			break;
		case UCL_USERDATA:
			ucl_utstring_append_len ("userdata", 8, buf);
			break;
		}
		res = utstring_body (buf);
		free (buf);
	}

	return res;
}

#define LONG_STRING_LIMIT 80

bool
ucl_maybe_long_string (const ucl_object_t *obj)
{
	if (obj->len > LONG_STRING_LIMIT || (obj->flags & UCL_OBJECT_MULTILINE)) {
		/* String is long enough, so search for newline characters in it */
		if (memchr (obj->value.sv, '\n', obj->len) != NULL) {
			return true;
		}
	}

	return false;
}
