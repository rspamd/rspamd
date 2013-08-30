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

/*
 * Common section handlers
 */
gboolean rspamd_rcl_logging_handler (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	rspamd_cl_object_t *val;
	gchar *filepath;
	const gchar *facility, *log_type, *log_level;

	obj = obj->value.ov;

	HASH_FIND_STR (obj, "type", val);
	if (val != NULL && rspamd_cl_obj_tostring_safe (val, &log_type)) {
		if (g_ascii_strcasecmp (log_type, "file") == 0) {
			/* Need to get filename */
			HASH_FIND_STR (obj, "filename", val);
			if (val == NULL || val->type != RSPAMD_CL_STRING) {
				g_set_error (err, CFG_RCL_ERROR, ENOENT, "filename attribute must be specified for file logging type");
				return FALSE;
			}
			if ((filepath = realpath (rspamd_cl_obj_tostring (val), NULL)) == NULL ||
					access (filepath, W_OK) == -1) {
				g_set_error (err, CFG_RCL_ERROR, errno, "log file is inaccessible");
				return FALSE;
			}
			cfg->log_type = RSPAMD_LOG_FILE;
			cfg->log_file = memory_pool_strdup (cfg->cfg_pool, filepath);
		}
		else if (g_ascii_strcasecmp (log_type, "syslog") == 0) {
			/* Need to get facility */
			cfg->log_facility = LOG_DAEMON;
			cfg->log_type = RSPAMD_LOG_SYSLOG;
			HASH_FIND_STR (obj, "facility", val);
			if (val != NULL && rspamd_cl_obj_tostring_safe (val, &facility)) {
				if (g_ascii_strcasecmp (facility, "LOG_AUTH") == 0 ||
						g_ascii_strcasecmp (facility, "auth") == 0 ) {
					cfg->log_facility = LOG_AUTH;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_CRON") == 0 ||
						g_ascii_strcasecmp (facility, "cron") == 0 ) {
					cfg->log_facility = LOG_CRON;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_DAEMON") == 0 ||
						g_ascii_strcasecmp (facility, "daemon") == 0 ) {
					cfg->log_facility = LOG_DAEMON;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_MAIL") == 0 ||
						g_ascii_strcasecmp (facility, "mail") == 0) {
					cfg->log_facility = LOG_MAIL;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_USER") == 0 ||
						g_ascii_strcasecmp (facility, "user") == 0 ) {
					cfg->log_facility = LOG_USER;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL0") == 0 ||
						g_ascii_strcasecmp (facility, "local0") == 0) {
					cfg->log_facility = LOG_LOCAL0;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL1") == 0 ||
						g_ascii_strcasecmp (facility, "local1") == 0) {
					cfg->log_facility = LOG_LOCAL1;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL2") == 0 ||
						g_ascii_strcasecmp (facility, "local2") == 0) {
					cfg->log_facility = LOG_LOCAL2;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL3") == 0 ||
						g_ascii_strcasecmp (facility, "local3") == 0) {
					cfg->log_facility = LOG_LOCAL3;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL4") == 0 ||
						g_ascii_strcasecmp (facility, "local4") == 0) {
					cfg->log_facility = LOG_LOCAL4;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL5") == 0 ||
						g_ascii_strcasecmp (facility, "local5") == 0) {
					cfg->log_facility = LOG_LOCAL5;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL6") == 0 ||
						g_ascii_strcasecmp (facility, "local6") == 0) {
					cfg->log_facility = LOG_LOCAL6;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL7") == 0 ||
						g_ascii_strcasecmp (facility, "local7") == 0) {
					cfg->log_facility = LOG_LOCAL7;
				}
				else {
					g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid log facility: %s", facility);
					return FALSE;
				}
			}
		}
		else if (g_ascii_strcasecmp (log_type, "stderr") == 0 || g_ascii_strcasecmp (log_type, "console") == 0) {
			cfg->log_type = RSPAMD_LOG_CONSOLE;
		}
		else {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid log type: %s", log_type);
			return FALSE;
		}
	}
	else {
		/* No type specified */
		msg_warn ("logging type is not specified correctly, log output to the console");
	}

	/* Handle log level */
	HASH_FIND_STR (obj, "level", val);
	if (val != NULL && rspamd_cl_obj_tostring_safe (val, &log_level)) {
		if (g_ascii_strcasecmp (log_level, "error") == 0) {
			cfg->log_level = G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL;
		}
		else if (g_ascii_strcasecmp (log_level, "warning") == 0) {
			cfg->log_level = G_LOG_LEVEL_WARNING;
		}
		else if (g_ascii_strcasecmp (log_level, "info") == 0) {
			cfg->log_level = G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE;
		}
		else if (g_ascii_strcasecmp (log_level, "debug") == 0) {
			cfg->log_level = G_LOG_LEVEL_DEBUG;
		}
		else {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid log level: %s", log_level);
			return FALSE;
		}
	}

	return TRUE;
}

static inline void
rspamd_rcl_add_section (struct rspamd_rcl_section *top,
		const gchar *name, rspamd_rcl_handler_t handler,
		enum rspamd_cl_type type, gboolean required, gboolean strict_type)
{
	struct rspamd_rcl_section *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_section));
	new->name = name;
	new->handler = handler;
	new->type = type;
	new->strict_type = strict_type;

	HASH_ADD_KEYPTR (hh, top, new->name, strlen (new->name), new);
}

struct rspamd_rcl_section*
rspamd_rcl_config_init (void)
{
	struct rspamd_rcl_section *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_section));

	/* TODO: add all known rspamd sections here */
	rspamd_rcl_add_section (new, "logging", rspamd_rcl_logging_handler, RSPAMD_CL_OBJECT,
			FALSE, TRUE);

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

gboolean
rspamd_rcl_parse_struct_string (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gchar **target;
	const gsize num_str_len = 32;

	target = (gchar **)(((gchar *)pd->user_struct) + pd->offset);
	switch (obj->type) {
	case RSPAMD_CL_STRING:
		/* Direct assigning is safe, as object is likely linked to the cfg mem_pool */
		*target = obj->value.sv;
		break;
	case RSPAMD_CL_INT:
		*target = memory_pool_alloc (cfg->cfg_pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%L", obj->value.iv);
		break;
	case RSPAMD_CL_FLOAT:
		*target = memory_pool_alloc (cfg->cfg_pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%f", obj->value.dv);
		break;
	case RSPAMD_CL_BOOLEAN:
		*target = memory_pool_alloc (cfg->cfg_pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%b", (gboolean)obj->value.iv);
		break;
	default:
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert object or array to string");
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_integer (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	union {
		gint *ip;
		gint32 *i32p;
		gint16 *i16p;
		gint64 *i64p;
	} target;
	gint64 val;

	if (pd->size == sizeof (gint)) {
		target.ip = (gint *)(((gchar *)pd->user_struct) + pd->offset);
		if (!rspamd_cl_obj_toint_safe (obj, &val)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to integer");
			return FALSE;
		}
		*target.ip = val;
	}
	else if (pd->size == sizeof (gint32)) {
		target.i32p = (gint32 *)(((gchar *)pd->user_struct) + pd->offset);
		if (!rspamd_cl_obj_toint_safe (obj, &val)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to integer");
			return FALSE;
		}
		*target.i32p = val;
	}
	else if (pd->size == sizeof (gint16)) {
		target.i16p = (gint16 *)(((gchar *)pd->user_struct) + pd->offset);
		if (!rspamd_cl_obj_toint_safe (obj, &val)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to integer");
			return FALSE;
		}
		*target.i16p = val;
	}
	else if (pd->size == sizeof (gint64)) {
		target.i64p = (gint64 *)(((gchar *)pd->user_struct) + pd->offset);
		if (!rspamd_cl_obj_toint_safe (obj, &val)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to integer");
			return FALSE;
		}
		*target.i64p = val;
	}
	else {
		g_set_error (err, CFG_RCL_ERROR, E2BIG, "unknown integer size");
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_double (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gdouble *target;

	target = (gdouble *)(((gchar *)pd->user_struct) + pd->offset);

	if (!rspamd_cl_obj_todouble_safe (obj, target)) {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to double");
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_time (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	union {
		gint *psec;
		gdouble *pdv;
		struct timeval *ptv;
		struct timespec *pts;
	} target;
	gdouble val;

	if (!rspamd_cl_obj_todouble_safe (obj, &val)) {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to double");
		return FALSE;
	}

	if (pd->flags == RSPAMD_CL_FLAG_TIME_TIMEVAL) {
		target.ptv = (struct timeval *)(((gchar *)pd->user_struct) + pd->offset);
		target.ptv->tv_sec = (glong)val;
		target.ptv->tv_usec = (val - (glong)val) * 1000000;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_TIMESPEC) {
		target.pts = (struct timespec *)(((gchar *)pd->user_struct) + pd->offset);
		target.pts->tv_sec = (glong)val;
		target.pts->tv_nsec = (val - (glong)val) * 1000000000000LL;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_FLOAT) {
		target.pdv = (double *)(((gchar *)pd->user_struct) + pd->offset);
		*target.pdv = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_INTEGER) {
		target.psec = (gint *)(((gchar *)pd->user_struct) + pd->offset);
		*target.psec = val;
	}
	else {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid flags to parse time value");
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_string_list (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	GList **target;
	gchar *val;
	rspamd_cl_object_t *cur;
	const gsize num_str_len = 32;

	target = (GList **)(((gchar *)pd->user_struct) + pd->offset);

	if (obj->type != RSPAMD_CL_ARRAY) {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "an array of strings is expected");
		return FALSE;
	}

	for (cur = obj; cur != NULL; cur = cur->next) {
		switch (cur->type) {
		case RSPAMD_CL_STRING:
			/* Direct assigning is safe, as curect is likely linked to the cfg mem_pool */
			val = cur->value.sv;
			break;
		case RSPAMD_CL_INT:
			val = memory_pool_alloc (cfg->cfg_pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%L", cur->value.iv);
			break;
		case RSPAMD_CL_FLOAT:
			val = memory_pool_alloc (cfg->cfg_pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%f", cur->value.dv);
			break;
		case RSPAMD_CL_BOOLEAN:
			val = memory_pool_alloc (cfg->cfg_pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%b", (gboolean)cur->value.iv);
			break;
		default:
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert an object or array to string");
			return FALSE;
		}
		*target = g_list_prepend (*target, val);
	}

	return TRUE;
}
