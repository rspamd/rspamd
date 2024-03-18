/*
 * Copyright 2023 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "logger.h"
#include "rspamd.h"
#include "libserver/maps/map.h"
#include "libserver/maps/map_helpers.h"
#include "ottery.h"
#include "unix-std.h"
#include "logger_private.h"


static rspamd_logger_t *default_logger = NULL;
static rspamd_logger_t *emergency_logger = NULL;
static struct rspamd_log_modules *log_modules = NULL;

static const char lf_chr = '\n';

unsigned int rspamd_task_log_id = (unsigned int) -1;
RSPAMD_CONSTRUCTOR(rspamd_task_log_init)
{
	rspamd_task_log_id = rspamd_logger_add_debug_module("task");
}

rspamd_logger_t *
rspamd_log_default_logger(void)
{
	return default_logger;
}

rspamd_logger_t *
rspamd_log_emergency_logger(void)
{
	return emergency_logger;
}

void rspamd_log_set_log_level(rspamd_logger_t *logger, int level)
{
	if (logger == NULL) {
		logger = default_logger;
	}

	logger->log_level = level;
}

int rspamd_log_get_log_level(rspamd_logger_t *logger)
{
	if (logger == NULL) {
		logger = default_logger;
	}

	return logger->log_level;
}

void rspamd_log_set_log_flags(rspamd_logger_t *logger, int flags)
{
	g_assert(logger != NULL);

	logger->flags = flags;
}

void rspamd_log_close(rspamd_logger_t *logger)
{
	g_assert(logger != NULL);

	if (logger->closed) {
		return;
	}

	logger->closed = TRUE;

	if (logger->debug_ip) {
		rspamd_map_helper_destroy_radix(logger->debug_ip);
	}

	if (logger->pk) {
		rspamd_pubkey_unref(logger->pk);
	}

	if (logger->keypair) {
		rspamd_keypair_unref(logger->keypair);
	}

	logger->ops.dtor(logger, logger->ops.specific);

	/* TODO: Do we really need that ? */
	if (logger == default_logger) {
		default_logger = NULL;
	}

	if (logger == emergency_logger) {
		emergency_logger = NULL;
	}

	if (!logger->pool) {
		g_free(logger);
	}
}

bool rspamd_log_reopen(rspamd_logger_t *rspamd_log, struct rspamd_config *cfg,
					   uid_t uid, gid_t gid)
{
	void *nspec;
	GError *err = NULL;

	g_assert(rspamd_log != NULL);

	nspec = rspamd_log->ops.reload(rspamd_log, cfg, rspamd_log->ops.specific,
								   uid, gid, &err);

	if (nspec != NULL) {
		rspamd_log->ops.specific = nspec;
	}
	else {
	}

	return nspec != NULL;
}

static void
rspamd_emergency_logger_dtor(gpointer d)
{
	rspamd_logger_t *logger = (rspamd_logger_t *) d;

	rspamd_log_close(logger);
}

rspamd_logger_t *
rspamd_log_open_emergency(rspamd_mempool_t *pool, int flags)
{
	rspamd_logger_t *logger;
	GError *err = NULL;

	g_assert(default_logger == NULL);
	g_assert(emergency_logger == NULL);

	if (pool) {
		logger = rspamd_mempool_alloc0(pool, sizeof(rspamd_logger_t));
		logger->mtx = rspamd_mempool_get_mutex(pool);
	}
	else {
		logger = g_malloc0(sizeof(rspamd_logger_t));
	}

	logger->flags = flags;
	logger->pool = pool;
	logger->process_type = "main";
	logger->pid = getpid();

	const struct rspamd_logger_funcs *funcs = &console_log_funcs;
	memcpy(&logger->ops, funcs, sizeof(*funcs));

	logger->ops.specific = logger->ops.init(logger, NULL, -1, -1, &err);

	if (logger->ops.specific == NULL) {
		rspamd_fprintf(stderr, "fatal error: cannot init console logging: %e\n",
					   err);
		g_error_free(err);

		exit(EXIT_FAILURE);
	}

	default_logger = logger;
	emergency_logger = logger;

	rspamd_mempool_add_destructor(pool, rspamd_emergency_logger_dtor,
								  emergency_logger);

	return logger;
}

rspamd_logger_t *
rspamd_log_open_specific(rspamd_mempool_t *pool,
						 struct rspamd_config *cfg,
						 const char *ptype,
						 uid_t uid, gid_t gid)
{
	rspamd_logger_t *logger;
	GError *err = NULL;

	if (pool) {
		logger = rspamd_mempool_alloc0(pool, sizeof(rspamd_logger_t));
		logger->mtx = rspamd_mempool_get_mutex(pool);
	}
	else {
		logger = g_malloc0(sizeof(rspamd_logger_t));
	}

	logger->pool = pool;

	if (cfg) {
		if (cfg->log_error_elts > 0 && pool) {
			logger->errlog = rspamd_mempool_alloc0_shared(pool,
														  sizeof(*logger->errlog));
			logger->errlog->pool = pool;
			logger->errlog->max_elts = cfg->log_error_elts;
			logger->errlog->elt_len = cfg->log_error_elt_maxlen;
			logger->errlog->elts = rspamd_mempool_alloc0_shared(pool,
																sizeof(struct rspamd_logger_error_elt) * cfg->log_error_elts +
																	cfg->log_error_elt_maxlen * cfg->log_error_elts);
		}

		logger->log_level = cfg->log_level;
		logger->flags = cfg->log_flags;

		if (!(logger->flags & RSPAMD_LOG_FLAG_ENFORCED)) {
			logger->log_level = cfg->log_level;
		}
	}

	const struct rspamd_logger_funcs *funcs = NULL;

	if (cfg) {
		switch (cfg->log_type) {
		case RSPAMD_LOG_CONSOLE:
			funcs = &console_log_funcs;
			break;
		case RSPAMD_LOG_SYSLOG:
			funcs = &syslog_log_funcs;
			break;
		case RSPAMD_LOG_FILE:
			funcs = &file_log_funcs;
			break;
		}
	}
	else {
		funcs = &console_log_funcs;
	}

	g_assert(funcs != NULL);
	memcpy(&logger->ops, funcs, sizeof(*funcs));

	logger->ops.specific = logger->ops.init(logger, cfg, uid, gid, &err);

	if (emergency_logger && logger->ops.specific == NULL) {
		rspamd_common_log_function(emergency_logger, G_LOG_LEVEL_CRITICAL,
								   "logger", NULL, G_STRFUNC,
								   "cannot open specific logger: %e", err);
		g_error_free(err);

		return NULL;
	}

	logger->pid = getpid();
	logger->process_type = ptype;
	logger->enabled = TRUE;

	/* Set up conditional logging */
	if (cfg) {
		if (cfg->debug_ip_map != NULL) {
			/* Try to add it as map first of all */
			if (logger->debug_ip) {
				rspamd_map_helper_destroy_radix(logger->debug_ip);
			}

			logger->debug_ip = NULL;
			rspamd_config_radix_from_ucl(cfg,
										 cfg->debug_ip_map,
										 "IP addresses for which debug logs are enabled",
										 &logger->debug_ip,
										 NULL,
										 NULL, "debug ip");
		}

		if (cfg->log_encryption_key) {
			logger->pk = rspamd_pubkey_ref(cfg->log_encryption_key);
			logger->keypair = rspamd_keypair_new(RSPAMD_KEYPAIR_KEX,
												 RSPAMD_CRYPTOBOX_MODE_25519);
			rspamd_pubkey_calculate_nm(logger->pk, logger->keypair);
		}
	}

	default_logger = logger;

	return logger;
}


/**
 * Used after fork() for updating structure params
 */
void rspamd_log_on_fork(GQuark ptype, struct rspamd_config *cfg,
						rspamd_logger_t *logger)
{
	logger->pid = getpid();
	logger->process_type = g_quark_to_string(ptype);

	if (logger->ops.on_fork) {
		GError *err = NULL;

		bool ret = logger->ops.on_fork(logger, cfg, logger->ops.specific, &err);

		if (!ret && emergency_logger) {
			rspamd_common_log_function(emergency_logger, G_LOG_LEVEL_CRITICAL,
									   "logger", NULL, G_STRFUNC,
									   "cannot update logging on fork: %e", err);
			g_error_free(err);
		}
	}
}

inline gboolean
rspamd_logger_need_log(rspamd_logger_t *rspamd_log, GLogLevelFlags log_level,
					   int module_id)
{
	g_assert(rspamd_log != NULL);

	if ((log_level & RSPAMD_LOG_FORCED) ||
		(log_level & (RSPAMD_LOG_LEVEL_MASK & G_LOG_LEVEL_MASK)) <= rspamd_log->log_level) {
		return TRUE;
	}

	if (module_id != -1 && isset(log_modules->bitset, module_id)) {
		return TRUE;
	}

	return FALSE;
}

static char *
rspamd_log_encrypt_message(const char *begin, const char *end, gsize *enc_len,
						   rspamd_logger_t *rspamd_log)
{
	unsigned char *out;
	char *b64;
	unsigned char *p, *nonce, *mac;
	const unsigned char *comp;
	unsigned int len, inlen;

	g_assert(end > begin);
	/* base64 (pubkey | nonce | message) */
	inlen = rspamd_cryptobox_nonce_bytes(RSPAMD_CRYPTOBOX_MODE_25519) +
			rspamd_cryptobox_pk_bytes(RSPAMD_CRYPTOBOX_MODE_25519) +
			rspamd_cryptobox_mac_bytes(RSPAMD_CRYPTOBOX_MODE_25519) +
			(end - begin);
	out = g_malloc(inlen);

	p = out;
	comp = rspamd_pubkey_get_pk(rspamd_log->pk, &len);
	memcpy(p, comp, len);
	p += len;
	ottery_rand_bytes(p, rspamd_cryptobox_nonce_bytes(RSPAMD_CRYPTOBOX_MODE_25519));
	nonce = p;
	p += rspamd_cryptobox_nonce_bytes(RSPAMD_CRYPTOBOX_MODE_25519);
	mac = p;
	p += rspamd_cryptobox_mac_bytes(RSPAMD_CRYPTOBOX_MODE_25519);
	memcpy(p, begin, end - begin);
	comp = rspamd_pubkey_get_nm(rspamd_log->pk, rspamd_log->keypair);
	g_assert(comp != NULL);
	rspamd_cryptobox_encrypt_nm_inplace(p, end - begin, nonce, comp, mac,
										RSPAMD_CRYPTOBOX_MODE_25519);
	b64 = rspamd_encode_base64(out, inlen, 0, enc_len);
	g_free(out);

	return b64;
}

static void
rspamd_log_write_ringbuffer(rspamd_logger_t *rspamd_log,
							const char *module, const char *id,
							const char *data, glong len)
{
	uint32_t row_num;
	struct rspamd_logger_error_log *elog;
	struct rspamd_logger_error_elt *elt;

	if (!rspamd_log->errlog) {
		return;
	}

	elog = rspamd_log->errlog;

	g_atomic_int_compare_and_exchange(&elog->cur_row, elog->max_elts, 0);
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	row_num = g_atomic_int_add(&elog->cur_row, 1);
#else
	row_num = g_atomic_int_exchange_and_add(&elog->cur_row, 1);
#endif

	if (row_num < elog->max_elts) {
		elt = (struct rspamd_logger_error_elt *) (((unsigned char *) elog->elts) +
												  (sizeof(*elt) + elog->elt_len) * row_num);
		g_atomic_int_set(&elt->completed, 0);
	}
	else {
		/* Race condition */
		elog->cur_row = 0;
		return;
	}

	elt->pid = rspamd_log->pid;
	elt->ptype = g_quark_from_string(rspamd_log->process_type);
	elt->ts = rspamd_get_calendar_ticks();

	if (id) {
		rspamd_strlcpy(elt->id, id, sizeof(elt->id));
	}
	else {
		rspamd_strlcpy(elt->id, "", sizeof(elt->id));
	}

	if (module) {
		rspamd_strlcpy(elt->module, module, sizeof(elt->module));
	}
	else {
		rspamd_strlcpy(elt->module, "", sizeof(elt->module));
	}

	rspamd_strlcpy(elt->message, data, MIN(len + 1, elog->elt_len));
	g_atomic_int_set(&elt->completed, 1);
}

bool rspamd_common_logv(rspamd_logger_t *rspamd_log, int level_flags,
						const char *module, const char *id, const char *function,
						const char *fmt, va_list args)
{
	char *end;
	int level = level_flags & (RSPAMD_LOG_LEVEL_MASK & G_LOG_LEVEL_MASK), mod_id;
	bool ret = false;
	char logbuf[RSPAMD_LOGBUF_SIZE], *log_line;
	gsize nescaped;

	if (G_UNLIKELY(rspamd_log == NULL)) {
		rspamd_log = default_logger;
	}

	log_line = logbuf;

	if (G_UNLIKELY(rspamd_log == NULL)) {
		/* Just fprintf message to stderr */
		if (level >= G_LOG_LEVEL_INFO) {
			end = rspamd_vsnprintf(logbuf, sizeof(logbuf), fmt, args);
			rspamd_fprintf(stderr, "%*s\n", (int) (end - log_line),
						   log_line);
		}
	}
	else {
		if (level == G_LOG_LEVEL_DEBUG) {
			mod_id = rspamd_logger_add_debug_module(module);
		}
		else {
			mod_id = -1;
		}

		if (rspamd_logger_need_log(rspamd_log, level_flags, mod_id)) {
			end = rspamd_vsnprintf(logbuf, sizeof(logbuf), fmt, args);

			if (!(rspamd_log->flags & RSPAMD_LOG_FLAG_RSPAMADM)) {
				if ((nescaped = rspamd_log_line_need_escape(logbuf, end - logbuf)) != 0) {
					gsize unescaped_len = end - logbuf;
					char *logbuf_escaped = g_alloca(unescaped_len + nescaped * 4);
					log_line = logbuf_escaped;

					end = rspamd_log_line_hex_escape(logbuf, unescaped_len,
													 logbuf_escaped, unescaped_len + nescaped * 4);
				}
			}

			if ((level_flags & RSPAMD_LOG_ENCRYPTED) && rspamd_log->pk) {
				char *encrypted;
				gsize enc_len;

				encrypted = rspamd_log_encrypt_message(log_line, end, &enc_len,
													   rspamd_log);
				ret = rspamd_log->ops.log(module, id,
										  function,
										  level_flags,
										  encrypted,
										  enc_len,
										  rspamd_log,
										  rspamd_log->ops.specific);
				g_free(encrypted);
			}
			else {
				ret = rspamd_log->ops.log(module, id,
										  function,
										  level_flags,
										  log_line,
										  end - log_line,
										  rspamd_log,
										  rspamd_log->ops.specific);
			}

			switch (level) {
			case G_LOG_LEVEL_CRITICAL:
				rspamd_log->log_cnt[0]++;
				rspamd_log_write_ringbuffer(rspamd_log, module, id, log_line,
											end - log_line);
				break;
			case G_LOG_LEVEL_WARNING:
				rspamd_log->log_cnt[1]++;
				break;
			case G_LOG_LEVEL_INFO:
				rspamd_log->log_cnt[2]++;
				break;
			case G_LOG_LEVEL_DEBUG:
				rspamd_log->log_cnt[3]++;
				break;
			default:
				break;
			}
		}
	}

	return ret;
}

/**
 * This log functions select real logger and write message if level is less or equal to configured log level
 */
bool rspamd_common_log_function(rspamd_logger_t *rspamd_log,
								int level_flags,
								const char *module, const char *id,
								const char *function,
								const char *fmt,
								...)
{
	va_list vp;

	va_start(vp, fmt);
	bool ret = rspamd_common_logv(rspamd_log, level_flags, module, id, function, fmt, vp);
	va_end(vp);

	return ret;
}

bool rspamd_default_logv(int level_flags, const char *module, const char *id,
						 const char *function,
						 const char *fmt, va_list args)
{
	return rspamd_common_logv(NULL, level_flags, module, id, function, fmt, args);
}

bool rspamd_default_log_function(int level_flags,
								 const char *module, const char *id,
								 const char *function, const char *fmt, ...)
{

	va_list vp;

	va_start(vp, fmt);
	bool ret = rspamd_default_logv(level_flags, module, id, function, fmt, vp);
	va_end(vp);

	return ret;
}


/**
 * Main file interface for logging
 */
/**
 * Write log line depending on ip
 */
bool rspamd_conditional_debug(rspamd_logger_t *rspamd_log,
							  rspamd_inet_addr_t *addr, const char *module, const char *id,
							  const char *function, const char *fmt, ...)
{
	static char logbuf[LOGBUF_LEN];
	va_list vp;
	char *end;
	int mod_id;

	if (rspamd_log == NULL) {
		rspamd_log = default_logger;
	}

	mod_id = rspamd_logger_add_debug_module(module);

	if (rspamd_logger_need_log(rspamd_log, G_LOG_LEVEL_DEBUG, mod_id) ||
		rspamd_log->is_debug) {
		if (rspamd_log->debug_ip && addr != NULL) {
			if (rspamd_match_radix_map_addr(rspamd_log->debug_ip,
											addr) == NULL) {
				return false;
			}
		}

		va_start(vp, fmt);
		end = rspamd_vsnprintf(logbuf, sizeof(logbuf), fmt, vp);
		*end = '\0';
		va_end(vp);
		return rspamd_log->ops.log(module, id,
								   function,
								   G_LOG_LEVEL_DEBUG | RSPAMD_LOG_FORCED,
								   logbuf,
								   end - logbuf,
								   rspamd_log,
								   rspamd_log->ops.specific);
	}

	return false;
}

bool rspamd_conditional_debug_fast(rspamd_logger_t *rspamd_log,
								   rspamd_inet_addr_t *addr,
								   int mod_id, const char *module, const char *id,
								   const char *function, const char *fmt, ...)
{
	static char logbuf[LOGBUF_LEN];
	va_list vp;
	char *end;

	if (rspamd_log == NULL) {
		rspamd_log = default_logger;
	}

	if (rspamd_logger_need_log(rspamd_log, G_LOG_LEVEL_DEBUG, mod_id) ||
		rspamd_log->is_debug) {
		if (rspamd_log->debug_ip && addr != NULL) {
			if (rspamd_match_radix_map_addr(rspamd_log->debug_ip, addr) == NULL) {
				return false;
			}
		}

		va_start(vp, fmt);
		end = rspamd_vsnprintf(logbuf, sizeof(logbuf), fmt, vp);
		*end = '\0';
		va_end(vp);
		return rspamd_log->ops.log(module, id,
								   function,
								   G_LOG_LEVEL_DEBUG | RSPAMD_LOG_FORCED,
								   logbuf,
								   end - logbuf,
								   rspamd_log,
								   rspamd_log->ops.specific);
	}

	return false;
}

bool rspamd_conditional_debug_fast_num_id(rspamd_logger_t *rspamd_log,
										  rspamd_inet_addr_t *addr,
										  int mod_id, const char *module, uint64_t id,
										  const char *function, const char *fmt, ...)
{
	static char logbuf[LOGBUF_LEN], idbuf[64];
	va_list vp;
	char *end;

	if (rspamd_log == NULL) {
		rspamd_log = default_logger;
	}

	if (rspamd_logger_need_log(rspamd_log, G_LOG_LEVEL_DEBUG, mod_id) ||
		rspamd_log->is_debug) {
		if (rspamd_log->debug_ip && addr != NULL) {
			if (rspamd_match_radix_map_addr(rspamd_log->debug_ip, addr) == NULL) {
				return false;
			}
		}

		rspamd_snprintf(idbuf, sizeof(idbuf), "%XuL", id);
		va_start(vp, fmt);
		end = rspamd_vsnprintf(logbuf, sizeof(logbuf), fmt, vp);
		*end = '\0';
		va_end(vp);
		return rspamd_log->ops.log(module, idbuf,
								   function,
								   G_LOG_LEVEL_DEBUG | RSPAMD_LOG_FORCED,
								   logbuf,
								   end - logbuf,
								   rspamd_log,
								   rspamd_log->ops.specific);
	}

	return false;
}

/**
 * Wrapper for glib logger
 */
void rspamd_glib_log_function(const char *log_domain,
							  GLogLevelFlags log_level,
							  const char *message,
							  gpointer arg)
{
	rspamd_logger_t *rspamd_log = (rspamd_logger_t *) arg;

	if (rspamd_log->enabled &&
		rspamd_logger_need_log(rspamd_log, log_level, -1)) {
		rspamd_log->ops.log("glib", NULL,
							NULL,
							log_level,
							message,
							strlen(message),
							rspamd_log,
							rspamd_log->ops.specific);
	}
}

void rspamd_glib_printerr_function(const char *message)
{
	rspamd_common_log_function(NULL, G_LOG_LEVEL_CRITICAL, "glib",
							   NULL, G_STRFUNC,
							   "%s", message);
}

/**
 * Temporary turn on debugging
 */
void rspamd_log_debug(rspamd_logger_t *rspamd_log)
{
	rspamd_log->is_debug = TRUE;
}

/**
 * Turn off temporary debugging
 */
void rspamd_log_nodebug(rspamd_logger_t *rspamd_log)
{
	rspamd_log->is_debug = FALSE;
}

const uint64_t *
rspamd_log_counters(rspamd_logger_t *logger)
{
	if (logger) {
		return logger->log_cnt;
	}

	return NULL;
}

static int
rspamd_log_errlog_cmp(const ucl_object_t **o1, const ucl_object_t **o2)
{
	const ucl_object_t *ts1, *ts2;

	ts1 = ucl_object_lookup(*o1, "ts");
	ts2 = ucl_object_lookup(*o2, "ts");

	if (ts1 && ts2) {
		double t1 = ucl_object_todouble(ts1), t2 = ucl_object_todouble(ts2);

		if (t1 > t2) {
			return -1;
		}
		else if (t2 > t1) {
			return 1;
		}
	}

	return 0;
}

ucl_object_t *
rspamd_log_errorbuf_export(const rspamd_logger_t *logger)
{
	struct rspamd_logger_error_elt *cpy, *cur;
	ucl_object_t *top = ucl_object_typed_new(UCL_ARRAY);
	unsigned int i;

	if (logger->errlog == NULL) {
		return top;
	}

	cpy = g_malloc0_n(logger->errlog->max_elts,
					  sizeof(*cpy) + logger->errlog->elt_len);
	memcpy(cpy, logger->errlog->elts, logger->errlog->max_elts * (sizeof(*cpy) + logger->errlog->elt_len));

	for (i = 0; i < logger->errlog->max_elts; i++) {
		cur = (struct rspamd_logger_error_elt *) ((unsigned char *) cpy +
												  i * ((sizeof(*cpy) + logger->errlog->elt_len)));
		if (cur->completed) {
			ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);

			ucl_object_insert_key(obj, ucl_object_fromdouble(cur->ts),
								  "ts", 0, false);
			ucl_object_insert_key(obj, ucl_object_fromint(cur->pid),
								  "pid", 0, false);
			ucl_object_insert_key(obj,
								  ucl_object_fromstring(g_quark_to_string(cur->ptype)),
								  "type", 0, false);
			ucl_object_insert_key(obj, ucl_object_fromstring(cur->id),
								  "id", 0, false);
			ucl_object_insert_key(obj, ucl_object_fromstring(cur->module),
								  "module", 0, false);
			ucl_object_insert_key(obj, ucl_object_fromstring(cur->message),
								  "message", 0, false);

			ucl_array_append(top, obj);
		}
	}

	ucl_object_array_sort(top, rspamd_log_errlog_cmp);
	g_free(cpy);

	return top;
}

static unsigned int
rspamd_logger_allocate_mod_bit(void)
{
	if (log_modules->bitset_allocated * NBBY > log_modules->bitset_len + 1) {
		log_modules->bitset_len++;
		return log_modules->bitset_len - 1;
	}
	else {
		/* Need to expand */
		log_modules->bitset_allocated *= 2;
		log_modules->bitset = g_realloc(log_modules->bitset,
										log_modules->bitset_allocated);

		return rspamd_logger_allocate_mod_bit();
	}
}

RSPAMD_DESTRUCTOR(rspamd_debug_modules_dtor)
{
	if (log_modules) {
		g_hash_table_unref(log_modules->modules);
		g_free(log_modules->bitset);
		g_free(log_modules);
	}
}

int rspamd_logger_add_debug_module(const char *mname)
{
	struct rspamd_log_module *m;

	if (mname == NULL) {
		return -1;
	}

	if (log_modules == NULL) {
		/*
		 * This is usually called from constructors, so we call init check
		 * each time to avoid dependency issues between ctors calls
		 */
		log_modules = g_malloc0(sizeof(*log_modules));
		log_modules->modules = g_hash_table_new_full(rspamd_strcase_hash,
													 rspamd_strcase_equal, g_free, g_free);
		log_modules->bitset_allocated = 16;
		log_modules->bitset_len = 0;
		log_modules->bitset = g_malloc0(log_modules->bitset_allocated);
	}

	if ((m = g_hash_table_lookup(log_modules->modules, mname)) == NULL) {
		m = g_malloc0(sizeof(*m));
		m->mname = g_strdup(mname);
		m->id = rspamd_logger_allocate_mod_bit();
		clrbit(log_modules->bitset, m->id);
		g_hash_table_insert(log_modules->modules, m->mname, m);
	}

	return m->id;
}

void rspamd_logger_configure_modules(GHashTable *mods_enabled)
{
	GHashTableIter it;
	gpointer k, v;
	unsigned int id;

	/* Clear all in bitset_allocated -> this are bytes not bits */
	memset(log_modules->bitset, 0, log_modules->bitset_allocated);
	/* On first iteration, we go through all modules enabled and add missing ones */
	g_hash_table_iter_init(&it, mods_enabled);

	while (g_hash_table_iter_next(&it, &k, &v)) {
		rspamd_logger_add_debug_module((const char *) k);
	}

	g_hash_table_iter_init(&it, mods_enabled);

	while (g_hash_table_iter_next(&it, &k, &v)) {
		id = rspamd_logger_add_debug_module((const char *) k);

		if (isclr(log_modules->bitset, id)) {
			msg_info("enable debugging for module %s (%d)", (const char *) k,
					 id);
			setbit(log_modules->bitset, id);
		}
	}
}

struct rspamd_logger_funcs *
rspamd_logger_set_log_function(rspamd_logger_t *logger,
							   struct rspamd_logger_funcs *nfuncs)
{
	/* TODO: write this */

	return NULL;
}


char *
rspamd_log_line_hex_escape(const unsigned char *src, gsize srclen,
						   char *dst, gsize dstlen)
{
	static const char hexdigests[16] = "0123456789ABCDEF";
	char *d = dst;

	static uint32_t escape[] = {
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

		/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

		/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		0x00000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

		/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

		/* Allow all 8bit characters (assuming they are valid utf8) */
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
	};

	while (srclen && dstlen) {
		if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
			if (dstlen >= 4) {
				*d++ = '\\';
				*d++ = 'x';
				*d++ = hexdigests[*src >> 4];
				*d++ = hexdigests[*src & 0xf];
				src++;
				dstlen -= 4;
			}
			else {
				/* Overflow */
				break;
			}
		}
		else {
			*d++ = *src++;
			dstlen--;
		}

		srclen--;
	}

	return d;
}

gsize rspamd_log_line_need_escape(const unsigned char *src, gsize srclen)
{
	static uint32_t escape[] = {
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

		/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

		/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		0x00000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

		/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

		/* Allow all 8bit characters (assuming they are valid utf8) */
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
	};
	gsize n = 0;

	while (srclen) {
		if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
			n++;
		}

		src++;
		srclen--;
	}

	return n;
}

const char *
rspamd_get_log_severity_string(int level_flags)
{
	unsigned int bitnum;
	static const char *level_strs[G_LOG_LEVEL_USER_SHIFT] = {
		"", /* G_LOG_FLAG_RECURSION */
		"", /* G_LOG_FLAG_FATAL */
		"crit",
		"error",
		"warn",
		"notice",
		"info",
		"debug"};
	level_flags &= ((1u << G_LOG_LEVEL_USER_SHIFT) - 1u) & ~(G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL);
#ifdef __GNUC__
	/* We assume gcc >= 3 and clang >= 5 anyway */
	bitnum = __builtin_ffs(level_flags) - 1;
#else
	bitnum = ffs(level_flags) - 1;
#endif
	return level_strs[bitnum];
}

static inline void
log_time(double now, rspamd_logger_t *rspamd_log, char *timebuf,
		 size_t len)
{
	time_t sec = (time_t) now;
	gsize r;
	struct tm tms;

	rspamd_localtime(sec, &tms);
	r = strftime(timebuf, len, "%F %H:%M:%S", &tms);

	if (rspamd_log->flags & RSPAMD_LOG_FLAG_USEC) {
		char usec_buf[16];

		rspamd_snprintf(usec_buf, sizeof(usec_buf), "%.5f",
						now - (double) sec);
		rspamd_snprintf(timebuf + r, len - r,
						"%s", usec_buf + 1);
	}
}

void rspamd_log_fill_iov(struct rspamd_logger_iov_ctx *iov_ctx,
						 double ts,
						 const char *module,
						 const char *id,
						 const char *function,
						 int level_flags,
						 const char *message,
						 gsize mlen,
						 rspamd_logger_t *logger)
{
	bool log_color = (logger->flags & RSPAMD_LOG_FLAG_COLOR);
	bool log_severity = (logger->flags & RSPAMD_LOG_FLAG_SEVERITY);
	bool log_rspamadm = (logger->flags & RSPAMD_LOG_FLAG_RSPAMADM);
	bool log_systemd = (logger->flags & RSPAMD_LOG_FLAG_SYSTEMD);
	bool log_json = (logger->flags & RSPAMD_LOG_FLAG_JSON);

	if (log_json) {
		/* Some sanity to avoid too many branches */
		log_color = false;
		log_severity = true;
		log_systemd = false;
	}

	glong r;
	static char timebuf[64], modulebuf[64];
	static char tmpbuf[256];

	if (!log_json && !log_systemd) {
		log_time(ts, logger, timebuf, sizeof(timebuf));
	}

	if (G_UNLIKELY(log_json)) {
		/* Perform JSON logging */
		unsigned int slen = id ? strlen(id) : strlen("(NULL)");
		slen = MIN(RSPAMD_LOG_ID_LEN, slen);
		r = rspamd_snprintf(tmpbuf, sizeof(tmpbuf), "{\"ts\": %f, "
													"\"pid\": %P, "
													"\"severity\": \"%s\", "
													"\"worker_type\": \"%s\", "
													"\"id\": \"%*.s\", "
													"\"module\": \"%s\", "
													"\"function\": \"%s\", "
													"\"message\": \"",
							ts,
							logger->pid,
							rspamd_get_log_severity_string(level_flags),
							logger->process_type,
							slen, id,
							module,
							function);
		iov_ctx->iov[0].iov_base = tmpbuf;
		iov_ctx->iov[0].iov_len = r;
		/* TODO: is it possible to have other 'bad' symbols here? */
		if (rspamd_memcspn(message, "\"\\\r\n\b\t\v", mlen) == mlen) {
			iov_ctx->iov[1].iov_base = (void *) message;
			iov_ctx->iov[1].iov_len = mlen;
		}
		else {
			/* We need to do JSON escaping of the quotes */
			const char *p, *end = message + mlen;
			long escaped_len;

			for (p = message, escaped_len = 0; p < end; p++, escaped_len++) {
				switch (*p) {
				case '\v':
				case '\0':
					escaped_len += 5;
					break;
				case '\\':
				case '"':
				case '\n':
				case '\r':
				case '\b':
				case '\t':
					escaped_len++;
					break;
				default:
					break;
				}
			}


			struct rspamd_logger_iov_thrash_stack *thrash_stack_elt = g_malloc(
				sizeof(struct rspamd_logger_iov_thrash_stack) +
				escaped_len);

			char *dst = ((char *) thrash_stack_elt) + sizeof(struct rspamd_logger_iov_thrash_stack);
			char *d;

			thrash_stack_elt->prev = iov_ctx->thrash_stack;
			iov_ctx->thrash_stack = thrash_stack_elt;

			for (p = message, d = dst; p < end; p++, d++) {
				switch (*p) {
				case '\n':
					*d++ = '\\';
					*d = 'n';
					break;
				case '\r':
					*d++ = '\\';
					*d = 'r';
					break;
				case '\b':
					*d++ = '\\';
					*d = 'b';
					break;
				case '\t':
					*d++ = '\\';
					*d = 't';
					break;
				case '\f':
					*d++ = '\\';
					*d = 'f';
					break;
				case '\0':
					*d++ = '\\';
					*d++ = 'u';
					*d++ = '0';
					*d++ = '0';
					*d++ = '0';
					*d = '0';
					break;
				case '\v':
					*d++ = '\\';
					*d++ = 'u';
					*d++ = '0';
					*d++ = '0';
					*d++ = '0';
					*d = 'B';
					break;
				case '\\':
					*d++ = '\\';
					*d = '\\';
					break;
				case '"':
					*d++ = '\\';
					*d = '"';
					break;
				default:
					*d = *p;
					break;
				}
			}

			iov_ctx->iov[1].iov_base = dst;
			iov_ctx->iov[1].iov_len = d - dst;
		}
		iov_ctx->iov[2].iov_base = (void *) "\"}\n";
		iov_ctx->iov[2].iov_len = sizeof("\"}\n") - 1;

		iov_ctx->niov = 3;
	}
	else if (G_LIKELY(!log_rspamadm)) {
		if (!log_systemd) {
			if (log_color) {
				if (level_flags & (G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE)) {
					/* White */
					r = rspamd_snprintf(tmpbuf, sizeof(tmpbuf), "\033[0;37m");
				}
				else if (level_flags & G_LOG_LEVEL_WARNING) {
					/* Magenta */
					r = rspamd_snprintf(tmpbuf, sizeof(tmpbuf), "\033[0;32m");
				}
				else if (level_flags & G_LOG_LEVEL_CRITICAL) {
					/* Red */
					r = rspamd_snprintf(tmpbuf, sizeof(tmpbuf), "\033[1;31m");
				}
				else {
					r = 0;
				}
			}
			else {
				r = 0;
			}

			if (log_severity) {
				r += rspamd_snprintf(tmpbuf + r,
									 sizeof(tmpbuf) - r,
									 "%s [%s] #%P(%s) ",
									 timebuf,
									 rspamd_get_log_severity_string(level_flags),
									 logger->pid,
									 logger->process_type);
			}
			else {
				r += rspamd_snprintf(tmpbuf + r,
									 sizeof(tmpbuf) - r,
									 "%s #%P(%s) ",
									 timebuf,
									 logger->pid,
									 logger->process_type);
			}
		}
		else {
			r = 0;
			r += rspamd_snprintf(tmpbuf + r,
								 sizeof(tmpbuf) - r,
								 "(%s) ",
								 logger->process_type);
		}

		glong mremain, mr;
		char *m;

		modulebuf[0] = '\0';
		mremain = sizeof(modulebuf);
		m = modulebuf;

		if (id != NULL) {
			unsigned int slen = strlen(id);
			slen = MIN(RSPAMD_LOG_ID_LEN, slen);
			mr = rspamd_snprintf(m, mremain, "<%*.s>; ", slen,
								 id);
			m += mr;
			mremain -= mr;
		}
		if (module != NULL) {
			mr = rspamd_snprintf(m, mremain, "%s; ", module);
			m += mr;
			mremain -= mr;
		}
		if (function != NULL) {
			mr = rspamd_snprintf(m, mremain, "%s: ", function);
			m += mr;
			mremain -= mr;
		}
		else {
			mr = rspamd_snprintf(m, mremain, ": ");
			m += mr;
			mremain -= mr;
		}

		/* Ensure that we have a space at the end */
		if (m > modulebuf && *(m - 1) != ' ') {
			*(m - 1) = ' ';
		}

		/* Construct IOV for log line */
		iov_ctx->iov[0].iov_base = tmpbuf;
		iov_ctx->iov[0].iov_len = r;
		iov_ctx->iov[1].iov_base = modulebuf;
		iov_ctx->iov[1].iov_len = m - modulebuf;
		iov_ctx->iov[2].iov_base = (void *) message;
		iov_ctx->iov[2].iov_len = mlen;
		iov_ctx->iov[3].iov_base = (void *) &lf_chr;
		iov_ctx->iov[3].iov_len = 1;

		iov_ctx->niov = 4;

		if (log_color) {
			iov_ctx->iov[4].iov_base = "\033[0m";
			iov_ctx->iov[4].iov_len = sizeof("\033[0m") - 1;

			iov_ctx->niov = 5;
		}
	}
	else {
		/* Rspamadm case */
		int niov = 0;

		if (logger->log_level == G_LOG_LEVEL_DEBUG) {
			iov_ctx->iov[niov].iov_base = (void *) timebuf;
			iov_ctx->iov[niov++].iov_len = strlen(timebuf);
			iov_ctx->iov[niov].iov_base = (void *) " ";
			iov_ctx->iov[niov++].iov_len = 1;
		}

		iov_ctx->iov[niov].iov_base = (void *) message;
		iov_ctx->iov[niov++].iov_len = mlen;
		iov_ctx->iov[niov].iov_base = (void *) &lf_chr;
		iov_ctx->iov[niov++].iov_len = 1;

		iov_ctx->niov = niov;
	}

	// this is kind of "after-the-fact" check, but it's mostly for debugging-only
	g_assert(iov_ctx->niov <= G_N_ELEMENTS(iov_ctx->iov));
}

void rspamd_log_iov_free(struct rspamd_logger_iov_ctx *iov_ctx)
{
	struct rspamd_logger_iov_thrash_stack *st = iov_ctx->thrash_stack;

	while (st) {
		struct rspamd_logger_iov_thrash_stack *nst = st->prev;
		g_free(st);
		st = nst;
	}
}