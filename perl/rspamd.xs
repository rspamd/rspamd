/*
 * Perl XS module for interacting with rspamd
 *
 * vi:ts=4 
 */

#include <sys/types.h>
#include <unistd.h>
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <glib.h>

#include "../src/config.h"
#include "../src/main.h"
#include "../src/message.h"
#include "../src/cfg_file.h"
#include "../src/perl.h"
#include "../src/mem_pool.h"

#define perl_set_session(r)													    \
	r = INT2PTR(struct worker_task *, SvIV((SV *) SvRV(ST(0))))

#define perl_set_config(r)                                                      \
    r = INT2PTR(struct config_file *, SvIV((SV *) SvRV(ST(0))))

#define perl_set_targ(p, len)													\
	SvUPGRADE(TARG, SVt_PV);													\
	SvPOK_on(TARG);																\
	sv_setpvn(TARG, (char *) p, len)

MODULE = rspamd   PACKAGE = rspamd_task PREFIX = rspamd_task_
PROTOTYPES: DISABLE

void
rspamd_task_get_header (r, header)
	CODE:
	dXSTARG;
	struct worker_task *r;
	SV *header;
	char *s;
	STRLEN len;
	
    perl_set_session(r);

	header = ST(1);
	if (SvROK (header) && SvTYPE (SvRV (header)) == SVt_PV) {
		header = SvRV (header);
	}

	s = (char *) SvPV (header, len);

	if ((s = (char *)g_mime_message_get_header (r->message, s)) == NULL) {
		XSRETURN_UNDEF;
	}
	else {
		perl_set_targ (s, strlen (s));
		ST(0) = TARG;
	}

void
rspamd_task_get_part_num (r)
	CODE:
	dXSTARG;
	struct worker_task *r;

	perl_set_session (r);
	sv_upgrade(TARG, SVt_IV);
	sv_setiv(TARG, r->parts_count);

	ST(0) = TARG;


HV *
rspamd_task_get_part (r, num)
	CODE:
	struct worker_task *r;
	SV *num;
	int number;
	struct mime_part *part;
	char *type;

	perl_set_session (r);
	num = ST(1);

	number = (int) SvIV (num);
	if (number < 0 || number > r->parts_count - 1) {
		XSRETURN_UNDEF;
	}
	
	part = g_list_nth_data (r->parts, number);
	RETVAL = newHV();
	type = g_mime_content_type_to_string (part->type);

	(void)hv_store_ent (RETVAL, 
				newSVpv ("type", sizeof ("type") - 1), 
				newSVpv (type, strlen(type)), 0);
	(void)hv_store_ent (RETVAL, 
				newSVpv ("content", sizeof ("content") - 1), 
				newSVpv ((char *)part->content->data, part->content->len), 0);
    sv_2mortal((SV*)RETVAL);
	OUTPUT:
	RETVAL

void
rspamd_task_ip (r)
	CODE:
	dXSTARG;
	struct worker_task *r;
	char *ip_str;

	perl_set_session (r);
	sv_upgrade(TARG, SVt_PV);
	ip_str = inet_ntoa (r->from_addr);
	sv_setpv(TARG, ip_str);
	ST(0) = TARG;

void
rspamd_task_from (r)
	CODE:
	dXSTARG;
	struct worker_task *r;

	perl_set_session (r);
	if (r->from == NULL) {
		XSRETURN_UNDEF;
	}
	sv_upgrade(TARG, SVt_PV);
	sv_setpv(TARG, r->from);
	ST(0) = TARG;

void
rspamd_task_save_point (r)
    CODE:
	struct worker_task *r;

	perl_set_session (r);
    r->save.saved = 1;

void
rspamd_task_recall_filter (r)
    CODE:
    struct worker_task *r;

	perl_set_session (r);
    process_filters (r);

void
rspamd_task_insert_result (r, metric, symbol, flag)
	CODE:
	struct worker_task *r;
	char *metric, *symbol;
	int flag;

	perl_set_session (r);
	metric = (char *) SvPV_nolen (ST(1));
	symbol = (char *) SvPV_nolen (ST(2));
	flag = (int) SvIV (ST(3));

	insert_result (r, metric, symbol, flag);



void
rspamd_task_read_memcached_key (r, key, datalen, callback)
    CODE:
    struct worker_task *r;
    char *key;
    unsigned int datalen;
    SV *callback;
    struct _param {
        SV *callback;
        struct worker_task *task;
    } *callback_data;
    memcached_ctx_t *ctx;
    memcached_param_t param;

    perl_set_session (r);
    key = (char *) SvPV_nolen (ST(1));
    datalen = (unsigned int) SvIV (ST(2));
    callback = SvRV(ST(3));

    /* Copy old ctx to new one */
    ctx = memory_pool_alloc (r->task_pool, sizeof (memcached_ctx_t));
    if (ctx == NULL) {
        XSRETURN_UNDEF;
    }
    memcpy (ctx, r->memc_ctx, sizeof (memcached_ctx_t));
    /* Set perl callback */
    ctx->callback = perl_call_memcached_callback;
    callback_data = memory_pool_alloc (r->task_pool, sizeof (struct _param));
    if (callback_data == NULL) {
		XSRETURN_UNDEF;
    }
    callback_data->callback = callback;
    callback_data->task = r;
    ctx->callback_data = (void *)callback_data;

    g_strlcpy (param.key, key, sizeof (param.key));
	param.buf = memory_pool_alloc (r->task_pool, datalen);
    if (param.buf != NULL) {
        param.bufsize = datalen;
    }
    param.bufpos = 0;
    param.expire = 0;

    memc_get (ctx, &param);
    /* Set save point */
    r->save.saved = 1;
    XSRETURN_EMPTY;

void
rspamd_task_write_memcached_key (r, key, data, expire, callback)
    CODE:
    struct worker_task *r;
    char *key, *data;
    SV *callback;
    STRLEN datalen;
    int expire;
    struct _param {
        SV *callback;
        struct worker_task *task;
    } *callback_data;
    memcached_ctx_t *ctx;
    memcached_param_t param;

    perl_set_session (r);
    key = (char *) SvPV_nolen (ST(1));
    data = (char *) SvPV (ST(2), datalen);
    expire = (int) SvIV (ST(3));
    callback = SvRV(ST(4));

    /* Copy old ctx to new one */
    ctx = memory_pool_alloc (r->task_pool, sizeof (memcached_ctx_t));
    if (ctx == NULL) {
        XSRETURN_UNDEF;
    }
    memcpy (ctx, r->memc_ctx, sizeof (memcached_ctx_t));
    /* Set perl callback */
    ctx->callback = perl_call_memcached_callback;
    callback_data = memory_pool_alloc (r->task_pool, sizeof (struct _param));
    if (callback_data == NULL) {
		XSRETURN_UNDEF;
    }
    callback_data->callback = callback;
    callback_data->task = r;
    ctx->callback_data = (void *)callback_data;

    g_strlcpy (param.key, key, sizeof (param.key));
    param.buf = data;
    param.bufsize = datalen;
    param.bufpos = 0;
    param.expire = expire;

    memc_set (ctx, &param, expire);
    /* Set save point */
    r->save.saved = 1;
    XSRETURN_EMPTY;

void
rspamd_task_delete_memcached_key (r, key, callback)
    CODE:
    struct worker_task *r;
    char *key;
    SV *callback;
    struct _param {
        SV *callback;
        struct worker_task *task;
    } *callback_data;
    memcached_ctx_t *ctx;
    memcached_param_t param;

    perl_set_session (r);
    key = (char *) SvPV_nolen (ST(1));
    callback = SvRV (ST(2));

    /* Copy old ctx to new one */
    ctx = memory_pool_alloc (r->task_pool, sizeof (memcached_ctx_t));
    if (ctx == NULL) {
        XSRETURN_UNDEF;
    }
    memcpy (ctx, r->memc_ctx, sizeof (memcached_ctx_t));
    /* Set perl callback */
    ctx->callback = perl_call_memcached_callback;
    callback_data = memory_pool_alloc (r->task_pool, sizeof (struct _param));
    if (callback_data == NULL) {
		XSRETURN_UNDEF;
    }
    callback_data->callback = callback;
    callback_data->task = r;
    ctx->callback_data = (void *)callback_data;

    g_strlcpy (param.key, key, sizeof (param.key));
    param.buf = NULL;
    param.bufsize = 0;
    param.bufpos = 0;
    param.expire = 0;

    memc_delete (ctx, &param);
    /* Set save point */
    r->save.saved = 1;
    XSRETURN_EMPTY;

void
rspamd_task_get_conf (r)
CODE:
    struct worker_task *r;
	dXSTARG;

    perl_set_session (r);

	sv_setref_pv (TARG, "rspamd_config", r->cfg);
	ST(0) = TARG;


MODULE = rspamd   PACKAGE = rspamd_config PREFIX = rspamd_config_
PROTOTYPES: DISABLE

void
rspamd_config_get_scalar (r, param)
CODE:
    struct config_file *r;
    struct config_scalar *sc;
    char *param;
    int val;
	dXSTARG;

    perl_set_config (r);
    param = (char *) SvPV_nolen (ST(1));

    sc = g_hash_table_lookup (r->cfg_params, param);
    if (sc == NULL) {
        XSRETURN_UNDEF;
    }
    else {
        switch (sc->type) {
            case SCALAR_TYPE_SIZE:
                val = (int)(*(size_t *)sc->pointer);
                sv_upgrade (TARG, SVt_IV);
	            sv_setiv (TARG, val);
                break;
            case SCALAR_TYPE_INT:
            case SCALAR_TYPE_UINT:
                val = *(int *)sc->pointer;
                sv_upgrade (TARG, SVt_IV);
	            sv_setiv (TARG, val);
                break;
            case SCALAR_TYPE_STR:
                sv_upgrade (TARG, SVt_PV);
                SvPOK_on(TARG);
	            sv_setpv (TARG, (char *)sc->pointer);
                break;
        }
    }
	ST(0) = TARG;

void
rspamd_config_set_scalar (r, param, value)
CODE:
    struct config_file *r;
    struct config_scalar *sc;
    char *param, *charval;
    int intval;
	dXSTARG;

    perl_set_config (r);
    param = (char *) SvPV_nolen (ST(1));

    sc = g_hash_table_lookup (r->cfg_params, param);
    if (sc == NULL) {
        XSRETURN_UNDEF;
    }
    else {
        switch (sc->type) {
            case SCALAR_TYPE_SIZE:
                intval = (int)SvIV (ST(2));
                *((size_t *)sc->pointer) = intval;
                sv_upgrade (TARG, SVt_IV);
	            sv_setiv (TARG, intval);
                break;
            case SCALAR_TYPE_INT:
            case SCALAR_TYPE_UINT:
                intval = (int)SvIV (ST(2));
                *((int *)sc->pointer) = intval;
                sv_upgrade (TARG, SVt_IV);
	            sv_setiv (TARG, intval);
                break;
            case SCALAR_TYPE_STR:
                charval = (char *)SvPVX (ST(2));
                *((char **)sc->pointer) = charval;
                sv_upgrade (TARG, SVt_PV);
	            sv_setpv (TARG, charval);
                break;
        }
    }
	ST(0) = TARG;

HV *
rspamd_config_set_metric (r, name)
CODE:
    struct config_file *r;
    struct metric *val;
    char *name;
    
    perl_set_config (r);
    name = (char *) SvPV_nolen (ST(1));

    val = g_hash_table_lookup (r->metrics, name);
    if (val == NULL) {
        XSRETURN_UNDEF;
    }
    else {
     	RETVAL = newHV();

	    (void)hv_store_ent (RETVAL, 
				newSVpv ("name", sizeof ("name") - 1), 
				newSVpv (val->name, strlen (val->name)), 0);
	    (void)hv_store_ent (RETVAL, 
				newSVpv ("func_name", sizeof ("func_name") - 1), 
				newSVpv (val->func_name, strlen (val->func_name)), 0);
	    (void)hv_store_ent (RETVAL, 
				newSVpv ("required_score", sizeof ("required_score") - 1), 
				newSVnv (val->required_score), 0);
        sv_2mortal((SV*)RETVAL);
    }
OUTPUT:
    RETVAL

HV *
rspamd_config_set_statfile (r, name)
CODE:
    struct config_file *r;
    struct statfile *val;
    char *name;
    
    perl_set_config (r);
    name = (char *) SvPV_nolen (ST(1));

    val = g_hash_table_lookup (r->statfiles, name);
    if (val == NULL) {
        XSRETURN_UNDEF;
    }
    else {
     	RETVAL = newHV();

	    (void)hv_store_ent (RETVAL, 
				newSVpv ("alias", sizeof ("alias") - 1), 
				newSVpv (val->alias, strlen (val->alias)), 0);
	    (void)hv_store_ent (RETVAL, 
				newSVpv ("pattern", sizeof ("pattern") - 1), 
				newSVpv (val->pattern, strlen (val->pattern)), 0);
	    (void)hv_store_ent (RETVAL, 
				newSVpv ("metric", sizeof ("metric") - 1), 
				newSVpv (val->metric, strlen (val->metric)), 0);
	    (void)hv_store_ent (RETVAL, 
				newSVpv ("weight", sizeof ("weight") - 1), 
				newSVnv (val->weight), 0);
	    (void)hv_store_ent (RETVAL, 
				newSVpv ("size", sizeof ("size") - 1), 
				newSViv (val->size), 0);
        sv_2mortal((SV*)RETVAL);
    }
OUTPUT:
    RETVAL

void
rspamd_config_get_module_param (r, modulename, paramname)
	CODE:
	struct config_file *r;
	char *module, *param, *value;

	dXSTARG;
	perl_set_config (r);
	module = (char *) SvPV_nolen (ST(1));
	param = (char *) SvPV_nolen (ST(2));

	value = get_module_opt (r, module, param);
	if (value == NULL) {
		XSRETURN_UNDEF;
	}

	sv_upgrade(TARG, SVt_PV);
	sv_setpv(TARG, value);

	ST(0) = TARG;

MODULE = rspamd   PACKAGE = rspamd_log PREFIX = rspamd_log_
PROTOTYPES: DISABLE

void
rspamd_log_log (level, str)
    CODE:
    int level;
    char *str;
    
    level = (int)SvIV (ST(0));
    str = (char *)SvPV_nolen (ST(1));
    
    g_log (G_LOG_DOMAIN, level, "%s", str);
    XSRETURN_EMPTY;

