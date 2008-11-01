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

#include "../src/config.h"
#include "../src/main.h"
#include "../src/cfg_file.h"
#include "../src/perl.h"
#include "../src/mem_pool.h"

#define perl_set_session(r)													\
	r = INT2PTR(struct worker_task *, SvIV((SV *) SvRV(ST(0))))

#define perl_set_targ(p, len)													\
	SvUPGRADE(TARG, SVt_PV);													\
	SvPOK_on(TARG);																\
	sv_setpvn(TARG, (char *) p, len)

MODULE = rspamd	PACKAGE = rspamd
PROTOTYPES: DISABLE

void
get_header (r, header)
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
		ngx_http_perl_set_targ (s, strlen (s));
		ST(0) = TARG;
	}

void
get_part_num (r)
	CODE:
	dXSTARG;
	struct worker_task *r;

	perl_set_session (r);
	sv_upgrade(TARG, SVt_IV);
	sv_setiv(TARG, r->parts_count);

	ST(0) = TARG;


HV *
get_part (r, num)
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

	TAILQ_FOREACH (part, &r->parts, next) {
		if (--number == 0) {
			break;
		}
	}
	RETVAL = newHV();
	type = g_mime_content_type_to_string (part->type);

	hv_store_ent (RETVAL, 
				newSVpv ("type", sizeof ("type") - 1), 
				newSVpv (type, strlen(type)), 0);
	hv_store_ent (RETVAL, 
				newSVpv ("content", sizeof ("content") - 1), 
				newSVpv ((char *)part->content->data, part->content->len), 0);
    sv_2mortal((SV*)RETVAL);
	OUTPUT:
	RETVAL

void
ip (r)
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
from (r)
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
save_point (r)
    CODE:
	struct worker_task *r;

	perl_set_session (r);
    r->save.saved = 1;

void
recall_filter (r)
    CODE:
    struct worker_task *r;

	perl_set_session (r);
    process_filters (r);

void
insert_result (r, metric, symbol, flag)
	CODE:
	struct worker_task *r;
	char *metric, *symbol;
	int flag;
	STRLEN metriclen, symbollen;

	perl_set_session (r);
	metric = (char *) SvPV (ST(1), metriclen);
	symbol = (char *) SvPV (ST(2), symbollen);
	flag = (int) SvIV (ST(3));

	insert_result (r, metric, symbol, flag);

void
get_module_param (r, modulename, paramname)
	CODE:
	struct worker_task *r;
	char *module, *param, *value;
	STRLEN modulelen, paramlen;

	dXSTARG;
	perl_set_session (r);
	module = (char *) SvPV (ST(1), modulelen);
	param = (char *) SvPV (ST(2), paramlen);

	value = get_module_opt (r->worker->srv->cfg, module, param);
	if (value == NULL) {
		XSRETURN_UNDEF;
	}

	sv_upgrade(TARG, SVt_PV);
	sv_setpv(TARG, value);

	ST(0) = TARG;

void
read_memcached_key (r, key, datalen, callback)
    CODE:
    struct worker_task *r;
    char *key;
    unsigned int datalen;
    SV *callback;
    STRLEN keylen;
    struct _param {
        SV *callback;
        struct worker_task *task;
    } *callback_data;
    memcached_ctx_t *ctx;
    memcached_param_t param;

    perl_set_session (r);
    key = (char *) SvPV (ST(1), keylen);
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

    strlcpy (param.key, key, sizeof (param.key));
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
write_memcached_key (r, key, data, expire, callback)
    CODE:
    struct worker_task *r;
    char *key, *data;
    SV *callback;
    STRLEN keylen, datalen;
    int expire;
    struct _param {
        SV *callback;
        struct worker_task *task;
    } *callback_data;
    memcached_ctx_t *ctx;
    memcached_param_t param;

    perl_set_session (r);
    key = (char *) SvPV (ST(1), keylen);
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

    strlcpy (param.key, key, sizeof (param.key));
    param.buf = data;
    param.bufsize = datalen;
    param.bufpos = 0;
    param.expire = expire;

    memc_set (ctx, &param, expire);
    /* Set save point */
    r->save.saved = 1;
    XSRETURN_EMPTY;

void
delete_memcached_key (r, key, callback)
    CODE:
    struct worker_task *r;
    char *key;
    SV *callback;
    STRLEN keylen;
    struct _param {
        SV *callback;
        struct worker_task *task;
    } *callback_data;
    memcached_ctx_t *ctx;
    memcached_param_t param;

    perl_set_session (r);
    key = (char *) SvPV (ST(1), keylen);
    callback = SvRV(ST(2));

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

    strlcpy (param.key, key, sizeof (param.key));
    param.buf = NULL;
    param.bufsize = 0;
    param.bufpos = 0;
    param.expire = 0;

    memc_delete (ctx, &param);
    /* Set save point */
    r->save.saved = 1;
    XSRETURN_EMPTY;

