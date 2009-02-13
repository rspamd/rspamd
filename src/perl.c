#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <glib.h>

#include "url.h"
#include "main.h"
#include "perl.h"
#include "cfg_file.h"

/* Perl module init function */
#define MODULE_INIT_FUNC "module_init"

PerlInterpreter *perl_interpreter;

static HV  *rspamd_task_stash;
static HV  *rspamd_cfg_stash;

extern void boot_DynaLoader (pTHX_ CV* cv);
extern void boot_Socket (pTHX_ CV* cv);

void
xs_init(pTHX)
{
	dXSUB_SYS;
	/* DynaLoader is a special case */
	newXS ("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);

    rspamd_task_stash = gv_stashpv("rspamd_task", TRUE);
    rspamd_cfg_stash = gv_stashpv("rspamd_config", TRUE);
}

void
init_perl_filters (struct config_file *cfg)
{
	struct perl_module *module;
    char *init_func;
    size_t funclen;
	SV* sv;
    
	dTHXa (perl_interpreter);
	PERL_SET_CONTEXT (perl_interpreter);

    dSP;
	LIST_FOREACH (module, &cfg->perl_modules, next) {
		if (module->path) {
			require_pv (module->path);
            ENTER;
	        SAVETMPS;

	        PUSHMARK (SP);
			sv = sv_2mortal (sv_bless (newRV_noinc (newSViv (PTR2IV(cfg))), rspamd_cfg_stash));
	        XPUSHs (sv);
	        PUTBACK;
	        /* Call module init function */
            funclen = strlen (module->path) + sizeof ("::") + sizeof (MODULE_INIT_FUNC) - 1;
            init_func = g_malloc (funclen);
            snprintf (init_func, funclen, "%s::%s", module->path, MODULE_INIT_FUNC);
            call_pv (init_func, G_DISCARD);

            FREETMPS;
            LEAVE;
		}
	}
}


int
perl_call_header_filter (const char *function, struct worker_task *task)
{
	int result;
	SV* sv;

	dTHXa (perl_interpreter);
	PERL_SET_CONTEXT (perl_interpreter);

	dSP;
	ENTER;
	SAVETMPS;

	PUSHMARK (SP);
	sv = sv_2mortal (sv_bless (newRV_noinc (newSViv (PTR2IV(task))), rspamd_task_stash));
	XPUSHs (sv);
	PUTBACK;
	
	call_pv (function, G_SCALAR);

	SPAGAIN;

	result = POPi;
	msg_debug ("header_filter: call of %s with returned mark %d\n", function, result);

	PUTBACK;
	FREETMPS;
	LEAVE;

	return result;
}

int
perl_call_mime_filter (const char *function, struct worker_task *task)
{
	int result;
	SV *sv;

	dTHXa (perl_interpreter);
	PERL_SET_CONTEXT (perl_interpreter);

	dSP;
	ENTER;
	SAVETMPS;

	PUSHMARK (SP);
	sv = sv_2mortal (sv_bless (newRV_noinc (newSViv (PTR2IV(task))), rspamd_task_stash));
	XPUSHs (sv);
	PUTBACK;
	
	call_pv (function, G_SCALAR);

	SPAGAIN;

	result = POPi;
	msg_debug ("mime_filter: call of %s returned mark %d\n", function, result);

	PUTBACK;
	FREETMPS;
	LEAVE;

	return result;
}

int
perl_call_message_filter (const char *function, struct worker_task *task)
{
	int result;
	SV *sv;

	dTHXa (perl_interpreter);
	PERL_SET_CONTEXT (perl_interpreter);

	dSP;
	ENTER;
	SAVETMPS;

	PUSHMARK (SP);
	sv = sv_2mortal (sv_bless (newRV_noinc (newSViv (PTR2IV(task))), rspamd_task_stash));
	XPUSHs (sv);
	PUTBACK;
	
	call_pv (function, G_SCALAR);

	SPAGAIN;

	result = POPi;
	msg_debug ("message_filter: call of %s returned mark %d\n", function, result);

	PUTBACK;
	FREETMPS;
	LEAVE;

	return result;
}

int
perl_call_url_filter (const char *function, struct worker_task *task)
{
	int result;
	SV *sv;

	dTHXa (perl_interpreter);
	PERL_SET_CONTEXT (perl_interpreter);

	dSP;
	ENTER;
	SAVETMPS;
	
	PUSHMARK (SP);
	sv = sv_2mortal (sv_bless (newRV_noinc (newSViv (PTR2IV(task))), rspamd_task_stash));
	XPUSHs (sv);
	PUTBACK;
	
	call_pv (function, G_SCALAR);

	SPAGAIN;

	result = POPi;
	msg_debug ("url_filter: call of %s for url returned mark %d\n", function, result);

	PUTBACK;
	FREETMPS;
	LEAVE;

	return result;
}

int
perl_call_chain_filter (const char *function, struct worker_task *task, int *marks, unsigned int number)
{
	int result, i;
	AV *av;
	SV *sv;

	dTHXa (perl_interpreter);
	PERL_SET_CONTEXT (perl_interpreter);

	dSP;
	
	ENTER;
	SAVETMPS;
	av = newAV();
	av_extend (av, number);
	for (i = 0; i < number; i ++) {
		av_push (av, sv_2mortal (newSViv (marks[i])));
	}
	PUSHMARK (SP);
	sv = sv_2mortal (sv_bless (newRV_noinc (newSViv (PTR2IV(task))), rspamd_task_stash));
	XPUSHs (sv);
	XPUSHs (sv_2mortal ((SV *)AvARRAY (av)));
	PUTBACK;
	
	call_pv (function, G_SCALAR);

	SPAGAIN;

	result = POPi;
	msg_debug ("chain_filter: call of %s returned mark %d\n", function, result);

	PUTBACK;
	FREETMPS;
	av_undef (av);
	LEAVE;


	return result;
}

void perl_call_memcached_callback (memcached_ctx_t *ctx, memc_error_t error, void *data)
{
	struct {
        SV *callback;
        struct worker_task *task;
    } *callback_data = data;
	SV *sv;
	
	dTHXa (perl_interpreter);
	PERL_SET_CONTEXT (perl_interpreter);

	dSP;

	ENTER;
	SAVETMPS;
	PUSHMARK (SP);
	sv = sv_2mortal (sv_bless (newRV_noinc (newSViv (PTR2IV(callback_data->task))), rspamd_task_stash));
	XPUSHs (sv);
	XPUSHs (sv_2mortal (newSViv (error)));
	XPUSHs (sv_2mortal (newSVpv (ctx->param->buf, ctx->param->bufsize)));
	PUTBACK;

	call_sv (callback_data->callback, G_SCALAR);
	
    /* Set save point */
    callback_data->task->save.saved = 0;
	process_filters (callback_data->task);

	SPAGAIN;
	FREETMPS;
	LEAVE;

}
