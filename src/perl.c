#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <glib.h>

#include <EXTERN.h>               /* from the Perl distribution     */
#include <perl.h>                 /* from the Perl distribution     */

#include "url.h"
#include "main.h"
#include "perl.h"

extern PerlInterpreter *my_perl;

int
perl_call_header_filter (const char *function, struct worker_task *task)
{
	int result;
	dSP;

	ENTER;
	SAVETMPS;

	PUSHMARK (SP);
	XPUSHs (sv_2mortal (newSViv (PTR2IV (task))));
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
	dSP;

	ENTER;
	SAVETMPS;

	PUSHMARK (SP);
	XPUSHs (sv_2mortal (newSViv (PTR2IV (task))));
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
	dSP;

	ENTER;
	SAVETMPS;

	PUSHMARK (SP);
	XPUSHs (sv_2mortal (newSViv (PTR2IV (task))));
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
	dSP;

	ENTER;
	SAVETMPS;
	
	PUSHMARK (SP);
	XPUSHs (sv_2mortal (newSViv (PTR2IV (task))));
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

	dSP;
	
	ENTER;
	SAVETMPS;
	av = newAV();
	av_extend (av, number);
	for (i = 0; i < number; i ++) {
		av_push (av, sv_2mortal (newSViv (marks[i])));
	}
	PUSHMARK (SP);
	XPUSHs (sv_2mortal (newSViv (PTR2IV (task))));
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
	
	dSP;

	ENTER;
	SAVETMPS;
	PUSHMARK (SP);
	XPUSHs (sv_2mortal (newSViv (PTR2IV (callback_data->task))));
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
