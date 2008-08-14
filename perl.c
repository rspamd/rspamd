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
perl_call_header_filter (const char *function, const char *header_name, const char *header_value)
{
	int result;
	dSP;

	ENTER;
	SAVETMPS;

	PUSHMARK (SP);
	XPUSHs (sv_2mortal (newSVpv (header_name, 0)));
	XPUSHs (sv_2mortal (newSVpv (header_value, 0)));
	PUTBACK;
	
	call_pv (function, G_SCALAR);

	SPAGAIN;

	result = POPi;
	msg_debug ("header_filter: call of %s with header %s returned mark %d\n", function, header_name, result);

	PUTBACK;
	FREETMPS;
	LEAVE;

	return result;
}

int
perl_call_mime_filter (const char *function, GByteArray *content)
{
	int result;
	dSP;

	ENTER;
	SAVETMPS;

	PUSHMARK (SP);
	XPUSHs (sv_2mortal (newSVpv (content->data, content->len)));
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
perl_call_message_filter (const char *function, GByteArray *content)
{
	int result;
	dSP;

	ENTER;
	SAVETMPS;

	PUSHMARK (SP);
	XPUSHs (sv_2mortal (newSVpv (content->data, content->len)));
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
perl_call_url_filter (const char *function, struct uri *uri)
{
	int result;
	dSP;

	ENTER;
	SAVETMPS;
	
	/* URL:
	 * url,
	 * host,
	 * data
	 */
	PUSHMARK (SP);
	XPUSHs (sv_2mortal (newSVpv (uri->string, 0)));
	XPUSHs (sv_2mortal (newSVpv (uri->host, uri->hostlen)));
	XPUSHs (sv_2mortal (newSVpv (uri->data, uri->datalen)));
	PUTBACK;
	
	call_pv (function, G_SCALAR);

	SPAGAIN;

	result = POPi;
	msg_debug ("url_filter: call of %s for url '%s' returned mark %d\n", function, uri->string, result);

	PUTBACK;
	FREETMPS;
	LEAVE;

	return result;
}

int
perl_call_chain_filter (const char *function, GArray *results)
{
	int result, i;

	dSP;

	ENTER;
	SAVETMPS;
	PUSHMARK (SP);
	for (i = 0; i < results->len; i ++) {
		XPUSHs (sv_2mortal (newSViv (g_array_index (results, int, i))));
	}
	PUTBACK;
	
	call_pv (function, G_SCALAR);

	SPAGAIN;

	result = POPi;
	msg_debug ("chain_filter: call of %s returned mark %d\n", function, result);

	PUTBACK;
	FREETMPS;
	LEAVE;


	return result;
}
