/*
 * Perl XS module for interacting with rspamd
 *
 * vi:ts=4 
 */

#include <sys/types.h>
#include <unistd.h>
#include "../config.h"
#include "../main.h"

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

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

