/*
 * Perl XS module for interacting with rspamd
 *
 * vi:ts=4 
 */

#include "../src/config.h"
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include "../src/main.h"
#include "../src/message.h"
#include "../src/cfg_file.h"
#include "../src/perl.h"
#include "../src/mem_pool.h"
#include "../src/fuzzy.h"

#define XSINTERFACE_FUNC_RSPAMD_MESSAGE_SET(cv,f)      \
	CvXSUBANY(cv).any_dptr = (void (*) (pTHX_ void*))(CAT2( g_mime_message_,f ))
#define XSINTERFACE_FUNC_RSPAMD_PART_SET(cv,f)      \
	CvXSUBANY(cv).any_dptr = (void (*) (pTHX_ void*))(CAT2( g_mime_part_,f ))
#define XSINTERFACE_FUNC_RSPAMD_IA_SET(cv,f)      \
	CvXSUBANY(cv).any_dptr = (void (*) (pTHX_ void*))(CAT2( internet_address_,f ))

struct raw_header {
    struct raw_header *next;
    char *name;
    char *value;
};			

typedef struct _GMimeHeader {
	GHashTable *hash;
	GHashTable *writers;
	struct raw_header *headers;
} local_GMimeHeader;

/* enums */
#ifdef GMIME24
typedef GMimeContentEncoding Mail__Rspamd__PartEncodingType;
typedef int	Mail__Rspamd__InternetAddressType;
#else
typedef InternetAddressType	Mail__Rspamd__InternetAddressType;
typedef GMimePartEncodingType	Mail__Rspamd__PartEncodingType;
#endif

/* C types */
typedef GMimeObject *		Mail__Rspamd__Object;
typedef GMimeParam *		Mail__Rspamd__Param;
typedef GMimePart *		Mail__Rspamd__Part;
typedef struct mime_text_part * Mail__Rspamd__TextPart;
typedef GMimeParser *		Mail__Rspamd__Parser;
typedef GMimeMultipart *	Mail__Rspamd__MultiPart;
typedef GMimeMessage *		Mail__Rspamd__Message;
typedef GMimeMessagePart *	Mail__Rspamd__MessagePart;
typedef GMimeMessagePartial *	Mail__Rspamd__MessagePartial;
typedef InternetAddress *	Mail__Rspamd__InternetAddress;
#ifdef GMIME24
typedef GMimeContentDisposition *	Mail__Rspamd__Disposition;
#else
typedef GMimeDisposition *	Mail__Rspamd__Disposition;
#endif
typedef GMimeContentType *	Mail__Rspamd__ContentType;
typedef GMimeCharset *		Mail__Rspamd__Charset;

/*
 * Declarations for message header hash array
 */

static gboolean
recipients_destroy (gpointer key, gpointer value, gpointer user_data)
{
	InternetAddressList *recipients = value;
	internet_address_list_destroy (recipients);

	return TRUE;
}

typedef struct {
        int				keyindex;	/* key index for firstkey */
        char			*fetchvalue;	/* value for each() method fetched with FETCH */
        Mail__Rspamd__Message	objptr;		/* any object pointer */
} hash_header;

typedef hash_header *Mail__Rspamd__Hash__Header;


/*
 * Double linked list of perl allocated pointers (for DESTROY xsubs)
 */
static GList *plist = NULL;

/*
 * Calling callback function for each mime part
 */
struct _user_data_sv {
	SV *  svfunc;
	SV *  svuser_data;
	SV *  svfunc_complete;
	SV *  svfunc_sizeout;
};

static void
call_sub_foreach(GMimeObject *mime_object, gpointer data)
{
	SV * svpart;
	SV * rvpart;

	dSP ;
	struct _user_data_sv *svdata;

	svdata = (struct _user_data_sv *) data;
	svpart = sv_newmortal ();

	if (GMIME_IS_PART(mime_object)) {
		rvpart = sv_setref_pv(svpart, "Mail::Rspamd::Part", (Mail__Rspamd__Part)mime_object);
	} else {
		rvpart = sv_setref_pv(svpart, "Mail::Rspamd::Object", mime_object);
	}
		
	PUSHMARK (sp);
	XPUSHs (rvpart);
	XPUSHs (sv_mortalcopy (svdata->svuser_data));
	PUTBACK ;
	if (svdata->svfunc) {
		perl_call_sv (svdata->svfunc, G_DISCARD);
	}
}




MODULE = Mail::Rspamd   PACKAGE = Mail::Rspamd::Log PREFIX = rspamd_log_
PROTOTYPES: DISABLE

void
rspamd_log_log (level, str)
	int level
	const char *str
    CODE:
    	g_log (G_LOG_DOMAIN, level, "%s", str);


MODULE = Mail::Rspamd   PACKAGE = Mail::Rspamd

INCLUDE: Rspamd/Object.xs
INCLUDE: Rspamd/ContentType.xs
INCLUDE: Rspamd/Part.xs
INCLUDE: Rspamd/Message.xs

INCLUDE: Rspamd/InternetAddress.xs
INCLUDE: Rspamd/Hash.xs
INCLUDE: Rspamd/TextPart.xs


