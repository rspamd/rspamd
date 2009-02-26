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
typedef GMimePartEncodingType	Mail__Rspamd__PartEncodingType;
typedef InternetAddressType	Mail__Rspamd__InternetAddressType;

/* C types */
typedef GMimeObject *		Mail__Rspamd__Object;
typedef GMimeParam *		Mail__Rspamd__Param;
typedef GMimePart *		Mail__Rspamd__Part;
typedef GMimeParser *		Mail__Rspamd__Parser;
typedef GMimeMultipart *	Mail__Rspamd__MultiPart;
typedef GMimeMessage *		Mail__Rspamd__Message;
typedef GMimeMessagePart *	Mail__Rspamd__MessagePart;
typedef GMimeMessagePartial *	Mail__Rspamd__MessagePartial;
typedef InternetAddress *	Mail__Rspamd__InternetAddress;
typedef GMimeDisposition *	Mail__Rspamd__Disposition;
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
/* known header field types */
enum {
	HEADER_FROM = 0,
	HEADER_REPLY_TO,
	HEADER_TO,
	HEADER_CC,
	HEADER_BCC,
	HEADER_SUBJECT,
	HEADER_DATE,
	HEADER_MESSAGE_ID,
	HEADER_UNKNOWN
};

static GList *
local_message_get_header(GMimeMessage *message, const char *field)
{
	struct raw_header *h;
	GList *	gret = NULL;

	if (field == NULL) {
		return NULL;
	}
	h = GMIME_OBJECT(message)->headers->headers;
	while (h) {
		if (h->value && !g_strncasecmp(field, h->name, strlen(field))) {
			gret = g_list_prepend(gret, g_strdup(h->value));
		}
		h = h->next;
	}
	return gret;
}

/**
* g_mime_message_set_date_from_string: Set the message sent-date
* @message: MIME Message
* @string: A string of date
* 
* Set the sent-date on a MIME Message.
**/			 
static void
local_mime_message_set_date_from_string (GMimeMessage *message, const gchar *string) 
{
	time_t date;
	int offset = 0;

	date = g_mime_utils_header_decode_date (string, &offset);
	g_mime_message_set_date (message, date, offset); 
}



/* different declarations for different types of set and get functions */
typedef const char *(*GetFunc) (GMimeMessage *message);
typedef InternetAddressList *(*GetRcptFunc) (GMimeMessage *message, const char *type );
typedef GList *(*GetListFunc) (GMimeMessage *message, const char *type );
typedef void	 (*SetFunc) (GMimeMessage *message, const char *value);
typedef void	 (*SetListFunc) (GMimeMessage *message, const char *field, const char *value);

/** different types of functions
*
* FUNC_CHARPTR
*	- function with no arguments
*	- get returns char*
*
* FUNC_IA (from Internet Address)
*	- function with additional "field" argument from the fieldfunc table,
*	- get returns Glist*
*
* FUNC_LIST
*	- function with additional "field" argument (given arbitrary header field name)
*	- get returns Glist*
**/
enum {
	FUNC_CHARPTR = 0,
	FUNC_CHARFREEPTR,
	FUNC_IA,
	FUNC_LIST
};

/**
* fieldfunc struct: structure of MIME fields and corresponding get and set
* functions.
**/
static struct {
	char *	name;
	GetFunc	func;
	GetRcptFunc	rcptfunc;
	GetListFunc	getlistfunc;
	SetFunc	setfunc;
	SetListFunc	setlfunc;
	gint		functype;
} fieldfunc[] = {
	{ "From",		g_mime_message_get_sender,		NULL, NULL,				g_mime_message_set_sender,	NULL, FUNC_CHARPTR },
	{ "Reply-To",	g_mime_message_get_reply_to,	NULL, NULL,				g_mime_message_set_reply_to,	NULL, FUNC_CHARPTR },
	{ "To",	NULL,	g_mime_message_get_recipients,	NULL, NULL, 			g_mime_message_add_recipients_from_string, FUNC_IA },
	{ "Cc",	NULL,	g_mime_message_get_recipients,	NULL, NULL, 			g_mime_message_add_recipients_from_string, FUNC_IA },
	{ "Bcc",	NULL,	g_mime_message_get_recipients,	NULL, NULL, 		g_mime_message_add_recipients_from_string, FUNC_IA },
	{ "Subject",	g_mime_message_get_subject,		NULL, NULL,				g_mime_message_set_subject,	NULL, FUNC_CHARPTR },
	{ "Date",		g_mime_message_get_date_string, NULL, NULL,				local_mime_message_set_date_from_string,	NULL, FUNC_CHARFREEPTR },
	{ "Message-Id",	g_mime_message_get_message_id,	NULL, NULL,				g_mime_message_set_message_id,	NULL, FUNC_CHARPTR },
	{ NULL,	NULL,	NULL,	local_message_get_header,	  NULL,				g_mime_message_add_header, FUNC_LIST }
};

/**
* message_set_header: set header of any type excluding special (Content- and MIME-Version:)
**/
static void
message_set_header (GMimeMessage *message, const char *field, const char *value) 
{
	gint i;


	if (!g_strcasecmp (field, "MIME-Version:") || !g_strncasecmp (field, "Content-", 8)) {
		return;
	}
	for (i=0; i<=HEADER_UNKNOWN; ++i) {
		if (!fieldfunc[i].name || !g_strncasecmp(field, fieldfunc[i].name, strlen(fieldfunc[i].name))) { 
			switch (fieldfunc[i].functype) {
				case FUNC_CHARPTR:
					(*(fieldfunc[i].setfunc))(message, value);
					break;
				case FUNC_IA:
					(*(fieldfunc[i].setlfunc))(message, fieldfunc[i].name, value);
					break;
				case FUNC_LIST:
					(*(fieldfunc[i].setlfunc))(message, field, value);
					break;
			}
			break;
		}		 
	}
}


/**
* message_get_header: returns the list of 'any header' values
* (except of unsupported yet Content- and MIME-Version special headers)
*
* You should free the GList list by yourself.
**/
static
GList *
message_get_header(GMimeMessage *message, const char *field) {
	gint		i;
	char *	ret = NULL;
	GList *	gret = NULL;
	InternetAddressList *ia_list = NULL, *ia;

	for (i = 0; i <= HEADER_UNKNOWN; ++i) {
		if (!fieldfunc[i].name || !g_strncasecmp(field, fieldfunc[i].name, strlen(fieldfunc[i].name))) { 
			switch (fieldfunc[i].functype) {
				case FUNC_CHARFREEPTR:
					ret = (char *)(*(fieldfunc[i].func))(message);
					break;
				case FUNC_CHARPTR:
					ret = (char *)(*(fieldfunc[i].func))(message);
					break;
				case FUNC_IA:
					ia_list = (*(fieldfunc[i].rcptfunc))(message, field);
					gret = g_list_alloc();
					ia = ia_list;
					while (ia && ia->address) {
						char *ia_string;

						ia_string = internet_address_to_string ((InternetAddress *)ia->address, FALSE);
						gret = g_list_append (gret, ia_string);
						ia = ia->next;
					}
					break;
				case FUNC_LIST:
					gret = (*(fieldfunc[i].getlistfunc))(message, field);
					break;
			}
			break;
		}		 
	}
	if (gret == NULL && ret != NULL) {
		gret = g_list_prepend (gret, g_strdup (ret));
	}
	if (fieldfunc[i].functype == FUNC_CHARFREEPTR && ret) {
		g_free (ret);
	}
	return gret;
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


