MODULE = Mail::Rspamd PACKAGE = Mail::Rspamd::ContentType PREFIX = rspamd_content_type_

Mail::Rspamd::ContentType
rspamd_content_type_new (Class = "Mail::Rspamd::ContentType", name = 0, subname = 0)
	CASE: items == 2
		char *		Class;
		const char *	name;
	CODE:
		RETVAL = g_mime_content_type_new_from_string (name);
		plist = g_list_prepend (plist, RETVAL);
	OUTPUT:
		RETVAL
	CASE: items == 3
		char *		Class;
		const char *	name;
		const char *	subname;
	CODE:
		RETVAL = g_mime_content_type_new (name, subname);
		plist = g_list_prepend (plist, RETVAL);
	OUTPUT:
		RETVAL

void
DESTROY (mime_type)
		Mail::Rspamd::ContentType		mime_type
	CODE:
		if (g_list_find(plist,mime_type)) {
			g_mime_content_type_destroy(mime_type);
			plist = g_list_remove(plist, mime_type);
		}

SV *
rspamd_content_type_to_string (mime_type)
		Mail::Rspamd::ContentType		mime_type
	PREINIT:
		char *	type;
	CODE:
		type = g_mime_content_type_to_string (mime_type);
		if (!type)
	  		XSRETURN_UNDEF;
		RETVAL = newSVpv(type, 0);
		g_free (type);
	OUTPUT:
		RETVAL

gboolean
rspamd_content_type_is_type (mime_type, type, subtype)
		Mail::Rspamd::ContentType		mime_type
		const char *			type
		const char *			subtype
	CODE:
		RETVAL = g_mime_content_type_is_type (mime_type, type, subtype);
	OUTPUT:
		RETVAL

void
rspamd_content_type_set_parameter (mime_type, attribute, value)
		Mail::Rspamd::ContentType		mime_type
		const char *			attribute
		const char *			value
	CODE:
		g_mime_content_type_set_parameter (mime_type, attribute, value);

const char *
rspamd_content_type_get_parameter (mime_type, attribute)
		Mail::Rspamd::ContentType		mime_type
		const char *			attribute
	CODE:
		RETVAL = g_mime_content_type_get_parameter (mime_type, attribute);
	OUTPUT:
		RETVAL

char *
rspamd_content_type_type (ctype)
		Mail::Rspamd::ContentType	ctype
	CODE:
		RETVAL = ctype->type;
	OUTPUT:
		RETVAL
		
char *
rspamd_content_type_subtype (ctype)
		Mail::Rspamd::ContentType	ctype
	CODE:
		RETVAL = ctype->subtype;
	OUTPUT:
		RETVAL
