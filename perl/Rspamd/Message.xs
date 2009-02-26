MODULE = Mail::Rspamd PACKAGE = Mail::Rspamd::Message PREFIX = rspamd_message_

Mail::Rspamd::Message
rspamd_message_new(Class, pretty_headers = FALSE)
		char *		Class
		gboolean	pretty_headers
	CODE:
		RETVAL = g_mime_message_new (pretty_headers);
		plist = g_list_prepend(plist, RETVAL);
	OUTPUT:
		RETVAL

void
DESTROY(message)
		Mail::Rspamd::Message	message
	CODE:
		if (g_list_find(plist,message)) {
			g_mime_object_unref (GMIME_OBJECT (message));
			plist = g_list_remove(plist, message);
		}

void
rspamd_message_add_recipient(message, type, name, address)
		Mail::Rspamd::Message	message
		char *		type
		const char *	name
		const char *	address
	CODE:
		g_mime_message_add_recipient (message, type, name, address);

void
rspamd_message_add_recipients_from_string(message, type, recipients)
 	Mail::Rspamd::Message	message
		char *		type
		const char *	recipients
	CODE:
		g_mime_message_add_recipients_from_string (message, type, recipients);

AV *
rspamd_message_get_recipients(message, type)
		Mail::Rspamd::Message	message
		const char *	type
	PREINIT:
		const InternetAddressList *		rcpt;
		AV * 		retav;
	CODE:
		retav = newAV();
		rcpt = g_mime_message_get_recipients (message, type);
		while (rcpt) {
		  SV * address = newSViv(0);
		  sv_setref_pv(address, "Mail::Rspamd::InternetAddress", (Mail__Rspamd__InternetAddress)(rcpt->address));
		  av_push(retav, address);
		  rcpt = rcpt->next;
		}
		RETVAL = retav;
	OUTPUT:
		RETVAL


void
interface_m_set (message, value)
		Mail::Rspamd::Message	message
	char *			value
	INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_RSPAMD_MESSAGE_SET
	INTERFACE:
	set_subject
	set_message_id
	set_reply_to
	set_sender

const char *
interface_m_get (message)
		Mail::Rspamd::Message	message
	INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_RSPAMD_MESSAGE_SET
	INTERFACE:
	get_subject
	get_message_id
	get_reply_to
	get_sender
		
 # date
void
rspamd_message_set_date (message, date, gmt_offset)
		Mail::Rspamd::Message	message
		time_t		date
		int		gmt_offset
	CODE:
		g_mime_message_set_date (message, date, gmt_offset);

void
rspamd_message_set_date_from_string (message, str)
		Mail::Rspamd::Message	message
		const char *	str
	PREINIT:
		time_t		date;
		int		offset = 0;
	CODE:
		date = g_mime_utils_header_decode_date (str, &offset);
		g_mime_message_set_date (message, date, offset);


void
rspamd_message_get_date (message)
		Mail::Rspamd::Message	message
	PREINIT:
		time_t		date;
		int		gmt_offset;
		I32		gimme = GIMME_V;
		char *		str;
	PPCODE:
		if (gimme == G_SCALAR) {
			str = g_mime_message_get_date_string (message);
			if (str) {
				XPUSHs (sv_2mortal (newSVpv (str,0)));
				g_free (str);
	  		}
		} else if (gimme == G_ARRAY) {
			g_mime_message_get_date (message, &date, &gmt_offset);
			XPUSHs (sv_2mortal (newSVnv (date)));
			XPUSHs (sv_2mortal (newSViv (gmt_offset)));
		}

void
rspamd_message_set_header (message, field, value)
		Mail::Rspamd::Message	message
		const char *	field
		const char *	value
	CODE:
		g_mime_message_set_header (message, field, value);
		
void
rspamd_message_remove_header (message, field)
		Mail::Rspamd::Message	message
		const char *	field
	CODE:
		g_mime_object_remove_header (GMIME_OBJECT (message), field);

void
rspamd_message_add_header (message, field, value)
		Mail::Rspamd::Message	message
		const char *	field
		const char *	value
	CODE:
		g_mime_message_set_header (message, field, value);

const char *
rspamd_message_get_header (message, field)
		Mail::Rspamd::Message	message
		const char *	field
	CODE:
		RETVAL = g_mime_message_get_header (message, field);
	OUTPUT:
		RETVAL

void
rspamd_message_set_mime_part (message, mime_part)
		Mail::Rspamd::Message	message
		Mail::Rspamd::Object	mime_part
	CODE:
		g_mime_message_set_mime_part (message, GMIME_OBJECT (mime_part));
		plist = g_list_remove (plist, mime_part);

SV *
rspamd_message_get_body (message, want_plain = 1, is_html = 0)
	CASE: items == 1
		Mail::Rspamd::Message	message
	PREINIT:
		gboolean	want_plain = 1;
		gboolean	is_html;
	char *		textdata;
	CODE:
		textdata = g_mime_message_get_body (message, want_plain, &is_html);
	if (textdata == NULL)
	  XSRETURN_UNDEF;
		RETVAL = newSVpv (textdata, 0);
	g_free (textdata);
	OUTPUT:
		RETVAL
	CASE: items == 2
		Mail::Rspamd::Message	message
		gboolean	want_plain
	PREINIT:
		gboolean	is_html;
	char *		textdata;
	CODE:
		textdata = g_mime_message_get_body (message, want_plain, &is_html);
	if (textdata == NULL)
	  XSRETURN_UNDEF;
		RETVAL = newSVpv (textdata, 0);
	g_free (textdata);
	OUTPUT:
		RETVAL
	CASE: items == 3
		Mail::Rspamd::Message	message
		gboolean	want_plain
		gboolean	&is_html
	PREINIT:
	char *		textdata;
	CODE:
		textdata = g_mime_message_get_body (message, want_plain, &is_html);
		if (textdata == NULL) {
			RETVAL = &PL_sv_undef;
		}
		RETVAL = newSVpv (textdata, 0);
		g_free (textdata);
	OUTPUT:
		is_html
		RETVAL
		
SV *
rspamd_message_get_headers(message)
		Mail::Rspamd::Message	message
	PREINIT:
		char *		textdata;
	CODE:
		textdata = g_mime_message_get_headers (message);
		if (textdata == NULL) {
			RETVAL = &PL_sv_undef;
		}
		RETVAL = newSVpv (textdata, 0);
		g_free (textdata);
	OUTPUT:
		RETVAL

void
rspamd_message_foreach_part (message, callback, svdata)
		Mail::Rspamd::Message	message
		SV *			callback
		SV *			svdata
	PREINIT:
		struct _user_data_sv	*data;

	CODE:
		data = g_new0 (struct _user_data_sv, 1);
		data->svuser_data = newSVsv (svdata);
		data->svfunc = newSVsv (callback);
		g_mime_message_foreach_part (message, call_sub_foreach, data);
		g_free (data);

SV *
get_mime_part(message)
		Mail::Rspamd::Message	message
	PREINIT:
		GMimeObject *	mime_object;
	CODE:
		if (message->mime_part != NULL) {
			RETVAL = newSViv(4);
			mime_object = GMIME_OBJECT (message->mime_part);
			if (GMIME_IS_PART(mime_object)) {
				sv_setref_pv(RETVAL, "Mail::Rspamd::Part", (Mail__Rspamd__Part)mime_object);
			} else {
				plist = g_list_prepend(plist, RETVAL);
			}
			g_mime_object_ref( mime_object );
		} else {
			RETVAL = &PL_sv_undef;
		}
	OUTPUT:
		RETVAL

