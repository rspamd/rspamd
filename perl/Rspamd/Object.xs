MODULE = Mail::Rspamd PACKAGE = Mail::Rspamd::Object PREFIX = rspamd_object_

void
rspamd_object_set_content_type (mime_object, content_type)
		Mail::Rspamd::Object	mime_object
		Mail::Rspamd::ContentType	content_type
	CODE:
		g_mime_object_set_content_type (mime_object, content_type);
		plist = g_list_remove (plist, content_type);

Mail::Rspamd::ContentType
rspamd_object_get_content_type (mime_object)
		Mail::Rspamd::Object	mime_object
	PREINIT:
		char *			textdata;
		GMimeContentType	*ct;
	CODE:
		ct = g_mime_object_get_content_type (mime_object);
		textdata = g_mime_content_type_to_string (ct);
		RETVAL = g_mime_content_type_new_from_string (textdata);
		plist = g_list_prepend (plist, RETVAL);
		g_free (textdata);
	OUTPUT:
		RETVAL

void
rspamd_object_set_content_type_parameter (mime_object, name, value)
		Mail::Rspamd::Object	mime_object
		const char *		name
		const char *		value
	CODE:
		gmime_object_set_content_type_parameter (mime_object, name, value);

const char *
rspamd_object_get_content_type_parameter (mime_object, name)
		Mail::Rspamd::Object	mime_object
		const char *		name
	CODE:
		RETVAL = g_mime_object_get_content_type_parameter (mime_object, name);
	OUTPUT:
		RETVAL

void
rspamd_object_set_content_id (mime_object, content_id)
		Mail::Rspamd::Object	mime_object
		const char *		content_id
	CODE:
		g_mime_object_set_content_id (mime_object, content_id);

const char *
rspamd_object_get_content_id(mime_object)
		Mail::Rspamd::Object	mime_object
	CODE:
		RETVAL = g_mime_object_get_content_id (mime_object);
	OUTPUT:
		RETVAL


void
rspamd_object_add_header (mime_object, field, value)
		Mail::Rspamd::Object	mime_object
		const char *	field
		const char *	value
	CODE:
		g_mime_object_add_header (mime_object, field, value);

void
rspamd_object_set_header (mime_object, field, value)
		Mail::Rspamd::Object	mime_object
		const char *	field
		const char *	value
	CODE:
		g_mime_object_set_header (mime_object, field, value);

const char *
rspamd_object_get_header (mime_object, field)
		Mail::Rspamd::Object	mime_object
		const char *	field
	CODE:
		RETVAL = g_mime_object_get_header (mime_object, field);
	OUTPUT:
		RETVAL

void
rspamd_object_remove_header (mime_object, field)
		Mail::Rspamd::Object	mime_object
		const char *	field
	CODE:
		g_mime_object_remove_header (mime_object, field);

SV *
rspamd_object_get_headers(mime_object)
		Mail::Rspamd::Object	mime_object
	PREINIT:
		char *		textdata;
	CODE:
		textdata = g_mime_object_get_headers(mime_object);
		if (textdata == NULL) {
			XSRETURN_UNDEF;
		}
		RETVAL = newSVpv (textdata, 0);
		g_free (textdata);
	OUTPUT:
		RETVAL

SV *
rspamd_object_to_string(mime_object)
		Mail::Rspamd::Object	mime_object
	PREINIT:
		char *	textdata;
	CODE:
		textdata = g_mime_object_to_string (mime_object);
		if (textdata) {
	  		RETVAL = newSVpv (textdata, 0);
	  		g_free (textdata);
		} else {
	  		XSRETURN_UNDEF;
		}
	OUTPUT:
		RETVAL

guint
rspamd_object_get_content_length(mime_object)
		Mail::Rspamd::Object	mime_object
	PREINIT:
		guint			lsize = 0;
		GMimePart *		mime_part;
	CODE:
		if (mime_object) {
			if (GMIME_IS_PART(mime_object)) { // also MESSAGE_PARTIAL
				mime_part = GMIME_PART(mime_object);
				lsize = (mime_part->content && mime_part->content->stream) ?
							g_mime_stream_length (mime_part->content->stream) : 0; 
				if (lsize) {
#ifdef GMIME24
					GMimeContentEncoding enc;

					enc = _mime_part_get_encoding (mime_part);
					switch (enc) {
				  		case GMIME_CONTENT_ENCODING_BASE64:
							lsize = BASE64_ENCODE_LEN (lsize);
							break;
				  		case GMIME_CONTENT_ENCODING_QUOTEDPRINTABLE:
							lsize = QP_ENCODE_LEN (lsize);
							break;
					}
#else
					GMimePartEncodingType	enc;

					enc = g_mime_part_get_encoding (mime_part);
					switch (enc) {
				  		case GMIME_PART_ENCODING_BASE64:
							lsize = BASE64_ENCODE_LEN (lsize);
							break;
				  		case GMIME_PART_ENCODING_QUOTEDPRINTABLE:
							lsize = QP_ENCODE_LEN (lsize);
							break;
					}
#endif				
				}
			}
		}
		RETVAL = lsize;
	OUTPUT:
		RETVAL

