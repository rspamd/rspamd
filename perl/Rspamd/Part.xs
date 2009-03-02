MODULE = Mail::Rspamd PACKAGE = Mail::Rspamd::Part PREFIX = rspamd_part

Mail::Rspamd::Part
g_mime_part_new (Class = "Mail::Rspamd::Part", type = "text", subtype = "plain")
		char *		Class;
		const char *		type;
		const char *		subtype;
	CODE:
		RETVAL = g_mime_part_new_with_type (type, subtype);
		plist = g_list_prepend (plist, RETVAL);
	OUTPUT:
		RETVAL

void
DESTROY (mime_part)
		Mail::Rspamd::Part	mime_part
	CODE:
		if (g_list_find (plist,mime_part)) {
			g_object_unref (G_OBJECT (mime_part));
			plist = g_list_remove (plist, mime_part);
		}

void
interface_p_set(mime_part, value)
	Mail::Rspamd::Part	mime_part
	char *				value
	INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_RSPAMD_PART_SET
	INTERFACE:
	set_content_description
	set_content_md5
	set_content_location
	set_filename


const char *
interface_p_get(mime_part)
	Mail::Rspamd::Part	mime_part
	INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_RSPAMD_PART_SET
	INTERFACE:
	get_content_description
	get_content_md5
	get_content_location
	get_filename

#if !defined(GMIME24)

void
rspamd_part_set_content_header (mime_part, field, value)
		Mail::Rspamd::Part	mime_part
		const char *		field
		const char *		value
	CODE:
		g_mime_part_set_content_header (mime_part, field, value);

const char *
rspamd_part_get_content_header (mime_part, field)
		Mail::Rspamd::Part	mime_part
		const char *		field
	CODE:
		RETVAL = g_mime_part_get_content_header (mime_part, field);
	OUTPUT:
		RETVAL

#endif

void
rspamd_part_set_content_type (mime_part, content_type)
		Mail::Rspamd::Part		mime_part
		Mail::Rspamd::ContentType	content_type
	CODE:
		g_mime_part_set_content_type (mime_part, content_type);
		plist = g_list_remove (plist, content_type);


void
rspamd_part_set_encoding (mime_part, encoding)
		Mail::Rspamd::Part			mime_part
		Mail::Rspamd::PartEncodingType		encoding
	CODE:
		g_mime_part_set_encoding (mime_part, encoding);

Mail::Rspamd::PartEncodingType
rspamd_part_get_encoding (mime_part)
		Mail::Rspamd::Part	mime_part
	CODE:
		RETVAL = g_mime_part_get_encoding (mime_part);
	OUTPUT:
		RETVAL

const char *
rspamd_part_encoding_to_string (encoding)
		Mail::Rspamd::PartEncodingType		encoding
	PREINIT:
	CODE:
#ifdef GMIME24
		RETVAL = g_mime_content_encoding_to_string (encoding);
#else
		RETVAL = g_mime_part_encoding_to_string (encoding);
#endif
	OUTPUT:
		RETVAL

Mail::Rspamd::PartEncodingType
rspamd_part_encoding_from_string (encoding)
		const char *		encoding
	CODE:
#ifdef GMIME24
		RETVAL = g_mime_content_encoding_from_string (encoding);
#else
		RETVAL = g_mime_part_encoding_from_string (encoding);
#endif
	OUTPUT:
		RETVAL

void
rspamd_part_add_content_disposition_parameter (mime_part, name, value)
		Mail::Rspamd::Part	mime_part
		const char *		name
		const char *		value
	CODE:
#ifdef GMIME24
		g_mime_object_add_content_disposition_parameter (GMIME_OBJECT (mime_part), name, value);
#else
		g_mime_part_add_content_disposition_parameter (mime_part, name, value);
#endif

const char *
rspamd_part_get_content_disposition_parameter (mime_part, name)
		Mail::Rspamd::Part	mime_part
		const char *		name
	CODE:
#ifdef GMIME24
		RETVAL = g_mime_object_get_content_disposition_parameter (GMIME_OBJECT (mime_part), name);
#else
		RETVAL = g_mime_part_get_content_disposition_parameter (mime_part, name);
#endif
	OUTPUT:
		RETVAL


void
rspamd_part_set_pre_encoded_content(mime_part, content, encoding)
		Mail::Rspamd::Part	mime_part
		SV *		content
		Mail::Rspamd::PartEncodingType	encoding
	PREINIT:
		char *	data;
		STRLEN	len;
	CODE:
		data = SvPV (content, len);
		g_mime_part_set_pre_encoded_content (mime_part, data, len, encoding);


SV *
rspamd_part_get_content(mime_part)
		Mail::Rspamd::Part	mime_part
	PREINIT:
#ifdef GMIME24
		GMimeDataWrapper *wrapper;
        GMimeStream *part_stream;
        GByteArray *part_content;
#else
		guint len;
		const char * content_char;
#endif
		SV * content;
	CODE:
		ST(0) = &PL_sv_undef;
#ifdef GMIME24
		if (!(mime_part->content) || !(mime_part->content->stream) ||
			 (wrapper = g_mime_part_get_content_object (mime_part)) == NULL) {
#else
		if (!(mime_part->content) || !(mime_part->content->stream) ||
			 (content_char = g_mime_part_get_content (mime_part, &len)) == NULL) {
#endif
			return;
		}
		content = sv_newmortal ();
		SvUPGRADE (content, SVt_PV);
		SvREADONLY_on (content);
#ifdef GMIME24
		part_stream = g_mime_stream_mem_new ();
		g_mime_data_wrapper_write_to_stream (wrapper, part_stream);
		part_content = g_mime_stream_mem_get_byte_array (GMIME_STREAM_MEM (part_stream));
		SvPVX(content) = (char *) (part_content->data);
		SvCUR_set (content, part_content->len);
#else
		SvPVX(content) = (char *) (content_char);
		SvCUR_set (content, len);
#endif
		SvLEN_set (content, 0);
		SvPOK_only (content);
		ST(0) = content;

