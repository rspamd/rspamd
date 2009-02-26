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
	set_content_disposition
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
	get_content_disposition
	get_filename

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
	CODE:
		RETVAL = g_mime_part_encoding_to_string (encoding);
	OUTPUT:
		RETVAL

Mail::Rspamd::PartEncodingType
rspamd_part_encoding_from_string (encoding)
		const char *		encoding
	CODE:
		RETVAL = g_mime_part_encoding_from_string(encoding);
	OUTPUT:
		RETVAL

void
rspamd_part_add_content_disposition_parameter (mime_part, name, value)
		Mail::Rspamd::Part	mime_part
		const char *		name
		const char *		value
	CODE:
		g_mime_part_add_content_disposition_parameter (mime_part, name, value);

const char *
rspamd_part_get_content_disposition_parameter (mime_part, name)
		Mail::Rspamd::Part	mime_part
		const char *		name
	CODE:
		RETVAL = g_mime_part_get_content_disposition_parameter (mime_part, name);
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
		guint len;
		const char * content_char;
		SV * content;
	CODE:
		ST(0) = &PL_sv_undef;
		if (!(mime_part->content) || !(mime_part->content->stream) ||
			 (content_char = g_mime_part_get_content(mime_part, &len)) == NULL) {
			return;
		}
		content = sv_newmortal ();
		SvUPGRADE (content, SVt_PV);
		SvREADONLY_on (content);
		SvPVX(content) = (char *) (content_char);
		SvCUR_set (content, len);
		SvLEN_set (content, 0);
		SvPOK_only (content);
		ST(0) = content;

