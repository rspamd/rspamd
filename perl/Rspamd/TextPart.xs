MODULE = Mail::Rspamd PACKAGE = Mail::Rspamd::TextPart PREFIX = rspamd_text_part_

SV *
rspamd_text_part_get_content (mime_part)
		Mail::Rspamd::TextPart	mime_part
	PREINIT:
		SV* content;
	CODE:
		ST(0) = &PL_sv_undef;
		content = sv_newmortal ();
		SvUPGRADE (content, SVt_PV);
		SvREADONLY_on (content);
		SvPVX(content) = (char *) (mime_part->content->data);
		SvCUR_set (content, mime_part->content->len);
		SvLEN_set (content, 0);
		SvPOK_only (content);
		ST(0) = content;

char *
rspamd_text_part_get_fuzzy (mime_part)
		Mail::Rspamd::TextPart	mime_part
	CODE:
		RETVAL = mime_part->fuzzy->hash_pipe;

int
rspamd_text_part_compare_distance (mime_part, other)
		Mail::Rspamd::TextPart	mime_part
		Mail::Rspamd::TextPart	other
	CODE:
		RETVAL = fuzzy_compare_hashes (mime_part->fuzzy, other->fuzzy);
	OUTPUT:
		RETVAL

int
rspamd_text_part_is_html (mime_part)
		Mail::Rspamd::TextPart	mime_part
	CODE:
		RETVAL = mime_part->is_html;
	OUTPUT:
		RETVAL
