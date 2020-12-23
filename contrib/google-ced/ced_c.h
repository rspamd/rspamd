#ifndef RSPAMD_CED_C_H
#define RSPAMD_CED_C_H

#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif
enum CedTextCorpusType {
	CED_WEB_CORPUS,
	CED_XML_CORPUS,
	CED_QUERY_CORPUS,
	CED_EMAIL_CORPUS,
	CED_NUM_CORPA,
};

/*
 * XXX: Rspamd addition: it actually returns Mime format of the encoding
 */
const char *ced_encoding_detect (const char *text, int text_length,
								 const char *url_hint,
								 const char *http_charset_hint,
								 const char *meta_charset_hint,
								 const int encoding_hint,
								 enum CedTextCorpusType corpus_type,
								 bool ignore_7bit_mail_encodings,
								 int *bytes_consumed, bool *is_reliable);

#ifdef  __cplusplus
}
#endif
#endif
