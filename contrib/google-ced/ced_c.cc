#include "ced_c.h"
#include "compact_enc_det.h"

const char* ced_encoding_detect(const char* text, int text_length,
								const char* url_hint,
								const char* http_charset_hint,
								const char* meta_charset_hint,
								const int encoding_hint,
								CedTextCorpusType corpus_type, bool ignore_7bit_mail_encodings,
								int* bytes_consumed, bool* is_reliable)
{
	CompactEncDet::TextCorpusType ct = CompactEncDet::NUM_CORPA;

	ct = static_cast<CompactEncDet::TextCorpusType>(corpus_type);

	auto enc = CompactEncDet::DetectEncoding(text, text_length, url_hint,
			http_charset_hint, meta_charset_hint, encoding_hint, default_language(),
			ct, ignore_7bit_mail_encodings, bytes_consumed, is_reliable);

	if (IsValidEncoding(enc)) {
		return MimeEncodingName(enc);
	}

	return nullptr;
}
