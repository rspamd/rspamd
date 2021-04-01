%%{
  # It actually implements rfc2047 + rfc2231 extension
  machine rfc2047_parser;

  action Start_Charset {
    charset_start = p;
  }

  action End_Charset {
    if (charset_start && p > charset_start) {
      charset_end = p;
    }
  }

  action End_Encoding {
    if (p > in) {
      switch (*(p - 1)) {
      case 'B':
      case 'b':
        encoding = RSPAMD_RFC2047_BASE64;
        break;
      default:
        encoding = RSPAMD_RFC2047_QP;
        break;
      }
    }
  }

  action Start_Encoded {
    encoded_start = p;
  }

  action End_Encoded {
    if (encoded_start && p > encoded_start) {
      encoded_end = p;
    }
  }

  primary_tag = alpha{1,8};
  subtag = alpha{1,8};
  language = primary_tag ( "-" subtag )*;
  especials = "(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\"" | "/" | "[" | "]" | "?" | "." | "=" | "*";
  token = (graph - especials)+;
  charset = token;
  encoding = "Q" | "q" | "B" | "b";
  encoded_text = (print+ -- ("?="));
  encoded_word = "=?" charset >Start_Charset %End_Charset
    ("*" language)? "?"
    encoding %End_Encoding "?"
    encoded_text >Start_Encoded %End_Encoded
    "?="?;
  main := encoded_word;
}%%

#include "smtp_parsers.h"
#include "mime_headers.h"

%% write data;

gboolean
rspamd_rfc2047_parser (const gchar *in, gsize len, gint *pencoding,
  const gchar **charset, gsize *charset_len,
  const gchar **encoded, gsize *encoded_len)
{
  const char *p = in, *pe = in + len,
    *encoded_start = NULL, *encoded_end = NULL,
    *charset_start = NULL, *charset_end = NULL,
    *eof = in + len;
  gint encoding = RSPAMD_RFC2047_QP, cs = 0;

  %% write init;
  %% write exec;

  if (encoded_end) {
    *pencoding = encoding;
    *charset = charset_start;
    *charset_len = charset_end - charset_start;
    *encoded = encoded_start;
    *encoded_len = encoded_end - encoded_start;

    return TRUE;
  }

  return FALSE;
}
