%%{
  machine newlines_strip;

  action Double_CRLF {
    if (!crlf_added && p > c) {
      (*newlines_count)++;
      g_byte_array_append (data, (const guint8 *)" ", 1);
      c = p;
    }

    crlf_added = TRUE;
    c = p;
  }

  action WSP {
    g_byte_array_append (data, (const guint8 *)" ", 1);
    c = p;
  }

  action Text_Start {
    crlf_added = FALSE;
    c = p;
  }

  action Text_End {
    if (p > c) {
      g_byte_array_append (data, (const guint8 *)c, p - c);
      last_c = *(p - 1);
    }

    c = p;
  }

  action Line_CRLF {
    if (!crlf_added) {
      if (is_html || g_ascii_ispunct (last_c)) {
         g_byte_array_append (data, (const guint8 *)" ", 1);
         crlf_added = TRUE;
      }
    }

    (*newlines_count)++;
    g_ptr_array_add (newlines, (((gpointer) (goffset) (data->len))));
    c = p;
  }


  WSP   = " " | "\t" | "\v";
  CRLF  = ("\r" . "\n") | ( "\r" ) | ("\n");
  DOUBLE_CRLF = (CRLF <: (WSP* CRLF)+) %Double_CRLF;
  ANY_CRLF = CRLF | DOUBLE_CRLF;
  LINE = (([^\r\n]+) >Text_Start %Text_End);
  TEXT  = ANY_CRLF* . (LINE <: ANY_CRLF %Line_CRLF)+ | LINE | ANY_CRLF %Line_CRLF;

  main := TEXT;
}%%

#include <glib.h>

%% write data;

void
rspamd_strip_newlines_parse (const gchar *begin, const gchar *pe,
    GByteArray *data, gboolean is_html, guint *newlines_count,
    GPtrArray *newlines)
{
  const gchar *c, *p, *eof;
  gint last_c = -1;
  gint cs = 0;
  gboolean crlf_added = FALSE;

  c = begin;
  p = begin;
  eof = pe;

  %% write init;
  %% write exec;

  if (p > c) {
     g_byte_array_append (data, (const guint8 *)c, p - c);
  }
}
