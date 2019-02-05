%%{

  machine smtp_date_parser;
  include smtp_base "smtp_base.rl";
  include smtp_date "smtp_date.rl";

  main := date_time;
}%%

#include "smtp_parsers.h"
#include "util.h"

%% write data;

guint64
rspamd_parse_smtp_date (const char *data, size_t len)
{
  const gchar *p = data, *pe = data + len, *eof = data + len, *tmp = data;
  struct tm tm;
  glong tz = 0;
  gint cs = 0;

  memset (&tm, 0, sizeof (tm));

  %% write init;
  %% write exec;

  return rspamd_tm_to_time (&tm, tz);
}