%%{

  machine smtp_date_parser;
  alphtype unsigned char;
  include smtp_base "smtp_base.rl";
  include smtp_date "smtp_date.rl";

  main := date_time;
}%%

#include "smtp_parsers.h"
#include "util.h"

%% write data;

static int
rspamd_smtp_date_days_in_month (int mon, int year)
{
  static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

  if (mon == 1 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0)) {
    return 29;
  }

  return days[mon];
}

uint64_t
rspamd_parse_smtp_date (const unsigned char *data, size_t len, GError **err)
{
  const unsigned char *p = data, *pe = data + len, *eof = data + len, *tmp = data;
  struct tm tm;
  glong tz = 0;
  int cs = 0, *stack = NULL;;
  gsize top = 0;

  memset (&tm, 0, sizeof (tm));

  struct _ragel_st_storage {
    int *data;
    gsize size;
  } st_storage;
  memset (&st_storage, 0, sizeof (st_storage));

  %% write init;
  %% write exec;

    if (st_storage.data) {
        free (st_storage.data);
    }

  if ( cs < %%{ write first_final; }%% ) {
    /* p may equal pe (input ended, or fbreak on the last byte): no char */
    g_set_error (err, g_quark_from_static_string ("smtp_date"), cs, "invalid date at offset %d (%c), state %d",
			(int)(p - data), (p < pe && *p > 0 && *p < 128) ? *p : '?', cs);
    return (uint64_t)(-1);
  }

  /* The grammar takes any day from 1 to 31, whatever the month */
  if (tm.tm_mday > rspamd_smtp_date_days_in_month (tm.tm_mon, tm.tm_year + 1900)) {
    g_set_error (err, g_quark_from_static_string ("smtp_date"), cs,
        "invalid date: day %d is past the end of the month", tm.tm_mday);
    return (uint64_t)(-1);
  }

  /* RFC 5322: the last two digits of a zone are minutes, 00 to 59 */
  if ((tz < 0 ? -tz : tz) % 100 > 59) {
    g_set_error (err, g_quark_from_static_string ("smtp_date"), cs,
        "invalid date: zone minutes over 59");
    return (uint64_t)(-1);
  }

  return rspamd_tm_to_time (&tm, tz);
}