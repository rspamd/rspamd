%%{
  machine smtp_date;

  # SMTP date spec
  # Obtained from: http://tools.ietf.org/html/rfc5322#section_3.3


  action Day_Start {
    tmp = p;
  }
  action Day_End {
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        if (n > 0 && n <= 31) {
          tm.tm_mday = n;
        }
        else {
          fbreak;
        }
      }
    }
  }
  action Month_End {

  }
  action Year_Start {
    tmp = p;
  }
  action Year_End {
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        /*
         * RFC 5322, 4.3: only two digit years 00-49 are 20xx; other two and
         * three digit years add 1900 ("049" is 1949). Zero-padded four digit
         * years are read the same way: mailers printing tm_year with %04d
         * write 2002 as "0102"
         */
        if (p - tmp == 2 && n < 50) {
          tm.tm_year = n + 100;
        }
        else if (n < 1000) {
          tm.tm_year = n;
        }
        else {
          tm.tm_year = n - 1900;
        }
      }
    }
  }
  action Hour_Start {
    tmp = p;
  }
  action Hour_End {
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        if (n < 24) {
          tm.tm_hour = n;
        }
        else {
          fbreak;
        }
      }
    }
    else {
      fbreak;
    }
  }
  action Minute_Start {
    tmp = p;
  }
  action Minute_End {
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        if (n < 60) {
          tm.tm_min = n;
        }
        else {
          fbreak;
        }
      }
    }
    else {
      fbreak;
    }
  }
  action Second_Start {
    tmp = p;
  }
  action Second_End {
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        if (n <= 60) { /* Leap second */
          tm.tm_sec = n;
        }
        else {
          fbreak;
        }
      }
    }
    else {
      fbreak;
    }
  }
  action TZ_Sign {
    tmp = p;
  }
  action TZ_Offset_Start {

  }
  action TZ_Offset_End {
    if (p > tmp) {
      rspamd_strtoul (tmp, p - tmp, (gulong *)&tz);

      if (*(tmp - 1) == '-') {
        tz = -(tz);
      }
    }
  }
  action Obs_Zone_End {
  }
  action DT_End {
  }

  # Specific actions
  # Months
  action Month_Jan {
    tm.tm_mon = 0;
  }
  action Month_Feb {
    tm.tm_mon = 1;
  }
  action Month_Mar {
    tm.tm_mon = 2;
  }
  action Month_Apr {
    tm.tm_mon = 3;
  }
  action Month_May {
    tm.tm_mon = 4;
  }
  action Month_Jun {
    tm.tm_mon = 5;
  }
  action Month_Jul {
    tm.tm_mon = 6;
  }
  action Month_Aug {
    tm.tm_mon = 7;
  }
  action Month_Sep {
    tm.tm_mon = 8;
  }
  action Month_Oct {
    tm.tm_mon = 9;
  }
  action Month_Nov {
    tm.tm_mon = 10;
  }
  action Month_Dec {
    tm.tm_mon = 11;
  }
  # Obsoleted timezones
  action TZ_UT {
    tz = 0;
  }
  action TZ_GMT {
    tz = 0;
  }
  action TZ_EST {
    tz = -500;
  }
  action TZ_EDT {
    tz = -400;
  }
  action TZ_CST {
    tz = -600;
  }
  action TZ_CDT {
    tz = -500;
  }
  action TZ_MST {
    tz = -700;
  }
  action TZ_MDT {
    tz = -600;
  }
  action TZ_PST {
    tz = -800;
  }
  action TZ_PDT {
    tz = -700;
  }
  prepush {
    if (top >= RSPAMD_RAGEL_MAX_COMMENT_NESTING) {
      /* Too deeply nested comments, bail out instead of growing the stack */
      fbreak;
    }

    if (top >= st_storage.size) {
      gsize _new_size = (top + 1) * 2;
      int *_new_data = realloc (st_storage.data, _new_size * sizeof (int));

      if (_new_data == NULL) {
        /* Keep the old allocation so that it can still be freed */
        fbreak;
      }

      st_storage.size = _new_size;
      st_storage.data = _new_data;
      stack = st_storage.data;
    }
  }
  # RFC 5322 quoted-pair: an escaped character, e.g. "\)" inside a comment
  quoted_pair = "\\" (32..126 | "\t");
  ccontent = ctext | FWS | quoted_pair | '(' @{ fcall balanced_ccontent; };
  balanced_ccontent := ccontent* ')' @{ fret; };
  comment         =   "(" (FWS? ccontent)* FWS? ")";
  CFWS            =   ((FWS? comment)+ FWS?) | FWS;
  digit_2         =   digit{2};
  digit_4         =   digit{4};
  # Names are case-insensitive, as are all literals in RFC 5322's ABNF
  day_name        =    "Mon"i | "Tue"i | "Wed"i | "Thu"i |
                       "Fri"i | "Sat"i | "Sun"i;
  day_of_week     =   FWS? day_name;
  day             =   FWS? digit{1,2} >Day_Start %Day_End FWS;
  month           =    "Jan"i %Month_Jan | "Feb"i %Month_Feb | "Mar"i %Month_Mar | "Apr"i %Month_Apr |
                       "May"i %Month_May | "Jun"i %Month_Jun | "Jul"i %Month_Jul | "Aug"i %Month_Aug |
                       "Sep"i %Month_Sep | "Oct"i %Month_Oct | "Nov"i %Month_Nov | "Dec"i %Month_Dec;
  year            =   FWS digit{2,4} >Year_Start %Year_End FWS;
  date            =   day month %Month_End year;
  hour            =   digit_2;
  minute          =   digit_2;
  second          =   digit_2;
  time_of_day     =   hour >Hour_Start %Hour_End ":" minute >Minute_Start %Minute_End (":" second >Second_Start %Second_End )?;
  zone            =   ("+" | "-") %TZ_Sign digit_4 >TZ_Offset_Start %TZ_Offset_End;
  # "UTC" is not an RFC 5322 obs-zone, but some mailers write it
  obs_zone        =   "UT"i %TZ_UT | "UTC"i %TZ_UT | "GMT"i %TZ_GMT |
                     "EST"i %TZ_EST | "EDT"i %TZ_EDT |
                     "CST"i %TZ_CST | "CDT"i %TZ_CDT |
                     "MST"i %TZ_MST | "MDT"i %TZ_MDT |
                     "PST"i %TZ_PST | "PDT"i %TZ_PDT |
                     [a-iA-I] | [k-zK-Z];
  time            =   time_of_day %DT_End FWS (zone | obs_zone %Obs_Zone_End) FWS*;
  date_time       =   (day_of_week ",")? date time CFWS?;
}%%
