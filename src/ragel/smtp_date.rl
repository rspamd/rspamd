%%{
  machine smtp_date;

  include smtp_whitespace "smtp_whitespace.rl";

  # SMTP date spec
  # Obtained from: http://tools.ietf.org/html/rfc5322#section_3.3

  digit_2         =   digit{2};
  digit_4         =   digit{4};
  day_name        =    "Mon" | "Tue" | "Wed" | "Thu" |
                       "Fri" | "Sat" | "Sun";
  day_of_week     =   FWS? day_name;
  day             =   FWS? digit{1,2} FWS;
  month           =    "Jan" | "Feb" | "Mar" | "Apr" |
                       "May" | "Jun" | "Jul" | "Aug" |
                       "Sep" | "Oct" | "Nov" | "Dec";
  year            =   FWS digit{4,} FWS;
  date            =   day month year;
  hour            =   digit_2;
  minute          =   digit_2;
  second          =   digit_2;
  time_of_day     =   hour ":" minute (":" second )?;
  zone            =   FWS ("+" | "-") digit_4;
  time            =   time_of_day zone;
  date_time       =   (day_of_week ",")? date time;
}%%