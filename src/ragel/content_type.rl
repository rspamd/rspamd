%%{
  machine content_type;
  include smtp_whitespace "smtp_whitespace.rl";

  # https://tools.ietf.org/html/rfc2045#section-5.1

  ccontent = ctext | FWS | '(' @{ fcall balanced_ccontent; };
  balanced_ccontent := ccontent* ')' @{ fret; };
  comment        =   "(" (FWS? ccontent)* FWS? ")";
  CFWS           =   ((FWS? comment)+ FWS?) | FWS;
  qcontent = qtextSMTP | quoted_pairSMTP;
  quoted_string = (DQUOTE
                    (((FWS? qcontent)* FWS?) >Quoted_Str_Start %Quoted_Str_End)
                  DQUOTE);
  token = 0x21..0x27 | 0x2a..0x2b | 0x2c..0x2e | 0x30..0x39 | 0x41..0x5a | 0x5e..0x7e;
  value = (quoted_string | (token)+) >Param_Value_Start %Param_Value_End;
  attribute = (token+) >Param_Name_Start %Param_Name_End;
  parameter = CFWS? attribute FWS? "=" FWS? value CFWS?;

  ietf_token = token+;
  custom_x_token = 'x'i "-" token+;
  extension_token = ietf_token | custom_x_token;
  iana_token = token+;
  main_type = (extension_token) >Type_Start %Type_End;
  sub_type = (extension_token | iana_token) >Subtype_Start %Subtype_End;
  content_type = main_type ("/" sub_type)? (((CFWS? ";"+) | CFWS) parameter CFWS?)*;

  prepush {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  }
}%%