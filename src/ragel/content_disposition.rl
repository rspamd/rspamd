%%{
  machine content_disposition;

  # https://tools.ietf.org/html/rfc2045#section-5.1

  ccontent = ctext | FWS | '(' @{ fcall balanced_ccontent; };
  balanced_ccontent := ccontent* ')' @{ fret; };
  comment        =   "(" (FWS? ccontent)* FWS? ")";
  CFWS           =   ((FWS? comment)+ FWS?) | FWS;
  qcontent = qtextSMTP | quoted_pairSMTP | textUTF8;
  quoted_string = CFWS?
                  (DQUOTE
                    (((FWS? qcontent)* FWS?) >Quoted_Str_Start %Quoted_Str_End)
                  DQUOTE) CFWS?;
  token = 0x21..0x27 | 0x2a..0x2b | 0x2c..0x2e | 0x30..0x39 | 0x41..0x5a | 0x5e..0x7e;
  value = (quoted_string | (token -- '"' | 0x3d | utf8_2c | utf8_3c | utf8_4c)+) >Param_Value_Start %Param_Value_End;
  attribute = (quoted_string | (token -- '"' | 0x3d)+) >Param_Name_Start %Param_Name_End;
  parameter = CFWS? attribute FWS? "=" FWS? value CFWS?;

  ietf_token = token+;
  custom_x_token = /x/i "-" token+;
  extension_token = ietf_token | custom_x_token;
  disposition_type = /inline/i %Disposition_Inline | /attachment/i %Disposition_Attachment
    | extension_token >Disposition_Start %Disposition_End;
  disposition_parm = parameter;
  content_disposition = disposition_type (";" disposition_parm)*;

  prepush {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  }
}%%
