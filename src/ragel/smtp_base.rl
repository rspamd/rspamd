%%{
  machine smtp_base;

  # Base SMTP definitions
  # Dependencies: none
  # Required actions: none

  WSP             =   " ";
  CRLF            =   "\r\n" | ("\r" [^\n]) | ([^\r] "\n");
  DQUOTE = '"';

  utf8_cont = 0x80..0xbf;
  utf8_2c   = 0xc0..0xdf utf8_cont;
  utf8_3c   = 0xe0..0xef utf8_cont utf8_cont;
  utf8_4c   = 0xf0..0xf7 utf8_cont utf8_cont utf8_cont;
  UTF8_non_ascii  =   utf8_2c | utf8_3c | utf8_4c;

  # Printable US-ASCII characters not including specials
  atext = alpha | digit | "!" | "#" | "$" | "%" | "&" |
          "'" | "*" | "+" | "_" | "/" | "=" | "?" | "^" |
          "-" | "`" | "{" | "|" | "}" | "~" | UTF8_non_ascii;
  # Printable US-ASCII characters not including "[", "]", or "\"
  dtext = 33..90 | 94..126 | UTF8_non_ascii;
  # Printable US-ASCII characters not including  "(", ")", or "\"
  ctext = 33..39 | 42..91 | 93..126 | UTF8_non_ascii;

  dcontent       = 33..90 | 94..126 | UTF8_non_ascii;
  Let_dig        = alpha | digit | UTF8_non_ascii;
  Ldh_str        = ( Let_dig | "_" | "-" )* Let_dig;

  quoted_pairSMTP  = "\\" 32..126;
  qtextSMTP      = 32..33 | 35..91 | 93..126 | UTF8_non_ascii;
  Atom           = atext+;
  Dot_string     = Atom ("."  Atom)*;
  dot_atom_text  = atext+ ("." atext+)*;
  #FWS            =   ((WSP* CRLF)? WSP+);
  FWS            = WSP+; # We work with unfolded headers, so we can simplify machine

  sub_domain     = Let_dig Ldh_str?;
  Domain = sub_domain ("." sub_domain)*;
  Atdomain = "@" Domain;
  Adl = Atdomain ( "," Atdomain )*;

  Standardized_tag = Ldh_str;
}%%