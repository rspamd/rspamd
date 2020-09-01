%%{
  machine smtp_base;

  # Base SMTP definitions
  # Dependencies: none
  # Required actions: none

  WSP             =   " ";
  CRLF            =   "\r\n" | ("\r" [^\n]) | ([^\r] "\n");
  DQUOTE = '"';

  # Printable US-ASCII characters not including specials
  atext = alpha | digit | "!" | "#" | "$" | "%" | "&" |
          "'" | "*" | "+" | "_" | "/" | "=" | "?" | "^" |
          "-" | "`" | "{" | "|" | "}" | "~";
  # Printable US-ASCII characters not including "[", "]", or "\"
  dtext = 33..90 | 94..126;
  # Printable US-ASCII characters not including  "(", ")", or "\"
  ctext = 33..39 | 42..91 | 93..126;

  dcontent       = 33..90 | 94..126;
  Let_dig        = alpha | digit;
  Ldh_str        = ( alpha | digit | "_" | "-" )* Let_dig;

  quoted_pairSMTP  = "\\" 32..126;
  qtextSMTP      = 32..33 | 35..91 | 93..126;
  utf8_cont = 0x80..0xbf;
  utf8_2c   = 0xc0..0xdf utf8_cont;
  utf8_3c   = 0xe0..0xef utf8_cont utf8_cont;
  utf8_4c   = 0xf0..0xf7 utf8_cont utf8_cont utf8_cont;
  textUTF8  = qtextSMTP | utf8_2c | utf8_3c | utf8_4c;
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