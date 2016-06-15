%%{
  machine smtp_whitespace;

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
  Atom           = atext+;
  Dot_string     = Atom ("."  Atom)*;
  dot_atom_text  = atext+ ("." atext+)*;
  #FWS            =   ((WSP* CRLF)? WSP+);
  FWS            = WSP+; # We work with unfolded headers, so we can simplify machine
}%%