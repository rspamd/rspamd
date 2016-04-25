%%{
  machine smtp_address;

  include smtp_ip "smtp_ip.rl";

  # SMTP address spec
  # Obtained from: https://tools.ietf.org/html/rfc5321#section-4.1.2

  LF = "\n";
  CR = "\r";
  CRLF = "\r\n";
  DQUOTE = '"';

  atext = alpha | digit | "!" | "#" | "$" | "%" | "&" |
          "'" | "*" | "+" | "_" | "/" | "=" | "?" | "^" |
          "_" | "`" | "{" | "|" | "}" | "~";

  dcontent       = 33..90 | 94..126;
  Let_dig        = alpha | digit;
  Ldh_str        = ( alpha | digit | "_" )* Let_dig;

  quoted_pairSMTP  = "\\" 32..126;
  qtextSMTP      = 32..33 | 35..91 | 93..126;
  Atom           = atext+;
  Dot_string     = Atom ("."  Atom)*;

  QcontentSMTP   = qtextSMTP | quoted_pairSMTP %User_has_backslash;
  Quoted_string  = ( DQUOTE QcontentSMTP* >User_start %User_end DQUOTE ) %Quoted_addr;
  Local_part     = Dot_string >User_start %User_end | Quoted_string;
  String         = Atom | Quoted_string;

  Standardized_tag = Ldh_str;
  General_address_literal  = Standardized_tag ":" dcontent+;
  address_literal  = "[" ( IPv4_address_literal |
                    IPv6_address_literal |
                    General_address_literal ) >Domain_addr_start %Domain_addr_end "]";


  sub_domain     = Let_dig Ldh_str?;
  Domain = sub_domain ("." sub_domain)*;
  Atdomain = "@" Domain;
  Adl = Atdomain ( "," Atdomain )*;

  Mailbox        = Local_part "@" (address_literal | Domain >Domain_start %Domain_end);
  UnangledPath = ( Adl ":" )? Mailbox;
  AngledPath = "<" UnangledPath >Angled_addr_start %Angled_addr_end ">";
  Path = AngledPath | UnangledPath >Unangled_addr_start %Unangled_addr_end;
  SMTPAddr = space* (Path | "<>" %Empty_addr ) %Valid_addr space*;

}%%
