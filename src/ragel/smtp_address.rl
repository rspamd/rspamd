%%{
  machine smtp_address;

  include smtp_ip "smtp_ip.rl";
  include smtp_whitespace "smtp_whitespace.rl";

  # SMTP address spec
  # Obtained from: https://tools.ietf.org/html/rfc5321#section-4.1.2

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
  UnangledPath = ( Adl ":" )? Mailbox >Addr_start %Addr_end "."?;
  AngledPath = "<" UnangledPath ">" %Addr_has_angle;
  Path = AngledPath | UnangledPath;
  SMTPAddr = space* (Path | "<>" %Empty_addr ) %Valid_addr space*;

}%%
