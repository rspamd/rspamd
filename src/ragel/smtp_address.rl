%%{
  machine smtp_address;

  # SMTP address spec
  # Source: https://tools.ietf.org/html/rfc5321#section-4.1.2
  # Dependencies: smtp_base + smtp_ip
  # Required actions:
  #  - User_has_backslash
  #  - User_end
  #  - Quoted_addr
  #  - Domain_start
  #  - Domain_end
  #  - Addr_end
  #  - Addr_has_angle
  #  - Valid_addr
  #  - Empty_addr
  # + from deps:
  #  - IP4_start
  #  - IP4_end
  #  - IP6_start
  #  - IP6_end
  #  - Domain_addr_start
  #  - Domain_addr_end

  # SMTP address spec
  # Obtained from: https://tools.ietf.org/html/rfc5321#section-4.1.2

  QcontentSMTP   = qtextSMTP | quoted_pairSMTP %User_has_backslash;
  Quoted_string  = ( DQUOTE QcontentSMTP* >User_start %User_end DQUOTE ) %Quoted_addr;
  Local_part     = Dot_string >User_start %User_end | Quoted_string;
  Mailbox        = Local_part "@" (address_literal | Domain >Domain_start %Domain_end);
  UnangledPath = ( Adl ":" )? Mailbox >Addr_start %Addr_end "."?;
  AngledPath = "<" FWS? UnangledPath FWS? ">" %Addr_has_angle;
  Path = AngledPath | UnangledPath;
  SMTPAddr = space* (Path | "<>" %Empty_addr ) %Valid_addr space*;
}%%
