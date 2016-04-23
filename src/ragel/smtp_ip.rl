%%{
  machine smtp_ip;

  # Parses IPv4/IPv6 address
  # Source: https://tools.ietf.org/html/rfc5321#section-4.1.3

  Snum           = digit{1,3};
  IPv4_address_literal  = Snum ("."  Snum){3};
  IPv6_hex       = xdigit{1,4};
  IPv6_full      = IPv6_hex (":" IPv6_hex){7};
  IPv6_comp      = (IPv6_hex (":" IPv6_hex){0,5})? "::"
                  (IPv6_hex (":" IPv6_hex){0,5})?;
  IPv6v4_full    = IPv6_hex (":" IPv6_hex){5} ":" IPv4_address_literal;
  IPv6v4_comp    = (IPv6_hex (":" IPv6_hex){0,3})? "::"
                  (IPv6_hex (":" IPv6_hex){0,3} ":")?
                  IPv4_address_literal;
  IPv6_addr      = IPv6_full | IPv6_comp | IPv6v4_full | IPv6v4_comp;
  IPv6_address_literal  = "IPv6:" IPv6_addr;
}%%