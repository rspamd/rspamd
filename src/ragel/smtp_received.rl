%%{
  machine smtp_received;

  include smtp_whitespace "smtp_whitespace.rl";
  include smtp_ip "smtp_ip.rl";
  include smtp_date "smtp_date.rl";
  include smtp_address"smtp_address.rl";

  # http://tools.ietf.org/html/rfc5321#section-4.4

  Addtl_Link     = Atom;
  Link           = "TCP" | Addtl_Link;
  Attdl_Protocol = Atom;
  Protocol       = "ESMTP" %ESMTP_proto |
                   "SMTP" %SMTP_proto |
                   "ESMTPS" %ESMTPS_proto |
                   "ESMTPA" %ESMTPA_proto |
                   "ESMTPSA" %ESMTPSA_proto |
                   "LMTP" %LMTP_proto |
                   "IMAP" %IMAP_proto |
                   Attdl_Protocol;

  TCP_info       = address_literal >Real_IP_Start %Real_IP_End |
                  ( Domain >Real_Domain_Start %Real_Domain_End FWS address_literal >Real_IP_Start %Real_IP_End );
  Extended_Domain  = Domain >Real_Domain_Start %Real_Domain_End | # Used to be a real domain
                  ( Domain >Reported_Domain_Start %Reported_Domain_End FWS "(" TCP_info ")" ) | # Here domain is something specified by remote side
                  ( address_literal >Real_Domain_Start %Real_Domain_End FWS "(" TCP_info ")" ) |
                  address_literal >Real_IP_Start %Real_IP_End; # Not RFC conforming, but many MTA try this

  exim_real_ip = "[" (IPv4_addr|IPv6_simple) >IP4_start %IP4_end "]"
                  >Real_IP_Start %Real_IP_End (":" digit{1,4})?;
  exim_content = exim_real_ip;
  ccontent = ctext | FWS | '(' @{ fcall balanced_ccontent; };
  balanced_ccontent := ccontent* ')' @{ fret; };
  comment        =   "(" (FWS? ccontent|exim_content)* FWS? ")";
  CFWS           =   ((FWS? comment)+ FWS?) | FWS;

  From_domain    = "FROM"i FWS Extended_Domain >From_Start %From_End;
  By_domain      = "BY"i FWS Extended_Domain >By_Start %By_End;

  Via            = CFWS "VIA"i FWS Link;
  With           = CFWS "WITH"i FWS Protocol;

  id_left        = dot_atom_text;
  no_fold_literal = "[" dtext* "]";
  id_right       = dot_atom_text | no_fold_literal;
  msg_id         = "<" id_left "@" id_right ">";
  ID             = CFWS "ID"i FWS ( Dot_string | msg_id );

  For            = CFWS "FOR"i FWS ( Path | Mailbox ) >For_Start %For_End;
  Additional_Registered_Clauses  = CFWS Atom FWS String;
  Opt_info       = Via? With? ID? For? Additional_Registered_Clauses?;
  # Here we make From part optional just because many received headers lack it
  Received       = From_domain? CFWS? By_domain? CFWS? Opt_info CFWS? ";" FWS date_time >Date_Start %Date_End CFWS?;

  prepush {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  }
}%%
