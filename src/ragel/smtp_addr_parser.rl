%%{

  machine smtp_addr_parser;

  action User_start {
    addr->user = p;
    addr->addr = p;
  }

  action User_end {
    if (addr->user) {
      addr->user_len = p - addr->user;
    }
  }

  action Domain_start {
    addr->domain = p;
  }

  action Domain_end {
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }

  action Domain_addr_start {
    addr->domain = p;
    addr->flags |= RSPAMD_EMAIL_ADDR_IP;
  }

  action Domain_addr_end {
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }

  action Quoted_addr {
    addr->flags |= RSPAMD_EMAIL_ADDR_QUOTED;
  }

  action Empty_addr {
    addr->flags |= RSPAMD_EMAIL_ADDR_EMPTY;
    addr->addr = "";
  }

  action Valid_addr {
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }

  action Angled_addr {
    addr->flags |= RSPAMD_EMAIL_ADDR_BRACED;
  }

  include smtp_address "smtp_address.rl";

  main := SMTPAddr;
}%%

%% write data;

static int
rspamd_smtp_addr_parse (const char *data, size_t len, struct rspamd_email_address *addr)
{
  const char *p = data, *pe = data + len, *eof;
  int cs;

  g_assert (addr != NULL);
  memset (addr, 0, sizeof (*addr));
  addr->raw = data;
  addr->raw_len = len;
  eof = pe;

  %% write init;
  %% write exec;

  return cs;
}
