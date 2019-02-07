%%{

  machine smtp_addr_parser;

  action IP6_start {}
  action IP6_end {}
  action IP4_start {}
  action IP4_end {}

  action User_start {
    addr->user = p;
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

  action User_has_backslash {
    addr->flags |= RSPAMD_EMAIL_ADDR_HAS_BACKSLASH;
  }

  action Quoted_addr {
    addr->flags |= RSPAMD_EMAIL_ADDR_QUOTED;
  }

  action Empty_addr {
    addr->flags |= RSPAMD_EMAIL_ADDR_EMPTY|RSPAMD_EMAIL_ADDR_VALID;
    addr->addr = "";
    addr->user = addr->addr;
    addr->domain = addr->addr;
  }

  action Valid_addr {
    if (addr->addr_len > 0) {
      addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
    }
  }

  action Addr_has_angle {
    addr->flags |= RSPAMD_EMAIL_ADDR_BRACED;
  }

  action Addr_start {
    addr->addr = p;
  }

  action Addr_end {
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }

  include smtp_base "smtp_base.rl";
  include smtp_ip "smtp_ip.rl";
  include smtp_address "smtp_address.rl";

  main := SMTPAddr;
}%%

#include "smtp_parsers.h"

%% write data;

int
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
