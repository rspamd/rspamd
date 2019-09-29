%%{

  machine smtp_ip_parser;

  action IP6_start {
    in_v6 = 1;
    ip_start = p;
  }
  action IP6_end {
    in_v6 = 0;
    ip_end = p;
  }
  action IP4_start {
    if (!in_v6) {
      ip_start = p;
    }
  }
  action IP4_end {
    if (!in_v6) {
      ip_end = p;
    }
  }

  action Domain_addr_start {}
  action Domain_addr_end {}

  include smtp_base "smtp_base.rl";
  include smtp_ip "smtp_ip.rl";

  main := address_literal | non_conformant_address_literal;
}%%

#include "smtp_parsers.h"
#include "util.h"
#include "addr.h"

%% write data;

rspamd_inet_addr_t *
rspamd_parse_smtp_ip (const char *data, size_t len, rspamd_mempool_t *pool)
{
  const char *p = data, *pe = data + len, *eof = data + len;
  const char *ip_start = NULL, *ip_end = NULL;
  gboolean in_v6 = FALSE;
  gint cs = 0;

  %% write init;
  %% write exec;

  if (ip_start && ip_end && ip_end > ip_start) {
    return rspamd_parse_inet_address_pool (ip_start, ip_end - ip_start, pool,
    		RSPAMD_INET_ADDRESS_PARSE_NO_UNIX|RSPAMD_INET_ADDRESS_PARSE_REMOTE);
  }

  return NULL;
}