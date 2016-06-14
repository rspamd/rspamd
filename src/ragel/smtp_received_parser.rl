%%{

  machine smtp_received_parser;


  action IP6_start {
    ip_start = p;
  }
  action IP6_end {
    ip_end = p;
  }
  action IP4_start {
    ip_start = p;
  }
  action IP4_end {
    ip_end = p;
  }

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
    addr->flags |= RSPAMD_EMAIL_ADDR_EMPTY;
    addr->addr = "";
    addr->user = addr->addr;
    addr->domain = addr->addr;
  }

  action Valid_addr {
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
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

  action Real_Domain_Start {
    real_domain_start = p;
  }
  action Real_Domain_End {
    real_domain_end = p;
  }
  action Reported_Domain_Start {
    reported_domain_start = p;
  }
  action Reported_Domain_End {
    reported_domain_end = p;
  }

  action Real_IP_Start {
    real_domain_start = p;
  }
  action Real_IP_End {
    real_domain_end = p;
  }
  action Reported_IP_Start {
    reported_domain_start = p;
  }
  action Reported_IP_End {
    reported_domain_end = p;
  }

  action From_Start {
    real_domain_start = NULL;
    real_domain_end = NULL;
    real_ip_start = NULL;
    real_ip_end = NULL;
    reported_domain_start = NULL;
    reported_domain_end = NULL;
    reported_ip_start = NULL;
    reported_ip_end = NULL;
    ip_start = NULL;
    ip_end = NULL;
  }

  action By_Start {
    real_domain_start = NULL;
    real_domain_end = NULL;
    real_ip_start = NULL;
    real_ip_end = NULL;
    reported_domain_start = NULL;
    reported_domain_end = NULL;
    reported_ip_start = NULL;
    reported_ip_end = NULL;
    ip_start = NULL;
    ip_end = NULL;
  }

  action By_End {
    /* Do nothing here for now */
  }

  action From_End {
    guint len;

    if (real_domain_end && real_domain_start && real_domain_end > real_domain_start) {
      len = real_domain_end - real_domain_start;
      rh->real_hostname = rspamd_mempool_alloc (task->task_pool, len + 1);
      rspamd_strlcpy (rh->real_hostname, real_domain_start, len + 1);
    }
    if (reported_domain_end && reported_domain_start && reported_domain_end > reported_domain_start) {
      len = reported_domain_end - reported_domain_start;
      rh->from_hostname = rspamd_mempool_alloc (task->task_pool, len + 1);
      rspamd_strlcpy (rh->from_hostname, reported_domain_start, len + 1);
    }
    if (real_ip_end && real_ip_start && real_ip_end > real_ip_start) {
      len = real_ip_end - real_ip_start;
      rh->real_ip = rspamd_mempool_alloc (task->task_pool, len + 1);
      rspamd_strlcpy (rh->real_ip, real_ip_start, len + 1);
    }
    if (reported_ip_end && reported_ip_start && reported_ip_end > reported_ip_start) {
      len = reported_ip_end - reported_ip_start;
      rh->from_ip = rspamd_mempool_alloc (task->task_pool, len + 1);
      rspamd_strlcpy (rh->from_ip, reported_ip_start, len + 1);
    }

    if (rh->real_ip && !rh->from_ip) {
      rh->from_ip = rh->real_ip;
    }
    if (rh->real_hostname && !rh->from_hostname) {
      rh->from_hostname = rh->real_hostname;
    }

    if (rh->real_ip && ip_start && ip_end && ip_end > ip_start) {
      if (rspamd_parse_inet_address (&rh->addr, ip_start, ip_end - ip_start)) {
        rspamd_mempool_add_destructor (task->task_pool, (rspamd_mempool_destruct_t)rspamd_inet_address_destroy, rh->addr);
      }
    }
  }

  action For_End {

  }

  action SMTP_proto {
    rh->type = RSPAMD_RECEIVED_SMTP;
  }
  action ESMTPS_proto {
    rh->type = RSPAMD_RECEIVED_ESMTPS;
  }
  action ESMTP_proto {
    rh->type = RSPAMD_RECEIVED_ESMTP;
  }
  action LMTP_proto {
    rh->type = RSPAMD_RECEIVED_LMTP;
  }
  action IMAP_proto {
    rh->type = RSPAMD_RECEIVED_IMAP;
  }

  include smtp_received "smtp_received.rl";

  main := Received;

}%%

%% write data;

static int
rspamd_smtp_recieved_parse (struct rspamd_task *task, const char *data, size_t len, struct received_header *rh)
{
  struct rspamd_email_address for_addr, *addr;
  const char *real_domain_start, *real_domain_end,
              *real_ip_start, *real_ip_end,
              *reported_domain_start, *reported_domain_end,
              *reported_ip_start, *reported_ip_end,
              *ip_start, *ip_end;
  const char *p = data, *pe = data + len, *eof;
  int cs;

  memset (rh, 0, sizeof (*rh));
  real_domain_start = NULL;
  real_domain_end = NULL;
  real_ip_start = NULL;
  real_ip_end = NULL;
  reported_domain_start = NULL;
  reported_domain_end = NULL;
  reported_ip_start = NULL;
  reported_ip_end = NULL;
  ip_start = NULL;
  ip_end = NULL;
  rh->type = RSPAMD_RECEIVED_UNKNOWN;

  memset (&for_addr, 0, sizeof (for_addr));
  addr = &for_addr;
  eof = pe;

  %% write init;
  %% write exec;

  return cs;
}
