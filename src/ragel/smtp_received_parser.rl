%%{

  machine smtp_received_parser;


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
    if (real_ip_end == NULL) {
      real_ip_start = p;
    }
  }
  action Real_IP_End {
    if (ip_start && ip_end && ip_end > ip_start) {
      real_ip_start = ip_start;
      real_ip_end = ip_end;
    }
    else {
      real_ip_end = p;
    }

    ip_start = NULL;
    ip_end = NULL;
  }
  action Reported_IP_Start {
    reported_ip_start = p;
  }
  action Reported_IP_End {

    if (ip_start && ip_end && ip_end > ip_start) {
      reported_ip_start = ip_start;
      reported_ip_end = ip_end;
    }
    else {
      reported_ip_end = p;
    }

    ip_start = NULL;
    ip_end = NULL;
  }

  action From_Start {
    real_domain_start = NULL;
    real_domain_end = NULL;
    reported_domain_start = NULL;
    reported_domain_end = NULL;
    ip_start = NULL;
    ip_end = NULL;
    for_start = NULL;
    for_end = NULL;
  }

  action By_Start {
    real_domain_start = NULL;
    real_domain_end = NULL;
    reported_domain_start = NULL;
    reported_domain_end = NULL;
    ip_start = NULL;
    ip_end = NULL;
    for_start = NULL;
    for_end = NULL;
  }

  action By_End {
    if (real_domain_end && real_domain_start && real_domain_end > real_domain_start) {
      tmplen = real_domain_end - real_domain_start;
      rh->by_hostname = rspamd_mempool_alloc (task->task_pool, tmplen + 1);
      rspamd_strlcpy (rh->by_hostname, real_domain_start, tmplen + 1);
    }
    else if (reported_domain_end && reported_domain_start && reported_domain_end > reported_domain_start) {
      len = reported_domain_end - reported_domain_start;
      rh->by_hostname = rspamd_mempool_alloc (task->task_pool, tmplen + 1);
      rspamd_strlcpy (rh->by_hostname, reported_domain_start, tmplen + 1);
    }
  }

  action From_End {
    if (real_domain_end && real_domain_start && real_domain_end > real_domain_start) {
      tmplen = real_domain_end - real_domain_start;
      rh->real_hostname = rspamd_mempool_alloc (task->task_pool, tmplen + 1);
      rspamd_strlcpy (rh->real_hostname, real_domain_start, tmplen + 1);
    }
    if (reported_domain_end && reported_domain_start && reported_domain_end > reported_domain_start) {
      tmplen = reported_domain_end - reported_domain_start;
      rh->from_hostname = rspamd_mempool_alloc (task->task_pool, tmplen + 1);
      rspamd_strlcpy (rh->from_hostname, reported_domain_start, tmplen + 1);
    }
  }

  action For_Start {
    for_start = p;
  }

  action For_End {
    if (for_start && p > for_start) {
      for_end = p;
      tmplen = for_end - for_start;
      rh->for_mbox = rspamd_mempool_alloc (task->task_pool, tmplen + 1);
      rspamd_strlcpy (rh->for_mbox, for_start, tmplen + 1);
    }
  }

  action SMTP_proto {
    rh->type = RSPAMD_RECEIVED_SMTP;
  }
  action ESMTPS_proto {
    rh->type = RSPAMD_RECEIVED_ESMTPS;
  }
  action ESMTPA_proto {
    rh->type = RSPAMD_RECEIVED_ESMTPA;
  }
  action ESMTP_proto {
    rh->type = RSPAMD_RECEIVED_ESMTP;
  }
  action ESMTPSA_proto {
    rh->type = RSPAMD_RECEIVED_ESMTPSA;
  }
  action LMTP_proto {
    rh->type = RSPAMD_RECEIVED_LMTP;
  }
  action IMAP_proto {
    rh->type = RSPAMD_RECEIVED_IMAP;
  }

  action Date_Start {
    date_start = p;
  }
  action Date_End {
    if (date_start && p > date_start) {
      rh->timestamp = rspamd_tm_to_time (&tm, tz);
    }
  }

  include smtp_received "smtp_received.rl";

  main := Received;

}%%

#include "smtp_parsers.h"

%% write data;

int
rspamd_smtp_received_parse (struct rspamd_task *task, const char *data, size_t len, struct received_header *rh)
{
  struct rspamd_email_address for_addr, *addr;
  const char *real_domain_start, *real_domain_end,
              *real_ip_start, *real_ip_end,
              *reported_domain_start, *reported_domain_end,
              *reported_ip_start, *reported_ip_end,
              *ip_start, *ip_end, *date_start,
              *for_start, *for_end, *tmp;
  struct tm tm;
  const char *p = data, *pe = data + len, *eof;
  int cs, in_v6 = 0, *stack = NULL;
  gsize top = 0;
  glong tz = 0;
  struct _ragel_st_storage {
    int *data;
    gsize size;
  } st_storage;
  guint tmplen;

  memset (&st_storage, 0, sizeof (st_storage));
  memset (rh, 0, sizeof (*rh));
  memset (&tm, 0, sizeof (tm));
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
  date_start = NULL;
  for_start = NULL;
  for_end = NULL;
  rh->type = RSPAMD_RECEIVED_UNKNOWN;

  memset (&for_addr, 0, sizeof (for_addr));
  addr = &for_addr;
  eof = pe;

  %% write init;
  %% write exec;

  if (real_ip_end && real_ip_start && real_ip_end > real_ip_start) {
    tmplen = real_ip_end - real_ip_start;
    rh->real_ip = rspamd_mempool_alloc (task->task_pool, tmplen + 1);
    rspamd_strlcpy (rh->real_ip, real_ip_start, tmplen + 1);
  }
  if (reported_ip_end && reported_ip_start && reported_ip_end > reported_ip_start) {
    tmplen = reported_ip_end - reported_ip_start;
    rh->from_ip = rspamd_mempool_alloc (task->task_pool, tmplen + 1);
    rspamd_strlcpy (rh->from_ip, reported_ip_start, tmplen + 1);
  }

  if (rh->real_ip && !rh->from_ip) {
    rh->from_ip = rh->real_ip;
  }
  if (rh->real_hostname && !rh->from_hostname) {
    rh->from_hostname = rh->real_hostname;
  }

  if (rh->real_ip) {
    if (rspamd_parse_inet_address (&rh->addr, rh->real_ip, strlen (rh->real_ip))) {
      rspamd_mempool_add_destructor (task->task_pool,
              (rspamd_mempool_destruct_t)rspamd_inet_address_free, rh->addr);
    }
  }

  if (st_storage.data) {
    free (st_storage.data);
  }

  return cs;
}
