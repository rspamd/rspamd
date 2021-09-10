%%{
  machine content_type_parser;
  alphtype unsigned char;

  action Disposition_Start {
  }

  action Disposition_End {
  }

  action Disposition_Inline {
    cd->type = RSPAMD_CT_INLINE;
  }

  action Disposition_Attachment {
    cd->type = RSPAMD_CT_ATTACHMENT;
  }

  action Param_Name_Start {
    qstart = NULL;
    qend = NULL;
    pname_start = p;
    pname_end = NULL;
  }

  action Param_Name_End {
    if (qstart) {
      pname_start = qstart;
    }
    if (qend && qend >= qstart) {
      pname_end = qend;
    }
    else if (p >= pname_start) {
      pname_end = p;
    }
    qstart = NULL;
    qend = NULL;
  }


  action Param_Value_Start {
    qstart = NULL;
    qend = NULL;

    if (pname_end) {
      pvalue_start = p;
      pvalue_end = NULL;
    }
  }


  action Param_Value_End {
    if (pname_end) {
      if (qstart) {
        pvalue_start = qstart;
      }
      if (qend && qend >= qstart) {
        pvalue_end = qend;
      }
      else if (p >= pvalue_start) {
        pvalue_end = p;
      }
      qstart = NULL;
      qend = NULL;

      if (pvalue_end && pvalue_end > pvalue_start && pname_end > pname_start) {
        rspamd_content_disposition_add_param (pool, cd, pname_start, pname_end, pvalue_start, pvalue_end);
      }
    }

    pname_start = NULL;
    pname_end = NULL;
    pvalue_start = NULL;
    pvalue_end = NULL;
    qend = NULL;
    qstart = NULL;
  }

  action Quoted_Str_Start {
    qstart = p;
    qend = NULL;
  }

  action Quoted_Str_End {
    if (qstart) {
      qend = p;
    }
  }

  include smtp_base "smtp_base.rl";
  include content_disposition "content_disposition.rl";

  main := content_disposition;

}%%

#include "smtp_parsers.h"
#include "content_type.h"

%% write data;

gboolean
rspamd_content_disposition_parser (const char *data, size_t len, struct rspamd_content_disposition *cd, rspamd_mempool_t *pool)
{
  const unsigned char *p = data, *pe = data + len, *eof, *qstart = NULL, *qend = NULL,
    *pname_start = NULL, *pname_end = NULL, *pvalue_start = NULL, *pvalue_end = NULL;
  int cs, *stack = NULL;
  gsize top = 0;
  struct _ragel_st_storage {
    int *data;
    gsize size;
  } st_storage;

  memset (&st_storage, 0, sizeof (st_storage));
  memset (cd, 0, sizeof (*cd));
  eof = pe;

  %% write init;
  %% write exec;

  if (st_storage.data) {
    free (st_storage.data);
  }

  return cd->attrs != NULL || cd->type != RSPAMD_CT_UNKNOWN;
}
