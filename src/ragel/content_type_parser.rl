%%{
  machine content_type_parser;

  action Type_Start {
    qstart = NULL;
    qend = NULL;
    ct->type.begin = p;
  }

  action Type_End {
    if (qstart) {
      ct->type.begin = qstart;
    }
    if (qend && qend >= qstart) {
      ct->type.len = qend - qstart;
    }
    else if (p >= ct->type.begin) {
      ct->type.len = p - ct->type.begin;
    }
    qstart = NULL;
    qend = NULL;
  }

  action Subtype_Start {
    qstart = NULL;
    qend = NULL;
    ct->subtype.begin = p;
  }

  action Subtype_End {
    if (qstart) {
      ct->subtype.begin = qstart;
    }
    if (qend && qend >= qstart) {
      ct->subtype.len = qend - qstart;
    }
    else if (p >= ct->subtype.begin) {
      ct->subtype.len = p - ct->subtype.begin;
    }
    qstart = NULL;
    qend = NULL;
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
        rspamd_content_type_add_param (pool, ct, pname_start, pname_end, pvalue_start, pvalue_end);
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


  include content_type "content_type.rl";

  main := content_type;

}%%

#include "smtp_parsers.h"
#include "content_type.h"

%% write data;

gboolean
rspamd_content_type_parser (const char *data, size_t len, struct rspamd_content_type *ct, rspamd_mempool_t *pool)
{
  const char *p = data, *pe = data + len, *eof, *qstart = NULL, *qend = NULL,
    *pname_start = NULL, *pname_end = NULL, *pvalue_start, *pvalue_end;
  int cs, *stack = NULL;
  gsize top = 0;
  struct _ragel_st_storage {
    int *data;
    gsize size;
  } st_storage;

  memset (&st_storage, 0, sizeof (st_storage));
  memset (ct, 0, sizeof (*ct));
  eof = pe;

  %% write init;
  %% write exec;

  if (st_storage.data) {
    free (st_storage.data);
  }

  return ct->type.len > 0;
}
