
#line 1 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"

#line 95 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"


#include "smtp_parsers.h"
#include "content_type.h"


#line 12 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
static const int content_type_parser_start = 1;
static const int content_type_parser_first_final = 26;
static const int content_type_parser_error = 0;

static const int content_type_parser_en_balanced_ccontent = 25;
static const int content_type_parser_en_main = 1;


#line 101 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"

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

  
#line 40 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	{
	cs = content_type_parser_start;
	top = 0;
	}

#line 119 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
  
#line 48 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	{
	if ( p == pe )
		goto _test_eof;
	goto _resume;

_again:
	switch ( cs ) {
		case 1: goto st1;
		case 0: goto st0;
		case 26: goto st26;
		case 2: goto st2;
		case 3: goto st3;
		case 4: goto st4;
		case 5: goto st5;
		case 27: goto st27;
		case 28: goto st28;
		case 6: goto st6;
		case 7: goto st7;
		case 8: goto st8;
		case 29: goto st29;
		case 9: goto st9;
		case 10: goto st10;
		case 11: goto st11;
		case 12: goto st12;
		case 13: goto st13;
		case 14: goto st14;
		case 15: goto st15;
		case 16: goto st16;
		case 17: goto st17;
		case 18: goto st18;
		case 19: goto st19;
		case 20: goto st20;
		case 21: goto st21;
		case 22: goto st22;
		case 23: goto st23;
		case 24: goto st24;
		case 30: goto st30;
		case 31: goto st31;
		case 32: goto st32;
		case 33: goto st33;
		case 34: goto st34;
		case 35: goto st35;
		case 36: goto st36;
		case 37: goto st37;
		case 38: goto st38;
		case 39: goto st39;
		case 40: goto st40;
		case 41: goto st41;
		case 42: goto st42;
		case 43: goto st43;
		case 44: goto st44;
		case 45: goto st45;
		case 25: goto st25;
		case 46: goto st46;
	default: break;
	}

	if ( ++p == pe )
		goto _test_eof;
_resume:
	switch ( cs )
	{
st1:
	if ( ++p == pe )
		goto _test_eof1;
case 1:
	switch( (*p) ) {
		case 65u: goto tr2;
		case 73u: goto tr3;
		case 97u: goto tr2;
		case 105u: goto tr3;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto tr0;
		} else if ( (*p) >= 33u )
			goto tr0;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto tr0;
		} else if ( (*p) >= 66u )
			goto tr0;
	} else
		goto tr0;
	goto st0;
st0:
cs = 0;
	goto _out;
tr0:
#line 5 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
  }
	goto st26;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
#line 148 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	if ( (*p) == 59u )
		goto tr62;
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
tr4:
#line 19 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = NULL;
    qend = NULL;
    pname_start = p;
    pname_end = NULL;
  }
	goto st2;
tr62:
#line 8 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
  }
	goto st2;
tr66:
#line 52 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
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
	goto st2;
tr78:
#line 15 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    cd->type = RSPAMD_CT_ATTACHMENT;
  }
#line 8 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
  }
	goto st2;
tr84:
#line 11 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    cd->type = RSPAMD_CT_INLINE;
  }
#line 8 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
  }
	goto st2;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
#line 231 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 32u: goto tr4;
		case 34u: goto tr6;
		case 40u: goto tr7;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto tr5;
		} else if ( (*p) >= 33u )
			goto tr5;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto tr5;
		} else if ( (*p) >= 65u )
			goto tr5;
	} else
		goto tr5;
	goto st0;
tr5:
#line 19 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = NULL;
    qend = NULL;
    pname_start = p;
    pname_end = NULL;
  }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 265 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 32u: goto tr8;
		case 33u: goto st3;
		case 61u: goto tr10;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st3;
		} else if ( (*p) >= 35u )
			goto st3;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st3;
		} else if ( (*p) >= 65u )
			goto st3;
	} else
		goto st3;
	goto st0;
tr8:
#line 26 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
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
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 306 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 32u: goto st4;
		case 61u: goto st5;
	}
	goto st0;
tr10:
#line 26 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
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
	goto st5;
tr13:
#line 41 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = NULL;
    qend = NULL;

    if (pname_end) {
      pvalue_start = p;
      pvalue_end = NULL;
    }
  }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 344 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 32u: goto tr13;
		case 34u: goto tr15;
		case 40u: goto tr16;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto tr14;
		} else if ( (*p) >= 33u )
			goto tr14;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto tr14;
		} else if ( (*p) >= 65u )
			goto tr14;
	} else
		goto tr14;
	goto st0;
tr14:
#line 41 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = NULL;
    qend = NULL;

    if (pname_end) {
      pvalue_start = p;
      pvalue_end = NULL;
    }
  }
	goto st27;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
#line 381 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 32u: goto tr63;
		case 33u: goto st27;
		case 40u: goto tr65;
		case 59u: goto tr66;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st27;
		} else if ( (*p) >= 35u )
			goto st27;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st27;
		} else if ( (*p) >= 65u )
			goto st27;
	} else
		goto st27;
	goto st0;
tr63:
#line 52 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
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
	goto st28;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
#line 436 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 32u: goto st28;
		case 40u: goto st6;
		case 59u: goto st2;
	}
	goto st0;
tr18:
#line 6 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition.rl"
	{ {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  {stack[top++] = 6;goto st25;}} }
	goto st6;
tr65:
#line 52 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
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
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 487 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 40u: goto tr18;
		case 41u: goto st28;
	}
	if ( (*p) > 91u ) {
		if ( 93u <= (*p) && (*p) <= 126u )
			goto st6;
	} else if ( (*p) >= 32u )
		goto st6;
	goto st0;
tr15:
#line 41 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = NULL;
    qend = NULL;

    if (pname_end) {
      pvalue_start = p;
      pvalue_end = NULL;
    }
  }
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 514 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 34u: goto tr21;
		case 92u: goto tr22;
	}
	if ( (*p) < 192u ) {
		if ( 32u <= (*p) && (*p) <= 126u )
			goto tr20;
	} else if ( (*p) > 223u ) {
		if ( (*p) > 239u ) {
			if ( 240u <= (*p) && (*p) <= 247u )
				goto tr25;
		} else if ( (*p) >= 224u )
			goto tr24;
	} else
		goto tr23;
	goto st0;
tr20:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 542 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 34u: goto tr27;
		case 92u: goto st10;
	}
	if ( (*p) < 192u ) {
		if ( 32u <= (*p) && (*p) <= 126u )
			goto st8;
	} else if ( (*p) > 223u ) {
		if ( (*p) > 239u ) {
			if ( 240u <= (*p) && (*p) <= 247u )
				goto st13;
		} else if ( (*p) >= 224u )
			goto st12;
	} else
		goto st11;
	goto st0;
tr21:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
#line 84 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    if (qstart) {
      qend = p;
    }
  }
	goto st29;
tr27:
#line 84 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    if (qstart) {
      qend = p;
    }
  }
	goto st29;
tr67:
#line 52 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
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
	goto st29;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
#line 613 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 32u: goto tr67;
		case 40u: goto tr68;
		case 59u: goto tr66;
	}
	goto st0;
tr33:
#line 6 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition.rl"
	{ {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  {stack[top++] = 9;goto st25;}} }
	goto st9;
tr68:
#line 52 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
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
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 664 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 40u: goto tr33;
		case 41u: goto st29;
	}
	if ( (*p) > 91u ) {
		if ( 93u <= (*p) && (*p) <= 126u )
			goto st9;
	} else if ( (*p) >= 32u )
		goto st9;
	goto st0;
tr22:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 686 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	if ( 32u <= (*p) && (*p) <= 126u )
		goto st8;
	goto st0;
tr23:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 701 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	if ( 128u <= (*p) && (*p) <= 191u )
		goto st8;
	goto st0;
tr24:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 716 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	if ( 128u <= (*p) && (*p) <= 191u )
		goto st11;
	goto st0;
tr25:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
	goto st13;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
#line 731 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	if ( 128u <= (*p) && (*p) <= 191u )
		goto st12;
	goto st0;
tr16:
#line 41 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = NULL;
    qend = NULL;

    if (pname_end) {
      pvalue_start = p;
      pvalue_end = NULL;
    }
  }
	goto st14;
tr36:
#line 6 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition.rl"
	{ {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  {stack[top++] = 14;goto st25;}} }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 762 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 40u: goto tr36;
		case 41u: goto st15;
	}
	if ( (*p) > 91u ) {
		if ( 93u <= (*p) && (*p) <= 126u )
			goto st14;
	} else if ( (*p) >= 32u )
		goto st14;
	goto st0;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
	switch( (*p) ) {
		case 32u: goto st15;
		case 34u: goto st7;
		case 40u: goto st14;
	}
	goto st0;
tr6:
#line 19 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = NULL;
    qend = NULL;
    pname_start = p;
    pname_end = NULL;
  }
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 796 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 34u: goto tr40;
		case 92u: goto tr41;
	}
	if ( (*p) < 192u ) {
		if ( 32u <= (*p) && (*p) <= 126u )
			goto tr39;
	} else if ( (*p) > 223u ) {
		if ( (*p) > 239u ) {
			if ( 240u <= (*p) && (*p) <= 247u )
				goto tr44;
		} else if ( (*p) >= 224u )
			goto tr43;
	} else
		goto tr42;
	goto st0;
tr39:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 824 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 34u: goto tr46;
		case 92u: goto st20;
	}
	if ( (*p) < 192u ) {
		if ( 32u <= (*p) && (*p) <= 126u )
			goto st17;
	} else if ( (*p) > 223u ) {
		if ( (*p) > 239u ) {
			if ( 240u <= (*p) && (*p) <= 247u )
				goto st23;
		} else if ( (*p) >= 224u )
			goto st22;
	} else
		goto st21;
	goto st0;
tr51:
#line 26 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
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
	goto st18;
tr40:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
#line 84 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    if (qstart) {
      qend = p;
    }
  }
	goto st18;
tr46:
#line 84 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    if (qstart) {
      qend = p;
    }
  }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 882 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 32u: goto tr51;
		case 40u: goto st19;
		case 61u: goto tr10;
	}
	goto st0;
tr53:
#line 6 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition.rl"
	{ {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  {stack[top++] = 19;goto st25;}} }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 904 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 40u: goto tr53;
		case 41u: goto st18;
	}
	if ( (*p) > 91u ) {
		if ( 93u <= (*p) && (*p) <= 126u )
			goto st19;
	} else if ( (*p) >= 32u )
		goto st19;
	goto st0;
tr41:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 926 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	if ( 32u <= (*p) && (*p) <= 126u )
		goto st17;
	goto st0;
tr42:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 941 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	if ( 128u <= (*p) && (*p) <= 191u )
		goto st17;
	goto st0;
tr43:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 956 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	if ( 128u <= (*p) && (*p) <= 191u )
		goto st21;
	goto st0;
tr44:
#line 79 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = p;
    qend = NULL;
  }
	goto st23;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
#line 971 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	if ( 128u <= (*p) && (*p) <= 191u )
		goto st22;
	goto st0;
tr7:
#line 19 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    qstart = NULL;
    qend = NULL;
    pname_start = p;
    pname_end = NULL;
  }
	goto st24;
tr56:
#line 6 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition.rl"
	{ {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  {stack[top++] = 24;goto st25;}} }
	goto st24;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
#line 999 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 40u: goto tr56;
		case 41u: goto st2;
	}
	if ( (*p) > 91u ) {
		if ( 93u <= (*p) && (*p) <= 126u )
			goto st24;
	} else if ( (*p) >= 32u )
		goto st24;
	goto st0;
tr2:
#line 5 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
  }
	goto st30;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
#line 1019 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 59u: goto tr62;
		case 84u: goto st31;
		case 116u: goto st31;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 84u: goto st32;
		case 116u: goto st32;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 65u: goto st33;
		case 97u: goto st33;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 66u )
			goto st26;
	} else
		goto st26;
	goto st0;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 67u: goto st34;
		case 99u: goto st34;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 72u: goto st35;
		case 104u: goto st35;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 77u: goto st36;
		case 109u: goto st36;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 69u: goto st37;
		case 101u: goto st37;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 78u: goto st38;
		case 110u: goto st38;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 84u: goto st39;
		case 116u: goto st39;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
	if ( (*p) == 59u )
		goto tr78;
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
tr3:
#line 5 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
  }
	goto st40;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
#line 1262 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 59u: goto tr62;
		case 78u: goto st41;
		case 110u: goto st41;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 76u: goto st42;
		case 108u: goto st42;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 73u: goto st43;
		case 105u: goto st43;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 78u: goto st44;
		case 110u: goto st44;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
	switch( (*p) ) {
		case 59u: goto tr62;
		case 69u: goto st45;
		case 101u: goto st45;
	}
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
	if ( (*p) == 59u )
		goto tr84;
	if ( (*p) < 48u ) {
		if ( (*p) > 39u ) {
			if ( 42u <= (*p) && (*p) <= 46u )
				goto st26;
		} else if ( (*p) >= 33u )
			goto st26;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 94u <= (*p) && (*p) <= 126u )
				goto st26;
		} else if ( (*p) >= 65u )
			goto st26;
	} else
		goto st26;
	goto st0;
tr59:
#line 6 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition.rl"
	{ {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  {stack[top++] = 25;goto st25;}} }
	goto st25;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
#line 1415 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	switch( (*p) ) {
		case 40u: goto tr59;
		case 41u: goto tr60;
	}
	if ( (*p) > 91u ) {
		if ( 93u <= (*p) && (*p) <= 126u )
			goto st25;
	} else if ( (*p) >= 32u )
		goto st25;
	goto st0;
tr60:
#line 7 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition.rl"
	{ {cs = stack[--top];goto _again;} }
	goto st46;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
#line 1434 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	goto st0;
	}
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 

	_test_eof: {}
	if ( p == eof )
	{
	switch ( cs ) {
	case 26: 
	case 30: 
	case 31: 
	case 32: 
	case 33: 
	case 34: 
	case 35: 
	case 36: 
	case 37: 
	case 38: 
	case 40: 
	case 41: 
	case 42: 
	case 43: 
	case 44: 
#line 8 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
  }
	break;
	case 27: 
	case 29: 
#line 52 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
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
	break;
	case 45: 
#line 11 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    cd->type = RSPAMD_CT_INLINE;
  }
#line 8 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
  }
	break;
	case 39: 
#line 15 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
    cd->type = RSPAMD_CT_ATTACHMENT;
  }
#line 8 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"
	{
  }
	break;
#line 1555 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/content_disposition.rl.c"
	}
	}

	_out: {}
	}

#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/content_disposition_parser.rl"

  if (st_storage.data) {
    free (st_storage.data);
  }

  return cd->attrs != NULL || cd->type != RSPAMD_CT_UNKNOWN;
}
