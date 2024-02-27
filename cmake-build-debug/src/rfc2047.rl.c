
#line 1 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"

#line 53 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"


#include "smtp_parsers.h"
#include "mime_headers.h"


#line 12 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
static const int rfc2047_parser_start = 1;
static const int rfc2047_parser_first_final = 17;
static const int rfc2047_parser_error = 0;

static const int rfc2047_parser_en_main = 1;


#line 59 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"

gboolean
rspamd_rfc2047_parser (const gchar *in, gsize len, gint *pencoding,
  const gchar **charset, gsize *charset_len,
  const gchar **encoded, gsize *encoded_len)
{
  const char *p = in, *pe = in + len,
    *encoded_start = NULL, *encoded_end = NULL,
    *charset_start = NULL, *charset_end = NULL,
    *eof = in + len;
  gint encoding = RSPAMD_RFC2047_QP, cs = 0;

  
#line 34 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
	{
	cs = rfc2047_parser_start;
	}

#line 72 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"
  
#line 41 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 61 )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 63 )
		goto st3;
	goto st0;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	switch( (*p) ) {
		case 33: goto tr3;
		case 43: goto tr3;
		case 45: goto tr3;
		case 92: goto tr3;
	}
	if ( (*p) < 48 ) {
		if ( 35 <= (*p) && (*p) <= 39 )
			goto tr3;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr3;
		} else if ( (*p) >= 65 )
			goto tr3;
	} else
		goto tr3;
	goto st0;
tr3:
#line 5 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"
	{
    charset_start = p;
  }
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 93 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
	switch( (*p) ) {
		case 33: goto st4;
		case 42: goto tr5;
		case 43: goto st4;
		case 45: goto st4;
		case 63: goto tr6;
		case 92: goto st4;
	}
	if ( (*p) < 48 ) {
		if ( 35 <= (*p) && (*p) <= 39 )
			goto st4;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto st4;
		} else if ( (*p) >= 65 )
			goto st4;
	} else
		goto st4;
	goto st0;
tr5:
#line 9 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"
	{
    if (charset_start && p > charset_start) {
      charset_end = p;
    }
  }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 126 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st6;
	} else if ( (*p) >= 65 )
		goto st6;
	goto st0;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
	switch( (*p) ) {
		case 45: goto st5;
		case 63: goto st7;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st10;
	} else if ( (*p) >= 65 )
		goto st10;
	goto st0;
tr6:
#line 9 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"
	{
    if (charset_start && p > charset_start) {
      charset_end = p;
    }
  }
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 159 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
	switch( (*p) ) {
		case 66: goto st8;
		case 81: goto st8;
		case 98: goto st8;
		case 113: goto st8;
	}
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	if ( (*p) == 63 )
		goto tr12;
	goto st0;
tr12:
#line 15 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"
	{
    if (p > in) {
      switch (*(p - 1)) {
      case 'B':
      case 'b':
        encoding = RSPAMD_RFC2047_BASE64;
        break;
      default:
        encoding = RSPAMD_RFC2047_QP;
        break;
      }
    }
  }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 194 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
	if ( (*p) == 63 )
		goto tr14;
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr13;
	goto st0;
tr13:
#line 29 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"
	{
    encoded_start = p;
  }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 210 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
	if ( (*p) == 63 )
		goto tr22;
	if ( 32 <= (*p) && (*p) <= 126 )
		goto st17;
	goto st0;
tr22:
#line 33 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"
	{
    if (encoded_start && p > encoded_start) {
      encoded_end = p;
    }
  }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 228 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
	switch( (*p) ) {
		case 61: goto st19;
		case 63: goto tr22;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto st17;
	goto st0;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
	goto st0;
tr14:
#line 29 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"
	{
    encoded_start = p;
  }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 251 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
	if ( (*p) == 63 )
		goto tr22;
	if ( (*p) > 60 ) {
		if ( 62 <= (*p) && (*p) <= 126 )
			goto st17;
	} else if ( (*p) >= 32 )
		goto st17;
	goto st0;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
	switch( (*p) ) {
		case 45: goto st5;
		case 63: goto st7;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st11;
	} else if ( (*p) >= 65 )
		goto st11;
	goto st0;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
	switch( (*p) ) {
		case 45: goto st5;
		case 63: goto st7;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st12;
	} else if ( (*p) >= 65 )
		goto st12;
	goto st0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	switch( (*p) ) {
		case 45: goto st5;
		case 63: goto st7;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st13;
	} else if ( (*p) >= 65 )
		goto st13;
	goto st0;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
	switch( (*p) ) {
		case 45: goto st5;
		case 63: goto st7;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st14;
	} else if ( (*p) >= 65 )
		goto st14;
	goto st0;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
	switch( (*p) ) {
		case 45: goto st5;
		case 63: goto st7;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st15;
	} else if ( (*p) >= 65 )
		goto st15;
	goto st0;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
	switch( (*p) ) {
		case 45: goto st5;
		case 63: goto st7;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st16;
	} else if ( (*p) >= 65 )
		goto st16;
	goto st0;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
	switch( (*p) ) {
		case 45: goto st5;
		case 63: goto st7;
	}
	goto st0;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 

	_test_eof: {}
	if ( p == eof )
	{
	switch ( cs ) {
	case 17: 
	case 18: 
	case 20: 
#line 33 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"
	{
    if (encoded_start && p > encoded_start) {
      encoded_end = p;
    }
  }
	break;
#line 388 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/rfc2047.rl.c"
	}
	}

	_out: {}
	}

#line 73 "/home/fum/CLionProjects/rspamd/src/ragel/rfc2047_parser.rl"

  if (encoded_end) {
    *pencoding = encoding;
    *charset = charset_start;
    *charset_len = charset_end - charset_start;
    *encoded = encoded_start;
    *encoded_len = encoded_end - encoded_start;

    return TRUE;
  }

  return FALSE;
}
