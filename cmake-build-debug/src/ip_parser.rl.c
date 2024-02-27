
#line 1 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"

#line 31 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"


#include "smtp_parsers.h"
#include "util.h"
#include "addr.h"


#line 13 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
static const int smtp_ip_parser_start = 1;
static const int smtp_ip_parser_first_final = 155;
static const int smtp_ip_parser_error = 0;

static const int smtp_ip_parser_en_main = 1;


#line 38 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"

rspamd_inet_addr_t *
rspamd_parse_smtp_ip (const char *data, size_t len, rspamd_mempool_t *pool)
{
  const char *p = data, *pe = data + len, *eof = data + len;
  const char *ip_start = NULL, *ip_end = NULL;
  gboolean in_v6 = FALSE;
  gint cs = 0;

  
#line 32 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	{
	cs = smtp_ip_parser_start;
	}

#line 48 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
  
#line 39 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 91 )
		goto st14;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr0;
	goto st0;
st0:
cs = 0;
	goto _out;
tr0:
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{}
#line 13 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_start = p;
    }
  }
	goto st2;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
#line 68 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	if ( (*p) == 46 )
		goto st3;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st12;
	goto st0;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st4;
	goto st0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	if ( (*p) == 46 )
		goto st5;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st10;
	goto st0;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st6;
	goto st0;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
	if ( (*p) == 46 )
		goto st7;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st8;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st155;
	goto st0;
st155:
	if ( ++p == pe )
		goto _test_eof155;
case 155:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st156;
	goto st0;
st156:
	if ( ++p == pe )
		goto _test_eof156;
case 156:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st157;
	goto st0;
st157:
	if ( ++p == pe )
		goto _test_eof157;
case 157:
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	if ( (*p) == 46 )
		goto st7;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st9;
	goto st0;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
	if ( (*p) == 46 )
		goto st7;
	goto st0;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
	if ( (*p) == 46 )
		goto st5;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st11;
	goto st0;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
	if ( (*p) == 46 )
		goto st5;
	goto st0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	if ( (*p) == 46 )
		goto st3;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st13;
	goto st0;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
	if ( (*p) == 46 )
		goto st3;
	goto st0;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
	switch( (*p) ) {
		case 45: goto tr15;
		case 73: goto tr18;
		case 95: goto tr15;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr16;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr17;
	} else
		goto tr17;
	goto st0;
tr15:
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{}
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 206 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 45: goto st15;
		case 95: goto st15;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st16;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st16;
	} else
		goto st16;
	goto st0;
tr17:
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{}
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 228 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 45: goto st15;
		case 58: goto st17;
		case 95: goto st15;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st16;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st16;
	} else
		goto st16;
	goto st0;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
tr23:
#line 25 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{}
	goto st158;
tr34:
#line 18 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_end = p;
    }
  }
#line 25 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{}
	goto st158;
tr90:
#line 18 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_end = p;
    }
  }
#line 9 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    in_v6 = 0;
    ip_end = p;
  }
#line 25 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{}
	goto st158;
tr99:
#line 9 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    in_v6 = 0;
    ip_end = p;
  }
#line 25 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{}
	goto st158;
st158:
	if ( ++p == pe )
		goto _test_eof158;
case 158:
#line 307 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	goto st0;
tr16:
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{}
#line 13 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_start = p;
    }
  }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 323 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 45: goto st15;
		case 46: goto st20;
		case 58: goto st17;
		case 95: goto st15;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st32;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st16;
	} else
		goto st16;
	goto st0;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st21;
	goto st0;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
	if ( (*p) == 46 )
		goto st22;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st30;
	goto st0;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st23;
	goto st0;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
	if ( (*p) == 46 )
		goto st24;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st28;
	goto st0;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st25;
	goto st0;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
	if ( (*p) == 93 )
		goto tr34;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st26;
	goto st0;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
	if ( (*p) == 93 )
		goto tr34;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st27;
	goto st0;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
	if ( (*p) == 93 )
		goto tr34;
	goto st0;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
	if ( (*p) == 46 )
		goto st24;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st29;
	goto st0;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
	if ( (*p) == 46 )
		goto st24;
	goto st0;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
	if ( (*p) == 46 )
		goto st22;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto st31;
	goto st0;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
	if ( (*p) == 46 )
		goto st22;
	goto st0;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
	switch( (*p) ) {
		case 45: goto st15;
		case 46: goto st20;
		case 58: goto st17;
		case 95: goto st15;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st33;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st16;
	} else
		goto st16;
	goto st0;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
	switch( (*p) ) {
		case 45: goto st15;
		case 46: goto st20;
		case 58: goto st17;
		case 95: goto st15;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st16;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st16;
	} else
		goto st16;
	goto st0;
tr18:
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{}
	goto st34;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
#line 481 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 45: goto st15;
		case 58: goto st17;
		case 80: goto st35;
		case 95: goto st15;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st16;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st16;
	} else
		goto st16;
	goto st0;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
	switch( (*p) ) {
		case 45: goto st15;
		case 58: goto st17;
		case 95: goto st15;
		case 118: goto st36;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st16;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st16;
	} else
		goto st16;
	goto st0;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
	switch( (*p) ) {
		case 45: goto st15;
		case 54: goto st37;
		case 58: goto st17;
		case 95: goto st15;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st16;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st16;
	} else
		goto st16;
	goto st0;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
	switch( (*p) ) {
		case 45: goto st15;
		case 58: goto st38;
		case 95: goto st15;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st16;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto st16;
	} else
		goto st16;
	goto st0;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
	if ( (*p) == 58 )
		goto tr44;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto tr43;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto tr43;
		} else
			goto st18;
	} else
		goto tr43;
	goto st0;
tr43:
#line 5 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    in_v6 = 1;
    ip_start = p;
  }
	goto st39;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
#line 594 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 58: goto st43;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st40;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st40;
		} else
			goto st18;
	} else
		goto st40;
	goto st0;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
	switch( (*p) ) {
		case 58: goto st43;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st41;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st41;
		} else
			goto st18;
	} else
		goto st41;
	goto st0;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
	switch( (*p) ) {
		case 58: goto st43;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st42;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st42;
		} else
			goto st18;
	} else
		goto st42;
	goto st0;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
	switch( (*p) ) {
		case 58: goto st43;
		case 93: goto tr23;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
	switch( (*p) ) {
		case 58: goto st118;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st44;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st44;
		} else
			goto st18;
	} else
		goto st44;
	goto st0;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
	switch( (*p) ) {
		case 58: goto st48;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st45;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st45;
		} else
			goto st18;
	} else
		goto st45;
	goto st0;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
	switch( (*p) ) {
		case 58: goto st48;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st46;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st46;
		} else
			goto st18;
	} else
		goto st46;
	goto st0;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
	switch( (*p) ) {
		case 58: goto st48;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st47;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st47;
		} else
			goto st18;
	} else
		goto st47;
	goto st0;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
	switch( (*p) ) {
		case 58: goto st48;
		case 93: goto tr23;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
	switch( (*p) ) {
		case 58: goto st118;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st49;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st49;
		} else
			goto st18;
	} else
		goto st49;
	goto st0;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
	switch( (*p) ) {
		case 58: goto st53;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st50;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st50;
		} else
			goto st18;
	} else
		goto st50;
	goto st0;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
	switch( (*p) ) {
		case 58: goto st53;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st51;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st51;
		} else
			goto st18;
	} else
		goto st51;
	goto st0;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
	switch( (*p) ) {
		case 58: goto st53;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st52;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st52;
		} else
			goto st18;
	} else
		goto st52;
	goto st0;
st52:
	if ( ++p == pe )
		goto _test_eof52;
case 52:
	switch( (*p) ) {
		case 58: goto st53;
		case 93: goto tr23;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st53:
	if ( ++p == pe )
		goto _test_eof53;
case 53:
	switch( (*p) ) {
		case 58: goto st118;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st54;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st54;
		} else
			goto st18;
	} else
		goto st54;
	goto st0;
st54:
	if ( ++p == pe )
		goto _test_eof54;
case 54:
	switch( (*p) ) {
		case 58: goto st58;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st55;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st55;
		} else
			goto st18;
	} else
		goto st55;
	goto st0;
st55:
	if ( ++p == pe )
		goto _test_eof55;
case 55:
	switch( (*p) ) {
		case 58: goto st58;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st56;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st56;
		} else
			goto st18;
	} else
		goto st56;
	goto st0;
st56:
	if ( ++p == pe )
		goto _test_eof56;
case 56:
	switch( (*p) ) {
		case 58: goto st58;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st57;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st57;
		} else
			goto st18;
	} else
		goto st57;
	goto st0;
st57:
	if ( ++p == pe )
		goto _test_eof57;
case 57:
	switch( (*p) ) {
		case 58: goto st58;
		case 93: goto tr23;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st58:
	if ( ++p == pe )
		goto _test_eof58;
case 58:
	switch( (*p) ) {
		case 58: goto st118;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st59;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st59;
		} else
			goto st18;
	} else
		goto st59;
	goto st0;
st59:
	if ( ++p == pe )
		goto _test_eof59;
case 59:
	switch( (*p) ) {
		case 58: goto st63;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st60;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st60;
		} else
			goto st18;
	} else
		goto st60;
	goto st0;
st60:
	if ( ++p == pe )
		goto _test_eof60;
case 60:
	switch( (*p) ) {
		case 58: goto st63;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st61;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st61;
		} else
			goto st18;
	} else
		goto st61;
	goto st0;
st61:
	if ( ++p == pe )
		goto _test_eof61;
case 61:
	switch( (*p) ) {
		case 58: goto st63;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st62;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st62;
		} else
			goto st18;
	} else
		goto st62;
	goto st0;
st62:
	if ( ++p == pe )
		goto _test_eof62;
case 62:
	switch( (*p) ) {
		case 58: goto st63;
		case 93: goto tr23;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st63:
	if ( ++p == pe )
		goto _test_eof63;
case 63:
	switch( (*p) ) {
		case 58: goto st92;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st64;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st64;
		} else
			goto st18;
	} else
		goto st64;
	goto st0;
st64:
	if ( ++p == pe )
		goto _test_eof64;
case 64:
	switch( (*p) ) {
		case 58: goto st68;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st65;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st65;
		} else
			goto st18;
	} else
		goto st65;
	goto st0;
st65:
	if ( ++p == pe )
		goto _test_eof65;
case 65:
	switch( (*p) ) {
		case 58: goto st68;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st66;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st66;
		} else
			goto st18;
	} else
		goto st66;
	goto st0;
st66:
	if ( ++p == pe )
		goto _test_eof66;
case 66:
	switch( (*p) ) {
		case 58: goto st68;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st67;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st67;
		} else
			goto st18;
	} else
		goto st67;
	goto st0;
st67:
	if ( ++p == pe )
		goto _test_eof67;
case 67:
	switch( (*p) ) {
		case 58: goto st68;
		case 93: goto tr23;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st68:
	if ( ++p == pe )
		goto _test_eof68;
case 68:
	switch( (*p) ) {
		case 58: goto st92;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto tr76;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st117;
		} else
			goto st18;
	} else
		goto st117;
	goto st0;
tr76:
#line 13 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_start = p;
    }
  }
	goto st69;
st69:
	if ( ++p == pe )
		goto _test_eof69;
case 69:
#line 1455 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st85;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st82;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st91;
		} else
			goto st18;
	} else
		goto st91;
	goto st0;
st70:
	if ( ++p == pe )
		goto _test_eof70;
case 70:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto st18;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto st18;
		} else if ( (*p) >= 58 )
			goto st18;
	} else
		goto st71;
	goto st0;
st71:
	if ( ++p == pe )
		goto _test_eof71;
case 71:
	switch( (*p) ) {
		case 46: goto st72;
		case 93: goto tr23;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto st18;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto st18;
		} else if ( (*p) >= 58 )
			goto st18;
	} else
		goto st80;
	goto st0;
st72:
	if ( ++p == pe )
		goto _test_eof72;
case 72:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto st18;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto st18;
		} else if ( (*p) >= 58 )
			goto st18;
	} else
		goto st73;
	goto st0;
st73:
	if ( ++p == pe )
		goto _test_eof73;
case 73:
	switch( (*p) ) {
		case 46: goto st74;
		case 93: goto tr23;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto st18;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto st18;
		} else if ( (*p) >= 58 )
			goto st18;
	} else
		goto st78;
	goto st0;
st74:
	if ( ++p == pe )
		goto _test_eof74;
case 74:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto st18;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto st18;
		} else if ( (*p) >= 58 )
			goto st18;
	} else
		goto st75;
	goto st0;
st75:
	if ( ++p == pe )
		goto _test_eof75;
case 75:
	if ( (*p) == 93 )
		goto tr90;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto st18;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto st18;
		} else if ( (*p) >= 58 )
			goto st18;
	} else
		goto st76;
	goto st0;
st76:
	if ( ++p == pe )
		goto _test_eof76;
case 76:
	if ( (*p) == 93 )
		goto tr90;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto st18;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto st18;
		} else if ( (*p) >= 58 )
			goto st18;
	} else
		goto st77;
	goto st0;
st77:
	if ( ++p == pe )
		goto _test_eof77;
case 77:
	if ( (*p) == 93 )
		goto tr90;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st78:
	if ( ++p == pe )
		goto _test_eof78;
case 78:
	switch( (*p) ) {
		case 46: goto st74;
		case 93: goto tr23;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto st18;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto st18;
		} else if ( (*p) >= 58 )
			goto st18;
	} else
		goto st79;
	goto st0;
st79:
	if ( ++p == pe )
		goto _test_eof79;
case 79:
	switch( (*p) ) {
		case 46: goto st74;
		case 93: goto tr23;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st80:
	if ( ++p == pe )
		goto _test_eof80;
case 80:
	switch( (*p) ) {
		case 46: goto st72;
		case 93: goto tr23;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto st18;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto st18;
		} else if ( (*p) >= 58 )
			goto st18;
	} else
		goto st81;
	goto st0;
st81:
	if ( ++p == pe )
		goto _test_eof81;
case 81:
	switch( (*p) ) {
		case 46: goto st72;
		case 93: goto tr23;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st82:
	if ( ++p == pe )
		goto _test_eof82;
case 82:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st85;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st83;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st90;
		} else
			goto st18;
	} else
		goto st90;
	goto st0;
st83:
	if ( ++p == pe )
		goto _test_eof83;
case 83:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st85;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st84;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st84;
		} else
			goto st18;
	} else
		goto st84;
	goto st0;
st84:
	if ( ++p == pe )
		goto _test_eof84;
case 84:
	switch( (*p) ) {
		case 58: goto st85;
		case 93: goto tr23;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st85:
	if ( ++p == pe )
		goto _test_eof85;
case 85:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st86;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st86;
		} else
			goto st18;
	} else
		goto st86;
	goto st0;
st86:
	if ( ++p == pe )
		goto _test_eof86;
case 86:
	if ( (*p) == 93 )
		goto tr99;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st87;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st87;
		} else
			goto st18;
	} else
		goto st87;
	goto st0;
st87:
	if ( ++p == pe )
		goto _test_eof87;
case 87:
	if ( (*p) == 93 )
		goto tr99;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st88;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st88;
		} else
			goto st18;
	} else
		goto st88;
	goto st0;
st88:
	if ( ++p == pe )
		goto _test_eof88;
case 88:
	if ( (*p) == 93 )
		goto tr99;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st89;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st89;
		} else
			goto st18;
	} else
		goto st89;
	goto st0;
st89:
	if ( ++p == pe )
		goto _test_eof89;
case 89:
	if ( (*p) == 93 )
		goto tr99;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st90:
	if ( ++p == pe )
		goto _test_eof90;
case 90:
	switch( (*p) ) {
		case 58: goto st85;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st84;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st84;
		} else
			goto st18;
	} else
		goto st84;
	goto st0;
st91:
	if ( ++p == pe )
		goto _test_eof91;
case 91:
	switch( (*p) ) {
		case 58: goto st85;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st90;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st90;
		} else
			goto st18;
	} else
		goto st90;
	goto st0;
st92:
	if ( ++p == pe )
		goto _test_eof92;
case 92:
	if ( (*p) == 93 )
		goto tr99;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st93;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st93;
		} else
			goto st18;
	} else
		goto st93;
	goto st0;
st93:
	if ( ++p == pe )
		goto _test_eof93;
case 93:
	switch( (*p) ) {
		case 58: goto st97;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st94;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st94;
		} else
			goto st18;
	} else
		goto st94;
	goto st0;
st94:
	if ( ++p == pe )
		goto _test_eof94;
case 94:
	switch( (*p) ) {
		case 58: goto st97;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st95;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st95;
		} else
			goto st18;
	} else
		goto st95;
	goto st0;
st95:
	if ( ++p == pe )
		goto _test_eof95;
case 95:
	switch( (*p) ) {
		case 58: goto st97;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st96;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st96;
		} else
			goto st18;
	} else
		goto st96;
	goto st0;
st96:
	if ( ++p == pe )
		goto _test_eof96;
case 96:
	switch( (*p) ) {
		case 58: goto st97;
		case 93: goto tr99;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st97:
	if ( ++p == pe )
		goto _test_eof97;
case 97:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st98;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st98;
		} else
			goto st18;
	} else
		goto st98;
	goto st0;
st98:
	if ( ++p == pe )
		goto _test_eof98;
case 98:
	switch( (*p) ) {
		case 58: goto st102;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st99;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st99;
		} else
			goto st18;
	} else
		goto st99;
	goto st0;
st99:
	if ( ++p == pe )
		goto _test_eof99;
case 99:
	switch( (*p) ) {
		case 58: goto st102;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st100;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st100;
		} else
			goto st18;
	} else
		goto st100;
	goto st0;
st100:
	if ( ++p == pe )
		goto _test_eof100;
case 100:
	switch( (*p) ) {
		case 58: goto st102;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st101;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st101;
		} else
			goto st18;
	} else
		goto st101;
	goto st0;
st101:
	if ( ++p == pe )
		goto _test_eof101;
case 101:
	switch( (*p) ) {
		case 58: goto st102;
		case 93: goto tr99;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st102:
	if ( ++p == pe )
		goto _test_eof102;
case 102:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st103;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st103;
		} else
			goto st18;
	} else
		goto st103;
	goto st0;
st103:
	if ( ++p == pe )
		goto _test_eof103;
case 103:
	switch( (*p) ) {
		case 58: goto st107;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st104;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st104;
		} else
			goto st18;
	} else
		goto st104;
	goto st0;
st104:
	if ( ++p == pe )
		goto _test_eof104;
case 104:
	switch( (*p) ) {
		case 58: goto st107;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st105;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st105;
		} else
			goto st18;
	} else
		goto st105;
	goto st0;
st105:
	if ( ++p == pe )
		goto _test_eof105;
case 105:
	switch( (*p) ) {
		case 58: goto st107;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st106;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st106;
		} else
			goto st18;
	} else
		goto st106;
	goto st0;
st106:
	if ( ++p == pe )
		goto _test_eof106;
case 106:
	switch( (*p) ) {
		case 58: goto st107;
		case 93: goto tr99;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st107:
	if ( ++p == pe )
		goto _test_eof107;
case 107:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st108;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st108;
		} else
			goto st18;
	} else
		goto st108;
	goto st0;
st108:
	if ( ++p == pe )
		goto _test_eof108;
case 108:
	switch( (*p) ) {
		case 58: goto st112;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st109;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st109;
		} else
			goto st18;
	} else
		goto st109;
	goto st0;
st109:
	if ( ++p == pe )
		goto _test_eof109;
case 109:
	switch( (*p) ) {
		case 58: goto st112;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st110;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st110;
		} else
			goto st18;
	} else
		goto st110;
	goto st0;
st110:
	if ( ++p == pe )
		goto _test_eof110;
case 110:
	switch( (*p) ) {
		case 58: goto st112;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st111;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st111;
		} else
			goto st18;
	} else
		goto st111;
	goto st0;
st111:
	if ( ++p == pe )
		goto _test_eof111;
case 111:
	switch( (*p) ) {
		case 58: goto st112;
		case 93: goto tr99;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st112:
	if ( ++p == pe )
		goto _test_eof112;
case 112:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st113;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st113;
		} else
			goto st18;
	} else
		goto st113;
	goto st0;
st113:
	if ( ++p == pe )
		goto _test_eof113;
case 113:
	switch( (*p) ) {
		case 58: goto st85;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st114;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st114;
		} else
			goto st18;
	} else
		goto st114;
	goto st0;
st114:
	if ( ++p == pe )
		goto _test_eof114;
case 114:
	switch( (*p) ) {
		case 58: goto st85;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st115;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st115;
		} else
			goto st18;
	} else
		goto st115;
	goto st0;
st115:
	if ( ++p == pe )
		goto _test_eof115;
case 115:
	switch( (*p) ) {
		case 58: goto st85;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st116;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st116;
		} else
			goto st18;
	} else
		goto st116;
	goto st0;
st116:
	if ( ++p == pe )
		goto _test_eof116;
case 116:
	switch( (*p) ) {
		case 58: goto st85;
		case 93: goto tr99;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st117:
	if ( ++p == pe )
		goto _test_eof117;
case 117:
	switch( (*p) ) {
		case 58: goto st85;
		case 93: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st91;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st91;
		} else
			goto st18;
	} else
		goto st91;
	goto st0;
st118:
	if ( ++p == pe )
		goto _test_eof118;
case 118:
	if ( (*p) == 93 )
		goto tr99;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto tr126;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st153;
		} else
			goto st18;
	} else
		goto st153;
	goto st0;
tr126:
#line 13 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_start = p;
    }
  }
	goto st119;
st119:
	if ( ++p == pe )
		goto _test_eof119;
case 119:
#line 2745 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st123;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st120;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st152;
		} else
			goto st18;
	} else
		goto st152;
	goto st0;
st120:
	if ( ++p == pe )
		goto _test_eof120;
case 120:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st123;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st121;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st151;
		} else
			goto st18;
	} else
		goto st151;
	goto st0;
st121:
	if ( ++p == pe )
		goto _test_eof121;
case 121:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st123;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st122;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st122;
		} else
			goto st18;
	} else
		goto st122;
	goto st0;
st122:
	if ( ++p == pe )
		goto _test_eof122;
case 122:
	switch( (*p) ) {
		case 58: goto st123;
		case 93: goto tr99;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st123:
	if ( ++p == pe )
		goto _test_eof123;
case 123:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto tr134;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st150;
		} else
			goto st18;
	} else
		goto st150;
	goto st0;
tr134:
#line 13 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_start = p;
    }
  }
	goto st124;
st124:
	if ( ++p == pe )
		goto _test_eof124;
case 124:
#line 2897 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st128;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st125;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st149;
		} else
			goto st18;
	} else
		goto st149;
	goto st0;
st125:
	if ( ++p == pe )
		goto _test_eof125;
case 125:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st128;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st126;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st148;
		} else
			goto st18;
	} else
		goto st148;
	goto st0;
st126:
	if ( ++p == pe )
		goto _test_eof126;
case 126:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st128;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st127;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st127;
		} else
			goto st18;
	} else
		goto st127;
	goto st0;
st127:
	if ( ++p == pe )
		goto _test_eof127;
case 127:
	switch( (*p) ) {
		case 58: goto st128;
		case 93: goto tr99;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st128:
	if ( ++p == pe )
		goto _test_eof128;
case 128:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto tr142;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st147;
		} else
			goto st18;
	} else
		goto st147;
	goto st0;
tr142:
#line 13 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_start = p;
    }
  }
	goto st129;
st129:
	if ( ++p == pe )
		goto _test_eof129;
case 129:
#line 3049 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st133;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st130;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st146;
		} else
			goto st18;
	} else
		goto st146;
	goto st0;
st130:
	if ( ++p == pe )
		goto _test_eof130;
case 130:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st133;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st131;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st145;
		} else
			goto st18;
	} else
		goto st145;
	goto st0;
st131:
	if ( ++p == pe )
		goto _test_eof131;
case 131:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st133;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st132;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st132;
		} else
			goto st18;
	} else
		goto st132;
	goto st0;
st132:
	if ( ++p == pe )
		goto _test_eof132;
case 132:
	switch( (*p) ) {
		case 58: goto st133;
		case 93: goto tr99;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st133:
	if ( ++p == pe )
		goto _test_eof133;
case 133:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto tr150;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st144;
		} else
			goto st18;
	} else
		goto st144;
	goto st0;
tr150:
#line 13 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_start = p;
    }
  }
	goto st134;
st134:
	if ( ++p == pe )
		goto _test_eof134;
case 134:
#line 3201 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st138;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st135;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st143;
		} else
			goto st18;
	} else
		goto st143;
	goto st0;
st135:
	if ( ++p == pe )
		goto _test_eof135;
case 135:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st138;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st136;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st142;
		} else
			goto st18;
	} else
		goto st142;
	goto st0;
st136:
	if ( ++p == pe )
		goto _test_eof136;
case 136:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st138;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st137;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st137;
		} else
			goto st18;
	} else
		goto st137;
	goto st0;
st137:
	if ( ++p == pe )
		goto _test_eof137;
case 137:
	switch( (*p) ) {
		case 58: goto st138;
		case 93: goto tr99;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
st138:
	if ( ++p == pe )
		goto _test_eof138;
case 138:
	if ( (*p) == 93 )
		goto tr23;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto tr158;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st113;
		} else
			goto st18;
	} else
		goto st113;
	goto st0;
tr158:
#line 13 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_start = p;
    }
  }
	goto st139;
st139:
	if ( ++p == pe )
		goto _test_eof139;
case 139:
#line 3353 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st85;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st140;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st114;
		} else
			goto st18;
	} else
		goto st114;
	goto st0;
st140:
	if ( ++p == pe )
		goto _test_eof140;
case 140:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st85;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st141;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st115;
		} else
			goto st18;
	} else
		goto st115;
	goto st0;
st141:
	if ( ++p == pe )
		goto _test_eof141;
case 141:
	switch( (*p) ) {
		case 46: goto st70;
		case 58: goto st85;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st116;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st116;
		} else
			goto st18;
	} else
		goto st116;
	goto st0;
st142:
	if ( ++p == pe )
		goto _test_eof142;
case 142:
	switch( (*p) ) {
		case 58: goto st138;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st137;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st137;
		} else
			goto st18;
	} else
		goto st137;
	goto st0;
st143:
	if ( ++p == pe )
		goto _test_eof143;
case 143:
	switch( (*p) ) {
		case 58: goto st138;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st142;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st142;
		} else
			goto st18;
	} else
		goto st142;
	goto st0;
st144:
	if ( ++p == pe )
		goto _test_eof144;
case 144:
	switch( (*p) ) {
		case 58: goto st138;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st143;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st143;
		} else
			goto st18;
	} else
		goto st143;
	goto st0;
st145:
	if ( ++p == pe )
		goto _test_eof145;
case 145:
	switch( (*p) ) {
		case 58: goto st133;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st132;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st132;
		} else
			goto st18;
	} else
		goto st132;
	goto st0;
st146:
	if ( ++p == pe )
		goto _test_eof146;
case 146:
	switch( (*p) ) {
		case 58: goto st133;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st145;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st145;
		} else
			goto st18;
	} else
		goto st145;
	goto st0;
st147:
	if ( ++p == pe )
		goto _test_eof147;
case 147:
	switch( (*p) ) {
		case 58: goto st133;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st146;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st146;
		} else
			goto st18;
	} else
		goto st146;
	goto st0;
st148:
	if ( ++p == pe )
		goto _test_eof148;
case 148:
	switch( (*p) ) {
		case 58: goto st128;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st127;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st127;
		} else
			goto st18;
	} else
		goto st127;
	goto st0;
st149:
	if ( ++p == pe )
		goto _test_eof149;
case 149:
	switch( (*p) ) {
		case 58: goto st128;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st148;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st148;
		} else
			goto st18;
	} else
		goto st148;
	goto st0;
st150:
	if ( ++p == pe )
		goto _test_eof150;
case 150:
	switch( (*p) ) {
		case 58: goto st128;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st149;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st149;
		} else
			goto st18;
	} else
		goto st149;
	goto st0;
st151:
	if ( ++p == pe )
		goto _test_eof151;
case 151:
	switch( (*p) ) {
		case 58: goto st123;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st122;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st122;
		} else
			goto st18;
	} else
		goto st122;
	goto st0;
st152:
	if ( ++p == pe )
		goto _test_eof152;
case 152:
	switch( (*p) ) {
		case 58: goto st123;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st151;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st151;
		} else
			goto st18;
	} else
		goto st151;
	goto st0;
st153:
	if ( ++p == pe )
		goto _test_eof153;
case 153:
	switch( (*p) ) {
		case 58: goto st123;
		case 93: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto st18;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto st18;
		} else
			goto st152;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto st18;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto st18;
			} else if ( (*p) >= 97 )
				goto st152;
		} else
			goto st18;
	} else
		goto st152;
	goto st0;
tr44:
#line 5 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    in_v6 = 1;
    ip_start = p;
  }
	goto st154;
st154:
	if ( ++p == pe )
		goto _test_eof154;
case 154:
#line 3844 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	switch( (*p) ) {
		case 58: goto st118;
		case 93: goto tr23;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto st18;
	} else if ( (*p) >= 33 )
		goto st18;
	goto st0;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof155: cs = 155; goto _test_eof; 
	_test_eof156: cs = 156; goto _test_eof; 
	_test_eof157: cs = 157; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
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
	_test_eof158: cs = 158; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
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
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof52: cs = 52; goto _test_eof; 
	_test_eof53: cs = 53; goto _test_eof; 
	_test_eof54: cs = 54; goto _test_eof; 
	_test_eof55: cs = 55; goto _test_eof; 
	_test_eof56: cs = 56; goto _test_eof; 
	_test_eof57: cs = 57; goto _test_eof; 
	_test_eof58: cs = 58; goto _test_eof; 
	_test_eof59: cs = 59; goto _test_eof; 
	_test_eof60: cs = 60; goto _test_eof; 
	_test_eof61: cs = 61; goto _test_eof; 
	_test_eof62: cs = 62; goto _test_eof; 
	_test_eof63: cs = 63; goto _test_eof; 
	_test_eof64: cs = 64; goto _test_eof; 
	_test_eof65: cs = 65; goto _test_eof; 
	_test_eof66: cs = 66; goto _test_eof; 
	_test_eof67: cs = 67; goto _test_eof; 
	_test_eof68: cs = 68; goto _test_eof; 
	_test_eof69: cs = 69; goto _test_eof; 
	_test_eof70: cs = 70; goto _test_eof; 
	_test_eof71: cs = 71; goto _test_eof; 
	_test_eof72: cs = 72; goto _test_eof; 
	_test_eof73: cs = 73; goto _test_eof; 
	_test_eof74: cs = 74; goto _test_eof; 
	_test_eof75: cs = 75; goto _test_eof; 
	_test_eof76: cs = 76; goto _test_eof; 
	_test_eof77: cs = 77; goto _test_eof; 
	_test_eof78: cs = 78; goto _test_eof; 
	_test_eof79: cs = 79; goto _test_eof; 
	_test_eof80: cs = 80; goto _test_eof; 
	_test_eof81: cs = 81; goto _test_eof; 
	_test_eof82: cs = 82; goto _test_eof; 
	_test_eof83: cs = 83; goto _test_eof; 
	_test_eof84: cs = 84; goto _test_eof; 
	_test_eof85: cs = 85; goto _test_eof; 
	_test_eof86: cs = 86; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
	_test_eof91: cs = 91; goto _test_eof; 
	_test_eof92: cs = 92; goto _test_eof; 
	_test_eof93: cs = 93; goto _test_eof; 
	_test_eof94: cs = 94; goto _test_eof; 
	_test_eof95: cs = 95; goto _test_eof; 
	_test_eof96: cs = 96; goto _test_eof; 
	_test_eof97: cs = 97; goto _test_eof; 
	_test_eof98: cs = 98; goto _test_eof; 
	_test_eof99: cs = 99; goto _test_eof; 
	_test_eof100: cs = 100; goto _test_eof; 
	_test_eof101: cs = 101; goto _test_eof; 
	_test_eof102: cs = 102; goto _test_eof; 
	_test_eof103: cs = 103; goto _test_eof; 
	_test_eof104: cs = 104; goto _test_eof; 
	_test_eof105: cs = 105; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
	_test_eof108: cs = 108; goto _test_eof; 
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 
	_test_eof111: cs = 111; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
	_test_eof113: cs = 113; goto _test_eof; 
	_test_eof114: cs = 114; goto _test_eof; 
	_test_eof115: cs = 115; goto _test_eof; 
	_test_eof116: cs = 116; goto _test_eof; 
	_test_eof117: cs = 117; goto _test_eof; 
	_test_eof118: cs = 118; goto _test_eof; 
	_test_eof119: cs = 119; goto _test_eof; 
	_test_eof120: cs = 120; goto _test_eof; 
	_test_eof121: cs = 121; goto _test_eof; 
	_test_eof122: cs = 122; goto _test_eof; 
	_test_eof123: cs = 123; goto _test_eof; 
	_test_eof124: cs = 124; goto _test_eof; 
	_test_eof125: cs = 125; goto _test_eof; 
	_test_eof126: cs = 126; goto _test_eof; 
	_test_eof127: cs = 127; goto _test_eof; 
	_test_eof128: cs = 128; goto _test_eof; 
	_test_eof129: cs = 129; goto _test_eof; 
	_test_eof130: cs = 130; goto _test_eof; 
	_test_eof131: cs = 131; goto _test_eof; 
	_test_eof132: cs = 132; goto _test_eof; 
	_test_eof133: cs = 133; goto _test_eof; 
	_test_eof134: cs = 134; goto _test_eof; 
	_test_eof135: cs = 135; goto _test_eof; 
	_test_eof136: cs = 136; goto _test_eof; 
	_test_eof137: cs = 137; goto _test_eof; 
	_test_eof138: cs = 138; goto _test_eof; 
	_test_eof139: cs = 139; goto _test_eof; 
	_test_eof140: cs = 140; goto _test_eof; 
	_test_eof141: cs = 141; goto _test_eof; 
	_test_eof142: cs = 142; goto _test_eof; 
	_test_eof143: cs = 143; goto _test_eof; 
	_test_eof144: cs = 144; goto _test_eof; 
	_test_eof145: cs = 145; goto _test_eof; 
	_test_eof146: cs = 146; goto _test_eof; 
	_test_eof147: cs = 147; goto _test_eof; 
	_test_eof148: cs = 148; goto _test_eof; 
	_test_eof149: cs = 149; goto _test_eof; 
	_test_eof150: cs = 150; goto _test_eof; 
	_test_eof151: cs = 151; goto _test_eof; 
	_test_eof152: cs = 152; goto _test_eof; 
	_test_eof153: cs = 153; goto _test_eof; 
	_test_eof154: cs = 154; goto _test_eof; 

	_test_eof: {}
	if ( p == eof )
	{
	switch ( cs ) {
	case 155: 
	case 156: 
	case 157: 
#line 18 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{
    if (!in_v6) {
      ip_end = p;
    }
  }
#line 25 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"
	{}
	break;
#line 4030 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/ip_parser.rl.c"
	}
	}

	_out: {}
	}

#line 49 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_ip_parser.rl"

  if (ip_start && ip_end && ip_end > ip_start) {
    return rspamd_parse_inet_address_pool (ip_start, ip_end - ip_start, pool,
    		RSPAMD_INET_ADDRESS_PARSE_NO_UNIX|RSPAMD_INET_ADDRESS_PARSE_REMOTE);
  }

  return NULL;
}