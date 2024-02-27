
#line 1 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date_parser.rl"

#line 9 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date_parser.rl"


#include "smtp_parsers.h"
#include "util.h"


#line 12 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
static const int smtp_date_parser_start = 1;
static const int smtp_date_parser_first_final = 78;
static const int smtp_date_parser_error = 0;

static const int smtp_date_parser_en_balanced_ccontent = 77;
static const int smtp_date_parser_en_main = 1;


#line 15 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date_parser.rl"

guint64
rspamd_parse_smtp_date (const unsigned char *data, size_t len, GError **err)
{
  const unsigned char *p = data, *pe = data + len, *eof = data + len, *tmp = data;
  struct tm tm;
  glong tz = 0;
  gint cs = 0, *stack = NULL;;
  gsize top = 0;

  memset (&tm, 0, sizeof (tm));

  struct _ragel_st_storage {
    int *data;
    gsize size;
  } st_storage;
  memset (&st_storage, 0, sizeof (st_storage));

  
#line 41 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	{
	cs = smtp_date_parser_start;
	top = 0;
	}

#line 34 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date_parser.rl"
  
#line 49 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	{
	if ( p == pe )
		goto _test_eof;
	goto _resume;

_again:
	switch ( cs ) {
		case 1: goto st1;
		case 0: goto st0;
		case 2: goto st2;
		case 3: goto st3;
		case 4: goto st4;
		case 5: goto st5;
		case 6: goto st6;
		case 7: goto st7;
		case 8: goto st8;
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
		case 78: goto st78;
		case 79: goto st79;
		case 21: goto st21;
		case 80: goto st80;
		case 81: goto st81;
		case 22: goto st22;
		case 82: goto st82;
		case 23: goto st23;
		case 83: goto st83;
		case 84: goto st84;
		case 24: goto st24;
		case 85: goto st85;
		case 25: goto st25;
		case 86: goto st86;
		case 87: goto st87;
		case 26: goto st26;
		case 88: goto st88;
		case 89: goto st89;
		case 27: goto st27;
		case 90: goto st90;
		case 28: goto st28;
		case 91: goto st91;
		case 92: goto st92;
		case 29: goto st29;
		case 93: goto st93;
		case 30: goto st30;
		case 94: goto st94;
		case 95: goto st95;
		case 96: goto st96;
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
		case 46: goto st46;
		case 47: goto st47;
		case 48: goto st48;
		case 49: goto st49;
		case 50: goto st50;
		case 51: goto st51;
		case 52: goto st52;
		case 53: goto st53;
		case 54: goto st54;
		case 55: goto st55;
		case 56: goto st56;
		case 57: goto st57;
		case 58: goto st58;
		case 59: goto st59;
		case 60: goto st60;
		case 61: goto st61;
		case 62: goto st62;
		case 63: goto st63;
		case 64: goto st64;
		case 65: goto st65;
		case 66: goto st66;
		case 67: goto st67;
		case 68: goto st68;
		case 69: goto st69;
		case 70: goto st70;
		case 71: goto st71;
		case 72: goto st72;
		case 73: goto st73;
		case 74: goto st74;
		case 75: goto st75;
		case 76: goto st76;
		case 77: goto st77;
		case 97: goto st97;
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
		case 32u: goto st1;
		case 70u: goto st64;
		case 77u: goto st68;
		case 83u: goto st70;
		case 84u: goto st72;
		case 87u: goto st75;
	}
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr2;
	goto st0;
st0:
cs = 0;
	goto _out;
tr2:
#line 8 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tmp = p;
  }
	goto st2;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
#line 191 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	if ( (*p) == 32u )
		goto tr8;
	if ( 48u <= (*p) && (*p) <= 57u )
		goto st63;
	goto st0;
tr8:
#line 11 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        if (n > 0 && n <= 31) {
          tm.tm_mday = n;
        }
        else {
          {p++; cs = 3; goto _out;}
        }
      }
    }
  }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 217 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	switch( (*p) ) {
		case 32u: goto st3;
		case 65u: goto st4;
		case 68u: goto st38;
		case 70u: goto st41;
		case 74u: goto st44;
		case 77u: goto st50;
		case 78u: goto st54;
		case 79u: goto st57;
		case 83u: goto st60;
	}
	goto st0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	switch( (*p) ) {
		case 112u: goto st5;
		case 117u: goto st36;
	}
	goto st0;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
	if ( (*p) == 114u )
		goto st6;
	goto st0;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
	if ( (*p) == 32u )
		goto tr22;
	goto st0;
tr22:
#line 136 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 3;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr66:
#line 148 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 7;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr69:
#line 160 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 11;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr72:
#line 130 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 1;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr76:
#line 127 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 0;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr79:
#line 145 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 6;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr80:
#line 142 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 5;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr84:
#line 133 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 2;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr85:
#line 139 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 4;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr88:
#line 157 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 10;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr91:
#line 154 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 9;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
tr94:
#line 151 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tm.tm_mon = 8;
  }
#line 24 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 377 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	if ( (*p) == 32u )
		goto st7;
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr24;
	goto st0;
tr24:
#line 27 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tmp = p;
  }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 393 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	if ( 48u <= (*p) && (*p) <= 57u )
		goto st9;
	goto st0;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
	if ( (*p) == 32u )
		goto tr26;
	if ( 48u <= (*p) && (*p) <= 57u )
		goto st34;
	goto st0;
tr26:
#line 30 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        if (n < 1000) {
          if (n < 50) {
            tm.tm_year = n - 1900 + 2000;
          }
          else {
            tm.tm_year = n;
          }
        }
        else {
          tm.tm_year = n - 1900;
        }
      }
    }
  }
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 431 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	if ( (*p) == 32u )
		goto st10;
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr29;
	goto st0;
tr29:
#line 48 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tmp = p;
  }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 447 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	if ( 48u <= (*p) && (*p) <= 57u )
		goto st12;
	goto st0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	if ( (*p) == 58u )
		goto tr31;
	goto st0;
tr31:
#line 51 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        if (n < 24) {
          tm.tm_hour = n;
        }
        else {
          {p++; cs = 13; goto _out;}
        }
      }
    }
    else {
      {p++; cs = 13; goto _out;}
    }
  }
	goto st13;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
#line 481 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr32;
	goto st0;
tr32:
#line 67 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tmp = p;
  }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 495 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	if ( 48u <= (*p) && (*p) <= 57u )
		goto st15;
	goto st0;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
	switch( (*p) ) {
		case 32u: goto tr34;
		case 58u: goto tr35;
	}
	goto st0;
tr34:
#line 70 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        if (n < 60) {
          tm.tm_min = n;
        }
        else {
          {p++; cs = 16; goto _out;}
        }
      }
    }
    else {
      {p++; cs = 16; goto _out;}
    }
  }
#line 122 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st16;
tr63:
#line 89 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        if (n <= 60) { /* Leap second */
          tm.tm_sec = n;
        }
        else {
          {p++; cs = 16; goto _out;}
        }
      }
    }
    else {
      {p++; cs = 16; goto _out;}
    }
  }
#line 122 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 556 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	switch( (*p) ) {
		case 32u: goto st16;
		case 43u: goto st17;
		case 45u: goto st17;
		case 67u: goto st81;
		case 69u: goto st84;
		case 71u: goto st87;
		case 77u: goto st89;
		case 80u: goto st92;
		case 85u: goto st95;
	}
	if ( (*p) < 75u ) {
		if ( 65u <= (*p) && (*p) <= 73u )
			goto st80;
	} else if ( (*p) > 90u ) {
		if ( (*p) > 105u ) {
			if ( 107u <= (*p) && (*p) <= 122u )
				goto st80;
		} else if ( (*p) >= 97u )
			goto st80;
	} else
		goto st80;
	goto st0;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr45;
	goto st0;
tr45:
#line 105 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tmp = p;
  }
#line 108 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{

  }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 601 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	if ( 48u <= (*p) && (*p) <= 57u )
		goto st19;
	goto st0;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
	if ( 48u <= (*p) && (*p) <= 57u )
		goto st20;
	goto st0;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
	if ( 48u <= (*p) && (*p) <= 57u )
		goto st78;
	goto st0;
st78:
	if ( ++p == pe )
		goto _test_eof78;
case 78:
	switch( (*p) ) {
		case 32u: goto tr106;
		case 40u: goto tr107;
	}
	goto st0;
tr106:
#line 111 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    if (p > tmp) {
      rspamd_strtoul (tmp, p - tmp, (gulong *)&tz);

      if (*(tmp - 1) == '-') {
        tz = -(tz);
      }
    }
  }
	goto st79;
tr108:
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
tr112:
#line 179 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -500;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
tr114:
#line 176 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -600;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
tr118:
#line 173 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -400;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
tr120:
#line 170 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -500;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
tr123:
#line 167 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = 0;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
tr127:
#line 185 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -600;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
tr129:
#line 182 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -700;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
tr133:
#line 191 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -700;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
tr135:
#line 188 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -800;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
tr138:
#line 164 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = 0;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st79;
st79:
	if ( ++p == pe )
		goto _test_eof79;
case 79:
#line 739 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	switch( (*p) ) {
		case 32u: goto st79;
		case 40u: goto st21;
	}
	goto st0;
tr50:
#line 202 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{ {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  {stack[top++] = 21;goto st77;}} }
	goto st21;
tr107:
#line 111 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    if (p > tmp) {
      rspamd_strtoul (tmp, p - tmp, (gulong *)&tz);

      if (*(tmp - 1) == '-') {
        tz = -(tz);
      }
    }
  }
	goto st21;
tr109:
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
tr113:
#line 179 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -500;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
tr115:
#line 176 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -600;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
tr119:
#line 173 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -400;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
tr121:
#line 170 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -500;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
tr124:
#line 167 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = 0;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
tr128:
#line 185 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -600;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
tr130:
#line 182 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -700;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
tr134:
#line 191 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -700;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
tr136:
#line 188 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -800;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
tr139:
#line 164 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = 0;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 867 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	switch( (*p) ) {
		case 40u: goto tr50;
		case 41u: goto st79;
	}
	if ( (*p) > 91u ) {
		if ( 93u <= (*p) && (*p) <= 126u )
			goto st21;
	} else if ( (*p) >= 32u )
		goto st21;
	goto st0;
st80:
	if ( ++p == pe )
		goto _test_eof80;
case 80:
	switch( (*p) ) {
		case 32u: goto tr108;
		case 40u: goto tr109;
	}
	goto st0;
st81:
	if ( ++p == pe )
		goto _test_eof81;
case 81:
	switch( (*p) ) {
		case 32u: goto tr108;
		case 40u: goto tr109;
		case 68u: goto st22;
		case 83u: goto st23;
	}
	goto st0;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
	if ( (*p) == 84u )
		goto st82;
	goto st0;
st82:
	if ( ++p == pe )
		goto _test_eof82;
case 82:
	switch( (*p) ) {
		case 32u: goto tr112;
		case 40u: goto tr113;
	}
	goto st0;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
	if ( (*p) == 84u )
		goto st83;
	goto st0;
st83:
	if ( ++p == pe )
		goto _test_eof83;
case 83:
	switch( (*p) ) {
		case 32u: goto tr114;
		case 40u: goto tr115;
	}
	goto st0;
st84:
	if ( ++p == pe )
		goto _test_eof84;
case 84:
	switch( (*p) ) {
		case 32u: goto tr108;
		case 40u: goto tr109;
		case 68u: goto st24;
		case 83u: goto st25;
	}
	goto st0;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
	if ( (*p) == 84u )
		goto st85;
	goto st0;
st85:
	if ( ++p == pe )
		goto _test_eof85;
case 85:
	switch( (*p) ) {
		case 32u: goto tr118;
		case 40u: goto tr119;
	}
	goto st0;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
	if ( (*p) == 84u )
		goto st86;
	goto st0;
st86:
	if ( ++p == pe )
		goto _test_eof86;
case 86:
	switch( (*p) ) {
		case 32u: goto tr120;
		case 40u: goto tr121;
	}
	goto st0;
st87:
	if ( ++p == pe )
		goto _test_eof87;
case 87:
	switch( (*p) ) {
		case 32u: goto tr108;
		case 40u: goto tr109;
		case 77u: goto st26;
	}
	goto st0;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
	if ( (*p) == 84u )
		goto st88;
	goto st0;
st88:
	if ( ++p == pe )
		goto _test_eof88;
case 88:
	switch( (*p) ) {
		case 32u: goto tr123;
		case 40u: goto tr124;
	}
	goto st0;
st89:
	if ( ++p == pe )
		goto _test_eof89;
case 89:
	switch( (*p) ) {
		case 32u: goto tr108;
		case 40u: goto tr109;
		case 68u: goto st27;
		case 83u: goto st28;
	}
	goto st0;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
	if ( (*p) == 84u )
		goto st90;
	goto st0;
st90:
	if ( ++p == pe )
		goto _test_eof90;
case 90:
	switch( (*p) ) {
		case 32u: goto tr127;
		case 40u: goto tr128;
	}
	goto st0;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
	if ( (*p) == 84u )
		goto st91;
	goto st0;
st91:
	if ( ++p == pe )
		goto _test_eof91;
case 91:
	switch( (*p) ) {
		case 32u: goto tr129;
		case 40u: goto tr130;
	}
	goto st0;
st92:
	if ( ++p == pe )
		goto _test_eof92;
case 92:
	switch( (*p) ) {
		case 32u: goto tr108;
		case 40u: goto tr109;
		case 68u: goto st29;
		case 83u: goto st30;
	}
	goto st0;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
	if ( (*p) == 84u )
		goto st93;
	goto st0;
st93:
	if ( ++p == pe )
		goto _test_eof93;
case 93:
	switch( (*p) ) {
		case 32u: goto tr133;
		case 40u: goto tr134;
	}
	goto st0;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
	if ( (*p) == 84u )
		goto st94;
	goto st0;
st94:
	if ( ++p == pe )
		goto _test_eof94;
case 94:
	switch( (*p) ) {
		case 32u: goto tr135;
		case 40u: goto tr136;
	}
	goto st0;
st95:
	if ( ++p == pe )
		goto _test_eof95;
case 95:
	switch( (*p) ) {
		case 32u: goto tr108;
		case 40u: goto tr109;
		case 84u: goto st96;
	}
	goto st0;
st96:
	if ( ++p == pe )
		goto _test_eof96;
case 96:
	switch( (*p) ) {
		case 32u: goto tr138;
		case 40u: goto tr139;
	}
	goto st0;
tr35:
#line 70 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    if (p > tmp) {
      gulong n;
      if (rspamd_strtoul (tmp, p - tmp, &n)) {
        if (n < 60) {
          tm.tm_min = n;
        }
        else {
          {p++; cs = 31; goto _out;}
        }
      }
    }
    else {
      {p++; cs = 31; goto _out;}
    }
  }
	goto st31;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
#line 1127 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr61;
	goto st0;
tr61:
#line 86 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tmp = p;
  }
	goto st32;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
#line 1141 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	if ( 48u <= (*p) && (*p) <= 57u )
		goto st33;
	goto st0;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
	if ( (*p) == 32u )
		goto tr63;
	goto st0;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
	if ( (*p) == 32u )
		goto tr26;
	if ( 48u <= (*p) && (*p) <= 57u )
		goto st35;
	goto st0;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
	if ( (*p) == 32u )
		goto tr26;
	goto st0;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
	if ( (*p) == 103u )
		goto st37;
	goto st0;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
	if ( (*p) == 32u )
		goto tr66;
	goto st0;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
	if ( (*p) == 101u )
		goto st39;
	goto st0;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
	if ( (*p) == 99u )
		goto st40;
	goto st0;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
	if ( (*p) == 32u )
		goto tr69;
	goto st0;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
	if ( (*p) == 101u )
		goto st42;
	goto st0;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
	if ( (*p) == 98u )
		goto st43;
	goto st0;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
	if ( (*p) == 32u )
		goto tr72;
	goto st0;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
	switch( (*p) ) {
		case 97u: goto st45;
		case 117u: goto st47;
	}
	goto st0;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
	if ( (*p) == 110u )
		goto st46;
	goto st0;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
	if ( (*p) == 32u )
		goto tr76;
	goto st0;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
	switch( (*p) ) {
		case 108u: goto st48;
		case 110u: goto st49;
	}
	goto st0;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
	if ( (*p) == 32u )
		goto tr79;
	goto st0;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
	if ( (*p) == 32u )
		goto tr80;
	goto st0;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
	if ( (*p) == 97u )
		goto st51;
	goto st0;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
	switch( (*p) ) {
		case 114u: goto st52;
		case 121u: goto st53;
	}
	goto st0;
st52:
	if ( ++p == pe )
		goto _test_eof52;
case 52:
	if ( (*p) == 32u )
		goto tr84;
	goto st0;
st53:
	if ( ++p == pe )
		goto _test_eof53;
case 53:
	if ( (*p) == 32u )
		goto tr85;
	goto st0;
st54:
	if ( ++p == pe )
		goto _test_eof54;
case 54:
	if ( (*p) == 111u )
		goto st55;
	goto st0;
st55:
	if ( ++p == pe )
		goto _test_eof55;
case 55:
	if ( (*p) == 118u )
		goto st56;
	goto st0;
st56:
	if ( ++p == pe )
		goto _test_eof56;
case 56:
	if ( (*p) == 32u )
		goto tr88;
	goto st0;
st57:
	if ( ++p == pe )
		goto _test_eof57;
case 57:
	if ( (*p) == 99u )
		goto st58;
	goto st0;
st58:
	if ( ++p == pe )
		goto _test_eof58;
case 58:
	if ( (*p) == 116u )
		goto st59;
	goto st0;
st59:
	if ( ++p == pe )
		goto _test_eof59;
case 59:
	if ( (*p) == 32u )
		goto tr91;
	goto st0;
st60:
	if ( ++p == pe )
		goto _test_eof60;
case 60:
	if ( (*p) == 101u )
		goto st61;
	goto st0;
st61:
	if ( ++p == pe )
		goto _test_eof61;
case 61:
	if ( (*p) == 112u )
		goto st62;
	goto st0;
st62:
	if ( ++p == pe )
		goto _test_eof62;
case 62:
	if ( (*p) == 32u )
		goto tr94;
	goto st0;
st63:
	if ( ++p == pe )
		goto _test_eof63;
case 63:
	if ( (*p) == 32u )
		goto tr8;
	goto st0;
st64:
	if ( ++p == pe )
		goto _test_eof64;
case 64:
	if ( (*p) == 114u )
		goto st65;
	goto st0;
st65:
	if ( ++p == pe )
		goto _test_eof65;
case 65:
	if ( (*p) == 105u )
		goto st66;
	goto st0;
st66:
	if ( ++p == pe )
		goto _test_eof66;
case 66:
	if ( (*p) == 44u )
		goto st67;
	goto st0;
st67:
	if ( ++p == pe )
		goto _test_eof67;
case 67:
	if ( (*p) == 32u )
		goto st67;
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr2;
	goto st0;
st68:
	if ( ++p == pe )
		goto _test_eof68;
case 68:
	if ( (*p) == 111u )
		goto st69;
	goto st0;
st69:
	if ( ++p == pe )
		goto _test_eof69;
case 69:
	if ( (*p) == 110u )
		goto st66;
	goto st0;
st70:
	if ( ++p == pe )
		goto _test_eof70;
case 70:
	switch( (*p) ) {
		case 97u: goto st71;
		case 117u: goto st69;
	}
	goto st0;
st71:
	if ( ++p == pe )
		goto _test_eof71;
case 71:
	if ( (*p) == 116u )
		goto st66;
	goto st0;
st72:
	if ( ++p == pe )
		goto _test_eof72;
case 72:
	switch( (*p) ) {
		case 104u: goto st73;
		case 117u: goto st74;
	}
	goto st0;
st73:
	if ( ++p == pe )
		goto _test_eof73;
case 73:
	if ( (*p) == 117u )
		goto st66;
	goto st0;
st74:
	if ( ++p == pe )
		goto _test_eof74;
case 74:
	if ( (*p) == 101u )
		goto st66;
	goto st0;
st75:
	if ( ++p == pe )
		goto _test_eof75;
case 75:
	if ( (*p) == 101u )
		goto st76;
	goto st0;
st76:
	if ( ++p == pe )
		goto _test_eof76;
case 76:
	if ( (*p) == 100u )
		goto st66;
	goto st0;
tr104:
#line 202 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{ {
    if (top >= st_storage.size) {
      st_storage.size = (top + 1) * 2;
      st_storage.data = realloc (st_storage.data, st_storage.size * sizeof (int));
      g_assert (st_storage.data != NULL);
      stack = st_storage.data;
    }
  {stack[top++] = 77;goto st77;}} }
	goto st77;
st77:
	if ( ++p == pe )
		goto _test_eof77;
case 77:
#line 1482 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	switch( (*p) ) {
		case 40u: goto tr104;
		case 41u: goto tr105;
	}
	if ( (*p) > 91u ) {
		if ( 93u <= (*p) && (*p) <= 126u )
			goto st77;
	} else if ( (*p) >= 32u )
		goto st77;
	goto st0;
tr105:
#line 203 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{ {cs = stack[--top];goto _again;} }
	goto st97;
st97:
	if ( ++p == pe )
		goto _test_eof97;
case 97:
#line 1501 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	goto st0;
	}
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
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
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof78: cs = 78; goto _test_eof; 
	_test_eof79: cs = 79; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof80: cs = 80; goto _test_eof; 
	_test_eof81: cs = 81; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof82: cs = 82; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof83: cs = 83; goto _test_eof; 
	_test_eof84: cs = 84; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof85: cs = 85; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof86: cs = 86; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof91: cs = 91; goto _test_eof; 
	_test_eof92: cs = 92; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof93: cs = 93; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof94: cs = 94; goto _test_eof; 
	_test_eof95: cs = 95; goto _test_eof; 
	_test_eof96: cs = 96; goto _test_eof; 
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
	_test_eof97: cs = 97; goto _test_eof; 

	_test_eof: {}
	if ( p == eof )
	{
	switch ( cs ) {
	case 78: 
#line 111 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    if (p > tmp) {
      rspamd_strtoul (tmp, p - tmp, (gulong *)&tz);

      if (*(tmp - 1) == '-') {
        tz = -(tz);
      }
    }
  }
	break;
	case 80: 
	case 81: 
	case 84: 
	case 87: 
	case 89: 
	case 92: 
	case 95: 
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
	case 96: 
#line 164 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = 0;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
	case 88: 
#line 167 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = 0;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
	case 86: 
#line 170 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -500;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
	case 85: 
#line 173 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -400;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
	case 83: 
#line 176 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -600;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
	case 82: 
#line 179 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -500;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
	case 91: 
#line 182 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -700;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
	case 90: 
#line 185 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -600;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
	case 94: 
#line 188 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -800;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
	case 93: 
#line 191 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
    tz = -700;
  }
#line 120 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date.rl"
	{
  }
	break;
#line 1719 "/home/fum/CLionProjects/rspamd/cmake-build-debug/src/date_parser.rl.c"
	}
	}

	_out: {}
	}

#line 35 "/home/fum/CLionProjects/rspamd/src/ragel/smtp_date_parser.rl"

    if (st_storage.data) {
        free (st_storage.data);
    }

  if ( cs < 78 ) {
    g_set_error (err, g_quark_from_static_string ("smtp_date"), cs, "invalid date at offset %d (%c), state %d",
			(int)(p - data), (*p > 0 && *p < 128) ? *p : '?', cs);
    return (guint64)(-1);
  }

  return rspamd_tm_to_time (&tm, tz);
}