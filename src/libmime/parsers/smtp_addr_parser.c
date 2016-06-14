
#line 1 "../rspamd/src/ragel/smtp_addr_parser.rl"

#line 77 "../rspamd/src/ragel/smtp_addr_parser.rl"



#line 9 "../rspamd/src/libmime/parsers/smtp_addr_parser.c"
static const char _smtp_addr_parser_eof_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 20, 0, 21,
	22, 23
};

static const int smtp_addr_parser_start = 1;
static const int smtp_addr_parser_first_final = 317;
static const int smtp_addr_parser_error = 0;

static const int smtp_addr_parser_en_main = 1;


#line 80 "../rspamd/src/ragel/smtp_addr_parser.rl"

static int
rspamd_smtp_addr_parse (const char *data, size_t len, struct rspamd_email_address *addr)
{
  const char *p = data, *pe = data + len, *eof;
  int cs;

  g_assert (addr != NULL);
  memset (addr, 0, sizeof (*addr));
  addr->raw = data;
  addr->raw_len = len;
  eof = pe;


#line 76 "../rspamd/src/libmime/parsers/smtp_addr_parser.c"
	{
	cs = smtp_addr_parser_start;
	}

#line 94 "../rspamd/src/ragel/smtp_addr_parser.rl"

#line 83 "../rspamd/src/libmime/parsers/smtp_addr_parser.c"
	{
	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	switch ( cs ) {
case 1:
	switch( (*p) ) {
		case 32: goto tr0;
		case 34: goto tr3;
		case 45: goto tr2;
		case 60: goto tr4;
		case 61: goto tr2;
		case 64: goto tr5;
	}
	if ( (*p) < 42 ) {
		if ( (*p) > 13 ) {
			if ( 33 <= (*p) && (*p) <= 39 )
				goto tr2;
		} else if ( (*p) >= 9 )
			goto tr0;
	} else if ( (*p) > 43 ) {
		if ( (*p) < 63 ) {
			if ( 47 <= (*p) && (*p) <= 57 )
				goto tr2;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr2;
		} else
			goto tr2;
	} else
		goto tr2;
	goto tr1;
case 0:
	goto _out;
case 2:
	switch( (*p) ) {
		case 33: goto tr6;
		case 46: goto tr7;
		case 61: goto tr6;
		case 64: goto tr8;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr6;
		} else if ( (*p) >= 35 )
			goto tr6;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr6;
		} else if ( (*p) >= 63 )
			goto tr6;
	} else
		goto tr6;
	goto tr1;
case 3:
	switch( (*p) ) {
		case 33: goto tr6;
		case 45: goto tr6;
		case 61: goto tr6;
		case 63: goto tr6;
	}
	if ( (*p) < 47 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr6;
		} else if ( (*p) >= 35 )
			goto tr6;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr6;
		} else if ( (*p) >= 65 )
			goto tr6;
	} else
		goto tr6;
	goto tr1;
case 4:
	if ( (*p) == 91 )
		goto tr10;
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr9;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr9;
	} else
		goto tr9;
	goto tr1;
case 317:
	switch( (*p) ) {
		case 32: goto tr349;
		case 45: goto tr11;
		case 46: goto tr350;
		case 95: goto tr11;
	}
	if ( (*p) < 48 ) {
		if ( 9 <= (*p) && (*p) <= 13 )
			goto tr349;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr12;
		} else if ( (*p) >= 65 )
			goto tr12;
	} else
		goto tr12;
	goto tr1;
case 318:
	if ( (*p) == 32 )
		goto tr351;
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr351;
	goto tr1;
case 5:
	switch( (*p) ) {
		case 45: goto tr11;
		case 95: goto tr11;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr12;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr12;
	} else
		goto tr12;
	goto tr1;
case 6:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr12;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr12;
	} else
		goto tr12;
	goto tr1;
case 7:
	switch( (*p) ) {
		case 45: goto tr13;
		case 73: goto tr16;
		case 95: goto tr13;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr14;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr15;
	} else
		goto tr15;
	goto tr1;
case 8:
	switch( (*p) ) {
		case 45: goto tr17;
		case 95: goto tr17;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr18;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr18;
	} else
		goto tr18;
	goto tr1;
case 9:
	switch( (*p) ) {
		case 45: goto tr17;
		case 58: goto tr19;
		case 95: goto tr17;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr18;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr18;
	} else
		goto tr18;
	goto tr1;
case 10:
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 11:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 319:
	if ( (*p) == 32 )
		goto tr352;
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr352;
	goto tr1;
case 12:
	switch( (*p) ) {
		case 45: goto tr17;
		case 46: goto tr22;
		case 58: goto tr19;
		case 95: goto tr17;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr23;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr18;
	} else
		goto tr18;
	goto tr1;
case 13:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr24;
	goto tr1;
case 14:
	if ( (*p) == 46 )
		goto tr25;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr26;
	goto tr1;
case 15:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr27;
	goto tr1;
case 16:
	if ( (*p) == 46 )
		goto tr28;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr29;
	goto tr1;
case 17:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr30;
	goto tr1;
case 18:
	if ( (*p) == 93 )
		goto tr32;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr31;
	goto tr1;
case 19:
	if ( (*p) == 93 )
		goto tr32;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr33;
	goto tr1;
case 20:
	if ( (*p) == 93 )
		goto tr32;
	goto tr1;
case 21:
	if ( (*p) == 46 )
		goto tr28;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr34;
	goto tr1;
case 22:
	if ( (*p) == 46 )
		goto tr28;
	goto tr1;
case 23:
	if ( (*p) == 46 )
		goto tr25;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr35;
	goto tr1;
case 24:
	if ( (*p) == 46 )
		goto tr25;
	goto tr1;
case 25:
	switch( (*p) ) {
		case 45: goto tr17;
		case 46: goto tr22;
		case 58: goto tr19;
		case 95: goto tr17;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr36;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr18;
	} else
		goto tr18;
	goto tr1;
case 26:
	switch( (*p) ) {
		case 45: goto tr17;
		case 46: goto tr22;
		case 58: goto tr19;
		case 95: goto tr17;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr18;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr18;
	} else
		goto tr18;
	goto tr1;
case 27:
	switch( (*p) ) {
		case 45: goto tr17;
		case 58: goto tr19;
		case 80: goto tr37;
		case 95: goto tr17;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr18;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr18;
	} else
		goto tr18;
	goto tr1;
case 28:
	switch( (*p) ) {
		case 45: goto tr17;
		case 58: goto tr19;
		case 95: goto tr17;
		case 118: goto tr38;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr18;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr18;
	} else
		goto tr18;
	goto tr1;
case 29:
	switch( (*p) ) {
		case 45: goto tr17;
		case 54: goto tr39;
		case 58: goto tr19;
		case 95: goto tr17;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr18;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr18;
	} else
		goto tr18;
	goto tr1;
case 30:
	switch( (*p) ) {
		case 45: goto tr17;
		case 58: goto tr40;
		case 95: goto tr17;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr18;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr18;
	} else
		goto tr18;
	goto tr1;
case 31:
	if ( (*p) == 58 )
		goto tr42;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr41;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr41;
		} else
			goto tr20;
	} else
		goto tr41;
	goto tr1;
case 32:
	switch( (*p) ) {
		case 58: goto tr44;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr43;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr43;
		} else
			goto tr20;
	} else
		goto tr43;
	goto tr1;
case 33:
	switch( (*p) ) {
		case 58: goto tr44;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr45;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr45;
		} else
			goto tr20;
	} else
		goto tr45;
	goto tr1;
case 34:
	switch( (*p) ) {
		case 58: goto tr44;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr46;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr46;
		} else
			goto tr20;
	} else
		goto tr46;
	goto tr1;
case 35:
	switch( (*p) ) {
		case 58: goto tr44;
		case 93: goto tr21;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 36:
	switch( (*p) ) {
		case 58: goto tr48;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr47;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr47;
		} else
			goto tr20;
	} else
		goto tr47;
	goto tr1;
case 37:
	switch( (*p) ) {
		case 58: goto tr50;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr49;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr49;
		} else
			goto tr20;
	} else
		goto tr49;
	goto tr1;
case 38:
	switch( (*p) ) {
		case 58: goto tr50;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr51;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr51;
		} else
			goto tr20;
	} else
		goto tr51;
	goto tr1;
case 39:
	switch( (*p) ) {
		case 58: goto tr50;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr52;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr52;
		} else
			goto tr20;
	} else
		goto tr52;
	goto tr1;
case 40:
	switch( (*p) ) {
		case 58: goto tr50;
		case 93: goto tr21;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 41:
	switch( (*p) ) {
		case 58: goto tr48;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr53;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr53;
		} else
			goto tr20;
	} else
		goto tr53;
	goto tr1;
case 42:
	switch( (*p) ) {
		case 58: goto tr55;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr54;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr54;
		} else
			goto tr20;
	} else
		goto tr54;
	goto tr1;
case 43:
	switch( (*p) ) {
		case 58: goto tr55;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr56;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr56;
		} else
			goto tr20;
	} else
		goto tr56;
	goto tr1;
case 44:
	switch( (*p) ) {
		case 58: goto tr55;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr57;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr57;
		} else
			goto tr20;
	} else
		goto tr57;
	goto tr1;
case 45:
	switch( (*p) ) {
		case 58: goto tr55;
		case 93: goto tr21;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 46:
	switch( (*p) ) {
		case 58: goto tr48;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr58;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr58;
		} else
			goto tr20;
	} else
		goto tr58;
	goto tr1;
case 47:
	switch( (*p) ) {
		case 58: goto tr60;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr59;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr59;
		} else
			goto tr20;
	} else
		goto tr59;
	goto tr1;
case 48:
	switch( (*p) ) {
		case 58: goto tr60;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr61;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr61;
		} else
			goto tr20;
	} else
		goto tr61;
	goto tr1;
case 49:
	switch( (*p) ) {
		case 58: goto tr60;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr62;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr62;
		} else
			goto tr20;
	} else
		goto tr62;
	goto tr1;
case 50:
	switch( (*p) ) {
		case 58: goto tr60;
		case 93: goto tr21;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 51:
	switch( (*p) ) {
		case 58: goto tr48;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr63;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr63;
		} else
			goto tr20;
	} else
		goto tr63;
	goto tr1;
case 52:
	switch( (*p) ) {
		case 58: goto tr65;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr64;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr64;
		} else
			goto tr20;
	} else
		goto tr64;
	goto tr1;
case 53:
	switch( (*p) ) {
		case 58: goto tr65;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr66;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr66;
		} else
			goto tr20;
	} else
		goto tr66;
	goto tr1;
case 54:
	switch( (*p) ) {
		case 58: goto tr65;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr67;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr67;
		} else
			goto tr20;
	} else
		goto tr67;
	goto tr1;
case 55:
	switch( (*p) ) {
		case 58: goto tr65;
		case 93: goto tr21;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 56:
	switch( (*p) ) {
		case 58: goto tr69;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr68;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr68;
		} else
			goto tr20;
	} else
		goto tr68;
	goto tr1;
case 57:
	switch( (*p) ) {
		case 58: goto tr71;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr70;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr70;
		} else
			goto tr20;
	} else
		goto tr70;
	goto tr1;
case 58:
	switch( (*p) ) {
		case 58: goto tr71;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr72;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr72;
		} else
			goto tr20;
	} else
		goto tr72;
	goto tr1;
case 59:
	switch( (*p) ) {
		case 58: goto tr71;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr73;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr73;
		} else
			goto tr20;
	} else
		goto tr73;
	goto tr1;
case 60:
	switch( (*p) ) {
		case 58: goto tr71;
		case 93: goto tr21;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 61:
	switch( (*p) ) {
		case 58: goto tr69;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr74;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr75;
		} else
			goto tr20;
	} else
		goto tr75;
	goto tr1;
case 62:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr78;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr77;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr79;
		} else
			goto tr20;
	} else
		goto tr79;
	goto tr1;
case 63:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr20;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr20;
		} else if ( (*p) >= 58 )
			goto tr20;
	} else
		goto tr80;
	goto tr1;
case 64:
	switch( (*p) ) {
		case 46: goto tr81;
		case 93: goto tr21;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr20;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr20;
		} else if ( (*p) >= 58 )
			goto tr20;
	} else
		goto tr82;
	goto tr1;
case 65:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr20;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr20;
		} else if ( (*p) >= 58 )
			goto tr20;
	} else
		goto tr83;
	goto tr1;
case 66:
	switch( (*p) ) {
		case 46: goto tr84;
		case 93: goto tr21;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr20;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr20;
		} else if ( (*p) >= 58 )
			goto tr20;
	} else
		goto tr85;
	goto tr1;
case 67:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr20;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr20;
		} else if ( (*p) >= 58 )
			goto tr20;
	} else
		goto tr86;
	goto tr1;
case 68:
	if ( (*p) == 93 )
		goto tr88;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr20;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr20;
		} else if ( (*p) >= 58 )
			goto tr20;
	} else
		goto tr87;
	goto tr1;
case 69:
	if ( (*p) == 93 )
		goto tr88;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr20;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr20;
		} else if ( (*p) >= 58 )
			goto tr20;
	} else
		goto tr89;
	goto tr1;
case 70:
	if ( (*p) == 93 )
		goto tr88;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 71:
	switch( (*p) ) {
		case 46: goto tr84;
		case 93: goto tr21;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr20;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr20;
		} else if ( (*p) >= 58 )
			goto tr20;
	} else
		goto tr90;
	goto tr1;
case 72:
	switch( (*p) ) {
		case 46: goto tr84;
		case 93: goto tr21;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 73:
	switch( (*p) ) {
		case 46: goto tr81;
		case 93: goto tr21;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr20;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr20;
		} else if ( (*p) >= 58 )
			goto tr20;
	} else
		goto tr91;
	goto tr1;
case 74:
	switch( (*p) ) {
		case 46: goto tr81;
		case 93: goto tr21;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 75:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr78;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr92;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr93;
		} else
			goto tr20;
	} else
		goto tr93;
	goto tr1;
case 76:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr78;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr94;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr94;
		} else
			goto tr20;
	} else
		goto tr94;
	goto tr1;
case 77:
	switch( (*p) ) {
		case 58: goto tr78;
		case 93: goto tr21;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 78:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr95;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr95;
		} else
			goto tr20;
	} else
		goto tr95;
	goto tr1;
case 79:
	if ( (*p) == 93 )
		goto tr97;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr96;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr96;
		} else
			goto tr20;
	} else
		goto tr96;
	goto tr1;
case 80:
	if ( (*p) == 93 )
		goto tr97;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr98;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr98;
		} else
			goto tr20;
	} else
		goto tr98;
	goto tr1;
case 81:
	if ( (*p) == 93 )
		goto tr97;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr99;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr99;
		} else
			goto tr20;
	} else
		goto tr99;
	goto tr1;
case 82:
	if ( (*p) == 93 )
		goto tr97;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 83:
	switch( (*p) ) {
		case 58: goto tr78;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr94;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr94;
		} else
			goto tr20;
	} else
		goto tr94;
	goto tr1;
case 84:
	switch( (*p) ) {
		case 58: goto tr78;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr93;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr93;
		} else
			goto tr20;
	} else
		goto tr93;
	goto tr1;
case 85:
	if ( (*p) == 93 )
		goto tr97;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr100;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr100;
		} else
			goto tr20;
	} else
		goto tr100;
	goto tr1;
case 86:
	switch( (*p) ) {
		case 58: goto tr102;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr101;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr101;
		} else
			goto tr20;
	} else
		goto tr101;
	goto tr1;
case 87:
	switch( (*p) ) {
		case 58: goto tr102;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr103;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr103;
		} else
			goto tr20;
	} else
		goto tr103;
	goto tr1;
case 88:
	switch( (*p) ) {
		case 58: goto tr102;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr104;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr104;
		} else
			goto tr20;
	} else
		goto tr104;
	goto tr1;
case 89:
	switch( (*p) ) {
		case 58: goto tr102;
		case 93: goto tr97;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 90:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr105;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr105;
		} else
			goto tr20;
	} else
		goto tr105;
	goto tr1;
case 91:
	switch( (*p) ) {
		case 58: goto tr107;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr106;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr106;
		} else
			goto tr20;
	} else
		goto tr106;
	goto tr1;
case 92:
	switch( (*p) ) {
		case 58: goto tr107;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr108;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr108;
		} else
			goto tr20;
	} else
		goto tr108;
	goto tr1;
case 93:
	switch( (*p) ) {
		case 58: goto tr107;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr109;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr109;
		} else
			goto tr20;
	} else
		goto tr109;
	goto tr1;
case 94:
	switch( (*p) ) {
		case 58: goto tr107;
		case 93: goto tr97;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 95:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr110;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr110;
		} else
			goto tr20;
	} else
		goto tr110;
	goto tr1;
case 96:
	switch( (*p) ) {
		case 58: goto tr112;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr111;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr111;
		} else
			goto tr20;
	} else
		goto tr111;
	goto tr1;
case 97:
	switch( (*p) ) {
		case 58: goto tr112;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr113;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr113;
		} else
			goto tr20;
	} else
		goto tr113;
	goto tr1;
case 98:
	switch( (*p) ) {
		case 58: goto tr112;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr114;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr114;
		} else
			goto tr20;
	} else
		goto tr114;
	goto tr1;
case 99:
	switch( (*p) ) {
		case 58: goto tr112;
		case 93: goto tr97;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 100:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr115;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr115;
		} else
			goto tr20;
	} else
		goto tr115;
	goto tr1;
case 101:
	switch( (*p) ) {
		case 58: goto tr117;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr116;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr116;
		} else
			goto tr20;
	} else
		goto tr116;
	goto tr1;
case 102:
	switch( (*p) ) {
		case 58: goto tr117;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr118;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr118;
		} else
			goto tr20;
	} else
		goto tr118;
	goto tr1;
case 103:
	switch( (*p) ) {
		case 58: goto tr117;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr119;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr119;
		} else
			goto tr20;
	} else
		goto tr119;
	goto tr1;
case 104:
	switch( (*p) ) {
		case 58: goto tr117;
		case 93: goto tr97;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 105:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr120;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr120;
		} else
			goto tr20;
	} else
		goto tr120;
	goto tr1;
case 106:
	switch( (*p) ) {
		case 58: goto tr78;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr121;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr121;
		} else
			goto tr20;
	} else
		goto tr121;
	goto tr1;
case 107:
	switch( (*p) ) {
		case 58: goto tr78;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr122;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr122;
		} else
			goto tr20;
	} else
		goto tr122;
	goto tr1;
case 108:
	switch( (*p) ) {
		case 58: goto tr78;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr123;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr123;
		} else
			goto tr20;
	} else
		goto tr123;
	goto tr1;
case 109:
	switch( (*p) ) {
		case 58: goto tr78;
		case 93: goto tr97;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 110:
	switch( (*p) ) {
		case 58: goto tr78;
		case 93: goto tr21;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr79;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr79;
		} else
			goto tr20;
	} else
		goto tr79;
	goto tr1;
case 111:
	if ( (*p) == 93 )
		goto tr97;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr124;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr125;
		} else
			goto tr20;
	} else
		goto tr125;
	goto tr1;
case 112:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr127;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr126;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr128;
		} else
			goto tr20;
	} else
		goto tr128;
	goto tr1;
case 113:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr127;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr129;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr130;
		} else
			goto tr20;
	} else
		goto tr130;
	goto tr1;
case 114:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr127;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr131;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr131;
		} else
			goto tr20;
	} else
		goto tr131;
	goto tr1;
case 115:
	switch( (*p) ) {
		case 58: goto tr127;
		case 93: goto tr97;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 116:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr132;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr133;
		} else
			goto tr20;
	} else
		goto tr133;
	goto tr1;
case 117:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr135;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr134;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr136;
		} else
			goto tr20;
	} else
		goto tr136;
	goto tr1;
case 118:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr135;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr137;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr138;
		} else
			goto tr20;
	} else
		goto tr138;
	goto tr1;
case 119:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr135;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr139;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr139;
		} else
			goto tr20;
	} else
		goto tr139;
	goto tr1;
case 120:
	switch( (*p) ) {
		case 58: goto tr135;
		case 93: goto tr97;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 121:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr140;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr141;
		} else
			goto tr20;
	} else
		goto tr141;
	goto tr1;
case 122:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr143;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr142;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr144;
		} else
			goto tr20;
	} else
		goto tr144;
	goto tr1;
case 123:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr143;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr145;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr146;
		} else
			goto tr20;
	} else
		goto tr146;
	goto tr1;
case 124:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr143;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr147;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr147;
		} else
			goto tr20;
	} else
		goto tr147;
	goto tr1;
case 125:
	switch( (*p) ) {
		case 58: goto tr143;
		case 93: goto tr97;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 126:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr148;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr149;
		} else
			goto tr20;
	} else
		goto tr149;
	goto tr1;
case 127:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr151;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr150;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr152;
		} else
			goto tr20;
	} else
		goto tr152;
	goto tr1;
case 128:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr151;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr153;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr154;
		} else
			goto tr20;
	} else
		goto tr154;
	goto tr1;
case 129:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr151;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr155;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr155;
		} else
			goto tr20;
	} else
		goto tr155;
	goto tr1;
case 130:
	switch( (*p) ) {
		case 58: goto tr151;
		case 93: goto tr97;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 131:
	if ( (*p) == 93 )
		goto tr21;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr156;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr120;
		} else
			goto tr20;
	} else
		goto tr120;
	goto tr1;
case 132:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr78;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr157;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr121;
		} else
			goto tr20;
	} else
		goto tr121;
	goto tr1;
case 133:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr78;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr158;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr122;
		} else
			goto tr20;
	} else
		goto tr122;
	goto tr1;
case 134:
	switch( (*p) ) {
		case 46: goto tr76;
		case 58: goto tr78;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr123;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr123;
		} else
			goto tr20;
	} else
		goto tr123;
	goto tr1;
case 135:
	switch( (*p) ) {
		case 58: goto tr151;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr155;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr155;
		} else
			goto tr20;
	} else
		goto tr155;
	goto tr1;
case 136:
	switch( (*p) ) {
		case 58: goto tr151;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr154;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr154;
		} else
			goto tr20;
	} else
		goto tr154;
	goto tr1;
case 137:
	switch( (*p) ) {
		case 58: goto tr151;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr152;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr152;
		} else
			goto tr20;
	} else
		goto tr152;
	goto tr1;
case 138:
	switch( (*p) ) {
		case 58: goto tr143;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr147;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr147;
		} else
			goto tr20;
	} else
		goto tr147;
	goto tr1;
case 139:
	switch( (*p) ) {
		case 58: goto tr143;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr146;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr146;
		} else
			goto tr20;
	} else
		goto tr146;
	goto tr1;
case 140:
	switch( (*p) ) {
		case 58: goto tr143;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr144;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr144;
		} else
			goto tr20;
	} else
		goto tr144;
	goto tr1;
case 141:
	switch( (*p) ) {
		case 58: goto tr135;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr139;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr139;
		} else
			goto tr20;
	} else
		goto tr139;
	goto tr1;
case 142:
	switch( (*p) ) {
		case 58: goto tr135;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr138;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr138;
		} else
			goto tr20;
	} else
		goto tr138;
	goto tr1;
case 143:
	switch( (*p) ) {
		case 58: goto tr135;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr136;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr136;
		} else
			goto tr20;
	} else
		goto tr136;
	goto tr1;
case 144:
	switch( (*p) ) {
		case 58: goto tr127;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr131;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr131;
		} else
			goto tr20;
	} else
		goto tr131;
	goto tr1;
case 145:
	switch( (*p) ) {
		case 58: goto tr127;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr130;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr130;
		} else
			goto tr20;
	} else
		goto tr130;
	goto tr1;
case 146:
	switch( (*p) ) {
		case 58: goto tr127;
		case 93: goto tr97;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr20;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr20;
		} else
			goto tr128;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr20;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr20;
			} else if ( (*p) >= 97 )
				goto tr128;
		} else
			goto tr20;
	} else
		goto tr128;
	goto tr1;
case 147:
	switch( (*p) ) {
		case 58: goto tr48;
		case 93: goto tr21;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr20;
	} else if ( (*p) >= 33 )
		goto tr20;
	goto tr1;
case 148:
	switch( (*p) ) {
		case 34: goto tr160;
		case 92: goto tr161;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr159;
	goto tr1;
case 149:
	switch( (*p) ) {
		case 34: goto tr163;
		case 92: goto tr164;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr162;
	goto tr1;
case 150:
	if ( (*p) == 64 )
		goto tr165;
	goto tr1;
case 151:
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr166;
	goto tr1;
case 152:
	switch( (*p) ) {
		case 34: goto tr168;
		case 92: goto tr169;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr167;
	goto tr1;
case 153:
	switch( (*p) ) {
		case 34: goto tr171;
		case 45: goto tr170;
		case 62: goto tr172;
		case 64: goto tr173;
	}
	if ( (*p) < 47 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr170;
		} else if ( (*p) >= 33 )
			goto tr170;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr170;
		} else if ( (*p) >= 61 )
			goto tr170;
	} else
		goto tr170;
	goto tr1;
case 154:
	switch( (*p) ) {
		case 33: goto tr174;
		case 46: goto tr175;
		case 61: goto tr174;
		case 64: goto tr176;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr174;
		} else if ( (*p) >= 35 )
			goto tr174;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr174;
		} else if ( (*p) >= 63 )
			goto tr174;
	} else
		goto tr174;
	goto tr1;
case 155:
	switch( (*p) ) {
		case 33: goto tr174;
		case 45: goto tr174;
		case 61: goto tr174;
		case 63: goto tr174;
	}
	if ( (*p) < 47 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr174;
		} else if ( (*p) >= 35 )
			goto tr174;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr174;
		} else if ( (*p) >= 65 )
			goto tr174;
	} else
		goto tr174;
	goto tr1;
case 156:
	if ( (*p) == 91 )
		goto tr178;
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr177;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr177;
	} else
		goto tr177;
	goto tr1;
case 157:
	switch( (*p) ) {
		case 45: goto tr179;
		case 46: goto tr180;
		case 62: goto tr182;
		case 95: goto tr179;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr181;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr181;
	} else
		goto tr181;
	goto tr1;
case 158:
	switch( (*p) ) {
		case 45: goto tr179;
		case 95: goto tr179;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr181;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr181;
	} else
		goto tr181;
	goto tr1;
case 159:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr181;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr181;
	} else
		goto tr181;
	goto tr1;
case 320:
	if ( (*p) == 32 )
		goto tr353;
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr353;
	goto tr1;
case 160:
	switch( (*p) ) {
		case 45: goto tr183;
		case 73: goto tr186;
		case 95: goto tr183;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr185;
	} else
		goto tr185;
	goto tr1;
case 161:
	switch( (*p) ) {
		case 45: goto tr187;
		case 95: goto tr187;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr188;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr188;
	} else
		goto tr188;
	goto tr1;
case 162:
	switch( (*p) ) {
		case 45: goto tr187;
		case 58: goto tr189;
		case 95: goto tr187;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr188;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr188;
	} else
		goto tr188;
	goto tr1;
case 163:
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 164:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 165:
	if ( (*p) == 62 )
		goto tr192;
	goto tr1;
case 166:
	switch( (*p) ) {
		case 45: goto tr187;
		case 46: goto tr193;
		case 58: goto tr189;
		case 95: goto tr187;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr194;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr188;
	} else
		goto tr188;
	goto tr1;
case 167:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr195;
	goto tr1;
case 168:
	if ( (*p) == 46 )
		goto tr196;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr197;
	goto tr1;
case 169:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr198;
	goto tr1;
case 170:
	if ( (*p) == 46 )
		goto tr199;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr200;
	goto tr1;
case 171:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr201;
	goto tr1;
case 172:
	if ( (*p) == 93 )
		goto tr203;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr202;
	goto tr1;
case 173:
	if ( (*p) == 93 )
		goto tr203;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr204;
	goto tr1;
case 174:
	if ( (*p) == 93 )
		goto tr203;
	goto tr1;
case 175:
	if ( (*p) == 46 )
		goto tr199;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr205;
	goto tr1;
case 176:
	if ( (*p) == 46 )
		goto tr199;
	goto tr1;
case 177:
	if ( (*p) == 46 )
		goto tr196;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr206;
	goto tr1;
case 178:
	if ( (*p) == 46 )
		goto tr196;
	goto tr1;
case 179:
	switch( (*p) ) {
		case 45: goto tr187;
		case 46: goto tr193;
		case 58: goto tr189;
		case 95: goto tr187;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr207;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr188;
	} else
		goto tr188;
	goto tr1;
case 180:
	switch( (*p) ) {
		case 45: goto tr187;
		case 46: goto tr193;
		case 58: goto tr189;
		case 95: goto tr187;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr188;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr188;
	} else
		goto tr188;
	goto tr1;
case 181:
	switch( (*p) ) {
		case 45: goto tr187;
		case 58: goto tr189;
		case 80: goto tr208;
		case 95: goto tr187;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr188;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr188;
	} else
		goto tr188;
	goto tr1;
case 182:
	switch( (*p) ) {
		case 45: goto tr187;
		case 58: goto tr189;
		case 95: goto tr187;
		case 118: goto tr209;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr188;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr188;
	} else
		goto tr188;
	goto tr1;
case 183:
	switch( (*p) ) {
		case 45: goto tr187;
		case 54: goto tr210;
		case 58: goto tr189;
		case 95: goto tr187;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr188;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr188;
	} else
		goto tr188;
	goto tr1;
case 184:
	switch( (*p) ) {
		case 45: goto tr187;
		case 58: goto tr211;
		case 95: goto tr187;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr188;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr188;
	} else
		goto tr188;
	goto tr1;
case 185:
	if ( (*p) == 58 )
		goto tr213;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr212;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr212;
		} else
			goto tr190;
	} else
		goto tr212;
	goto tr1;
case 186:
	switch( (*p) ) {
		case 58: goto tr215;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr214;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr214;
		} else
			goto tr190;
	} else
		goto tr214;
	goto tr1;
case 187:
	switch( (*p) ) {
		case 58: goto tr215;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr216;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr216;
		} else
			goto tr190;
	} else
		goto tr216;
	goto tr1;
case 188:
	switch( (*p) ) {
		case 58: goto tr215;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr217;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr217;
		} else
			goto tr190;
	} else
		goto tr217;
	goto tr1;
case 189:
	switch( (*p) ) {
		case 58: goto tr215;
		case 93: goto tr191;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 190:
	switch( (*p) ) {
		case 58: goto tr219;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr218;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr218;
		} else
			goto tr190;
	} else
		goto tr218;
	goto tr1;
case 191:
	switch( (*p) ) {
		case 58: goto tr221;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr220;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr220;
		} else
			goto tr190;
	} else
		goto tr220;
	goto tr1;
case 192:
	switch( (*p) ) {
		case 58: goto tr221;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr222;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr222;
		} else
			goto tr190;
	} else
		goto tr222;
	goto tr1;
case 193:
	switch( (*p) ) {
		case 58: goto tr221;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr223;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr223;
		} else
			goto tr190;
	} else
		goto tr223;
	goto tr1;
case 194:
	switch( (*p) ) {
		case 58: goto tr221;
		case 93: goto tr191;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 195:
	switch( (*p) ) {
		case 58: goto tr219;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr224;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr224;
		} else
			goto tr190;
	} else
		goto tr224;
	goto tr1;
case 196:
	switch( (*p) ) {
		case 58: goto tr226;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr225;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr225;
		} else
			goto tr190;
	} else
		goto tr225;
	goto tr1;
case 197:
	switch( (*p) ) {
		case 58: goto tr226;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr227;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr227;
		} else
			goto tr190;
	} else
		goto tr227;
	goto tr1;
case 198:
	switch( (*p) ) {
		case 58: goto tr226;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr228;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr228;
		} else
			goto tr190;
	} else
		goto tr228;
	goto tr1;
case 199:
	switch( (*p) ) {
		case 58: goto tr226;
		case 93: goto tr191;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 200:
	switch( (*p) ) {
		case 58: goto tr219;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr229;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr229;
		} else
			goto tr190;
	} else
		goto tr229;
	goto tr1;
case 201:
	switch( (*p) ) {
		case 58: goto tr231;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr230;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr230;
		} else
			goto tr190;
	} else
		goto tr230;
	goto tr1;
case 202:
	switch( (*p) ) {
		case 58: goto tr231;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr232;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr232;
		} else
			goto tr190;
	} else
		goto tr232;
	goto tr1;
case 203:
	switch( (*p) ) {
		case 58: goto tr231;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr233;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr233;
		} else
			goto tr190;
	} else
		goto tr233;
	goto tr1;
case 204:
	switch( (*p) ) {
		case 58: goto tr231;
		case 93: goto tr191;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 205:
	switch( (*p) ) {
		case 58: goto tr219;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr234;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr234;
		} else
			goto tr190;
	} else
		goto tr234;
	goto tr1;
case 206:
	switch( (*p) ) {
		case 58: goto tr236;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr235;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr235;
		} else
			goto tr190;
	} else
		goto tr235;
	goto tr1;
case 207:
	switch( (*p) ) {
		case 58: goto tr236;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr237;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr237;
		} else
			goto tr190;
	} else
		goto tr237;
	goto tr1;
case 208:
	switch( (*p) ) {
		case 58: goto tr236;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr238;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr238;
		} else
			goto tr190;
	} else
		goto tr238;
	goto tr1;
case 209:
	switch( (*p) ) {
		case 58: goto tr236;
		case 93: goto tr191;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 210:
	switch( (*p) ) {
		case 58: goto tr240;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr239;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr239;
		} else
			goto tr190;
	} else
		goto tr239;
	goto tr1;
case 211:
	switch( (*p) ) {
		case 58: goto tr242;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr241;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr241;
		} else
			goto tr190;
	} else
		goto tr241;
	goto tr1;
case 212:
	switch( (*p) ) {
		case 58: goto tr242;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr243;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr243;
		} else
			goto tr190;
	} else
		goto tr243;
	goto tr1;
case 213:
	switch( (*p) ) {
		case 58: goto tr242;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr244;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr244;
		} else
			goto tr190;
	} else
		goto tr244;
	goto tr1;
case 214:
	switch( (*p) ) {
		case 58: goto tr242;
		case 93: goto tr191;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 215:
	switch( (*p) ) {
		case 58: goto tr240;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr245;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr246;
		} else
			goto tr190;
	} else
		goto tr246;
	goto tr1;
case 216:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr249;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr248;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr250;
		} else
			goto tr190;
	} else
		goto tr250;
	goto tr1;
case 217:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr190;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr190;
		} else if ( (*p) >= 58 )
			goto tr190;
	} else
		goto tr251;
	goto tr1;
case 218:
	switch( (*p) ) {
		case 46: goto tr252;
		case 93: goto tr191;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr190;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr190;
		} else if ( (*p) >= 58 )
			goto tr190;
	} else
		goto tr253;
	goto tr1;
case 219:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr190;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr190;
		} else if ( (*p) >= 58 )
			goto tr190;
	} else
		goto tr254;
	goto tr1;
case 220:
	switch( (*p) ) {
		case 46: goto tr255;
		case 93: goto tr191;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr190;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr190;
		} else if ( (*p) >= 58 )
			goto tr190;
	} else
		goto tr256;
	goto tr1;
case 221:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr190;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr190;
		} else if ( (*p) >= 58 )
			goto tr190;
	} else
		goto tr257;
	goto tr1;
case 222:
	if ( (*p) == 93 )
		goto tr259;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr190;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr190;
		} else if ( (*p) >= 58 )
			goto tr190;
	} else
		goto tr258;
	goto tr1;
case 223:
	if ( (*p) == 93 )
		goto tr259;
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr190;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr190;
		} else if ( (*p) >= 58 )
			goto tr190;
	} else
		goto tr260;
	goto tr1;
case 224:
	if ( (*p) == 93 )
		goto tr259;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 225:
	switch( (*p) ) {
		case 46: goto tr255;
		case 93: goto tr191;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr190;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr190;
		} else if ( (*p) >= 58 )
			goto tr190;
	} else
		goto tr261;
	goto tr1;
case 226:
	switch( (*p) ) {
		case 46: goto tr255;
		case 93: goto tr191;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 227:
	switch( (*p) ) {
		case 46: goto tr252;
		case 93: goto tr191;
	}
	if ( (*p) < 48 ) {
		if ( 33 <= (*p) && (*p) <= 47 )
			goto tr190;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr190;
		} else if ( (*p) >= 58 )
			goto tr190;
	} else
		goto tr262;
	goto tr1;
case 228:
	switch( (*p) ) {
		case 46: goto tr252;
		case 93: goto tr191;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 229:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr249;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr263;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr264;
		} else
			goto tr190;
	} else
		goto tr264;
	goto tr1;
case 230:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr249;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr265;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr265;
		} else
			goto tr190;
	} else
		goto tr265;
	goto tr1;
case 231:
	switch( (*p) ) {
		case 58: goto tr249;
		case 93: goto tr191;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 232:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr266;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr266;
		} else
			goto tr190;
	} else
		goto tr266;
	goto tr1;
case 233:
	if ( (*p) == 93 )
		goto tr268;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr267;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr267;
		} else
			goto tr190;
	} else
		goto tr267;
	goto tr1;
case 234:
	if ( (*p) == 93 )
		goto tr268;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr269;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr269;
		} else
			goto tr190;
	} else
		goto tr269;
	goto tr1;
case 235:
	if ( (*p) == 93 )
		goto tr268;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr270;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr270;
		} else
			goto tr190;
	} else
		goto tr270;
	goto tr1;
case 236:
	if ( (*p) == 93 )
		goto tr268;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 237:
	switch( (*p) ) {
		case 58: goto tr249;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr265;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr265;
		} else
			goto tr190;
	} else
		goto tr265;
	goto tr1;
case 238:
	switch( (*p) ) {
		case 58: goto tr249;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr264;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr264;
		} else
			goto tr190;
	} else
		goto tr264;
	goto tr1;
case 239:
	if ( (*p) == 93 )
		goto tr268;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr271;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr271;
		} else
			goto tr190;
	} else
		goto tr271;
	goto tr1;
case 240:
	switch( (*p) ) {
		case 58: goto tr273;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr272;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr272;
		} else
			goto tr190;
	} else
		goto tr272;
	goto tr1;
case 241:
	switch( (*p) ) {
		case 58: goto tr273;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr274;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr274;
		} else
			goto tr190;
	} else
		goto tr274;
	goto tr1;
case 242:
	switch( (*p) ) {
		case 58: goto tr273;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr275;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr275;
		} else
			goto tr190;
	} else
		goto tr275;
	goto tr1;
case 243:
	switch( (*p) ) {
		case 58: goto tr273;
		case 93: goto tr268;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 244:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr276;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr276;
		} else
			goto tr190;
	} else
		goto tr276;
	goto tr1;
case 245:
	switch( (*p) ) {
		case 58: goto tr278;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr277;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr277;
		} else
			goto tr190;
	} else
		goto tr277;
	goto tr1;
case 246:
	switch( (*p) ) {
		case 58: goto tr278;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr279;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr279;
		} else
			goto tr190;
	} else
		goto tr279;
	goto tr1;
case 247:
	switch( (*p) ) {
		case 58: goto tr278;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr280;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr280;
		} else
			goto tr190;
	} else
		goto tr280;
	goto tr1;
case 248:
	switch( (*p) ) {
		case 58: goto tr278;
		case 93: goto tr268;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 249:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr281;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr281;
		} else
			goto tr190;
	} else
		goto tr281;
	goto tr1;
case 250:
	switch( (*p) ) {
		case 58: goto tr283;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr282;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr282;
		} else
			goto tr190;
	} else
		goto tr282;
	goto tr1;
case 251:
	switch( (*p) ) {
		case 58: goto tr283;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr284;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr284;
		} else
			goto tr190;
	} else
		goto tr284;
	goto tr1;
case 252:
	switch( (*p) ) {
		case 58: goto tr283;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr285;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr285;
		} else
			goto tr190;
	} else
		goto tr285;
	goto tr1;
case 253:
	switch( (*p) ) {
		case 58: goto tr283;
		case 93: goto tr268;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 254:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr286;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr286;
		} else
			goto tr190;
	} else
		goto tr286;
	goto tr1;
case 255:
	switch( (*p) ) {
		case 58: goto tr288;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr287;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr287;
		} else
			goto tr190;
	} else
		goto tr287;
	goto tr1;
case 256:
	switch( (*p) ) {
		case 58: goto tr288;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr289;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr289;
		} else
			goto tr190;
	} else
		goto tr289;
	goto tr1;
case 257:
	switch( (*p) ) {
		case 58: goto tr288;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr290;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr290;
		} else
			goto tr190;
	} else
		goto tr290;
	goto tr1;
case 258:
	switch( (*p) ) {
		case 58: goto tr288;
		case 93: goto tr268;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 259:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr291;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr291;
		} else
			goto tr190;
	} else
		goto tr291;
	goto tr1;
case 260:
	switch( (*p) ) {
		case 58: goto tr249;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr292;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr292;
		} else
			goto tr190;
	} else
		goto tr292;
	goto tr1;
case 261:
	switch( (*p) ) {
		case 58: goto tr249;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr293;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr293;
		} else
			goto tr190;
	} else
		goto tr293;
	goto tr1;
case 262:
	switch( (*p) ) {
		case 58: goto tr249;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr294;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr294;
		} else
			goto tr190;
	} else
		goto tr294;
	goto tr1;
case 263:
	switch( (*p) ) {
		case 58: goto tr249;
		case 93: goto tr268;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 264:
	switch( (*p) ) {
		case 58: goto tr249;
		case 93: goto tr191;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr250;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr250;
		} else
			goto tr190;
	} else
		goto tr250;
	goto tr1;
case 265:
	if ( (*p) == 93 )
		goto tr268;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr295;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr296;
		} else
			goto tr190;
	} else
		goto tr296;
	goto tr1;
case 266:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr298;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr297;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr299;
		} else
			goto tr190;
	} else
		goto tr299;
	goto tr1;
case 267:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr298;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr300;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr301;
		} else
			goto tr190;
	} else
		goto tr301;
	goto tr1;
case 268:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr298;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr302;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr302;
		} else
			goto tr190;
	} else
		goto tr302;
	goto tr1;
case 269:
	switch( (*p) ) {
		case 58: goto tr298;
		case 93: goto tr268;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 270:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr303;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr304;
		} else
			goto tr190;
	} else
		goto tr304;
	goto tr1;
case 271:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr306;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr305;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr307;
		} else
			goto tr190;
	} else
		goto tr307;
	goto tr1;
case 272:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr306;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr308;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr309;
		} else
			goto tr190;
	} else
		goto tr309;
	goto tr1;
case 273:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr306;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr310;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr310;
		} else
			goto tr190;
	} else
		goto tr310;
	goto tr1;
case 274:
	switch( (*p) ) {
		case 58: goto tr306;
		case 93: goto tr268;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 275:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr311;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr312;
		} else
			goto tr190;
	} else
		goto tr312;
	goto tr1;
case 276:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr314;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr313;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr315;
		} else
			goto tr190;
	} else
		goto tr315;
	goto tr1;
case 277:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr314;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr316;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr317;
		} else
			goto tr190;
	} else
		goto tr317;
	goto tr1;
case 278:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr314;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr318;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr318;
		} else
			goto tr190;
	} else
		goto tr318;
	goto tr1;
case 279:
	switch( (*p) ) {
		case 58: goto tr314;
		case 93: goto tr268;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 280:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr319;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr320;
		} else
			goto tr190;
	} else
		goto tr320;
	goto tr1;
case 281:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr322;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr321;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr323;
		} else
			goto tr190;
	} else
		goto tr323;
	goto tr1;
case 282:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr322;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr324;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr325;
		} else
			goto tr190;
	} else
		goto tr325;
	goto tr1;
case 283:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr322;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr326;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr326;
		} else
			goto tr190;
	} else
		goto tr326;
	goto tr1;
case 284:
	switch( (*p) ) {
		case 58: goto tr322;
		case 93: goto tr268;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 285:
	if ( (*p) == 93 )
		goto tr191;
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 58 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr327;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr291;
		} else
			goto tr190;
	} else
		goto tr291;
	goto tr1;
case 286:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr249;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr328;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr292;
		} else
			goto tr190;
	} else
		goto tr292;
	goto tr1;
case 287:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr249;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr329;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr293;
		} else
			goto tr190;
	} else
		goto tr293;
	goto tr1;
case 288:
	switch( (*p) ) {
		case 46: goto tr247;
		case 58: goto tr249;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr294;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr294;
		} else
			goto tr190;
	} else
		goto tr294;
	goto tr1;
case 289:
	switch( (*p) ) {
		case 58: goto tr322;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr326;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr326;
		} else
			goto tr190;
	} else
		goto tr326;
	goto tr1;
case 290:
	switch( (*p) ) {
		case 58: goto tr322;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr325;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr325;
		} else
			goto tr190;
	} else
		goto tr325;
	goto tr1;
case 291:
	switch( (*p) ) {
		case 58: goto tr322;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr323;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr323;
		} else
			goto tr190;
	} else
		goto tr323;
	goto tr1;
case 292:
	switch( (*p) ) {
		case 58: goto tr314;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr318;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr318;
		} else
			goto tr190;
	} else
		goto tr318;
	goto tr1;
case 293:
	switch( (*p) ) {
		case 58: goto tr314;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr317;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr317;
		} else
			goto tr190;
	} else
		goto tr317;
	goto tr1;
case 294:
	switch( (*p) ) {
		case 58: goto tr314;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr315;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr315;
		} else
			goto tr190;
	} else
		goto tr315;
	goto tr1;
case 295:
	switch( (*p) ) {
		case 58: goto tr306;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr310;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr310;
		} else
			goto tr190;
	} else
		goto tr310;
	goto tr1;
case 296:
	switch( (*p) ) {
		case 58: goto tr306;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr309;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr309;
		} else
			goto tr190;
	} else
		goto tr309;
	goto tr1;
case 297:
	switch( (*p) ) {
		case 58: goto tr306;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr307;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr307;
		} else
			goto tr190;
	} else
		goto tr307;
	goto tr1;
case 298:
	switch( (*p) ) {
		case 58: goto tr298;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr302;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr302;
		} else
			goto tr190;
	} else
		goto tr302;
	goto tr1;
case 299:
	switch( (*p) ) {
		case 58: goto tr298;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr301;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr301;
		} else
			goto tr190;
	} else
		goto tr301;
	goto tr1;
case 300:
	switch( (*p) ) {
		case 58: goto tr298;
		case 93: goto tr268;
	}
	if ( (*p) < 65 ) {
		if ( (*p) < 48 ) {
			if ( 33 <= (*p) && (*p) <= 47 )
				goto tr190;
		} else if ( (*p) > 57 ) {
			if ( 59 <= (*p) && (*p) <= 64 )
				goto tr190;
		} else
			goto tr299;
	} else if ( (*p) > 70 ) {
		if ( (*p) < 94 ) {
			if ( 71 <= (*p) && (*p) <= 90 )
				goto tr190;
		} else if ( (*p) > 96 ) {
			if ( (*p) > 102 ) {
				if ( 103 <= (*p) && (*p) <= 126 )
					goto tr190;
			} else if ( (*p) >= 97 )
				goto tr299;
		} else
			goto tr190;
	} else
		goto tr299;
	goto tr1;
case 301:
	switch( (*p) ) {
		case 58: goto tr219;
		case 93: goto tr191;
	}
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr190;
	} else if ( (*p) >= 33 )
		goto tr190;
	goto tr1;
case 302:
	switch( (*p) ) {
		case 34: goto tr331;
		case 92: goto tr332;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr330;
	goto tr1;
case 303:
	switch( (*p) ) {
		case 34: goto tr334;
		case 92: goto tr335;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr333;
	goto tr1;
case 304:
	if ( (*p) == 64 )
		goto tr336;
	goto tr1;
case 305:
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr337;
	goto tr1;
case 306:
	switch( (*p) ) {
		case 34: goto tr339;
		case 92: goto tr340;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr338;
	goto tr1;
case 321:
	if ( (*p) == 32 )
		goto tr354;
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr354;
	goto tr1;
case 307:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr341;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr341;
	} else
		goto tr341;
	goto tr1;
case 308:
	switch( (*p) ) {
		case 44: goto tr342;
		case 45: goto tr343;
		case 46: goto tr173;
		case 58: goto tr344;
		case 95: goto tr343;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr341;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr341;
	} else
		goto tr341;
	goto tr1;
case 309:
	if ( (*p) == 64 )
		goto tr173;
	goto tr1;
case 310:
	switch( (*p) ) {
		case 45: goto tr343;
		case 95: goto tr343;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr341;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr341;
	} else
		goto tr341;
	goto tr1;
case 311:
	switch( (*p) ) {
		case 34: goto tr171;
		case 45: goto tr170;
		case 61: goto tr170;
		case 63: goto tr170;
	}
	if ( (*p) < 47 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr170;
		} else if ( (*p) >= 33 )
			goto tr170;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr170;
		} else if ( (*p) >= 65 )
			goto tr170;
	} else
		goto tr170;
	goto tr1;
case 312:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr345;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr345;
	} else
		goto tr345;
	goto tr1;
case 313:
	switch( (*p) ) {
		case 44: goto tr346;
		case 45: goto tr347;
		case 46: goto tr5;
		case 58: goto tr348;
		case 95: goto tr347;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr345;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr345;
	} else
		goto tr345;
	goto tr1;
case 314:
	if ( (*p) == 64 )
		goto tr5;
	goto tr1;
case 315:
	switch( (*p) ) {
		case 45: goto tr347;
		case 95: goto tr347;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr345;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr345;
	} else
		goto tr345;
	goto tr1;
case 316:
	switch( (*p) ) {
		case 34: goto tr3;
		case 45: goto tr2;
		case 61: goto tr2;
		case 63: goto tr2;
	}
	if ( (*p) < 47 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr2;
		} else if ( (*p) >= 33 )
			goto tr2;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr2;
		} else if ( (*p) >= 65 )
			goto tr2;
	} else
		goto tr2;
	goto tr1;
	}

	tr1: cs = 0; goto _again;
	tr0: cs = 1; goto _again;
	tr6: cs = 2; goto _again;
	tr2: cs = 2; goto f0;
	tr7: cs = 3; goto _again;
	tr8: cs = 4; goto f2;
	tr165: cs = 4; goto f14;
	tr11: cs = 5; goto _again;
	tr350: cs = 6; goto _again;
	tr10: cs = 7; goto _again;
	tr17: cs = 8; goto _again;
	tr13: cs = 8; goto f4;
	tr18: cs = 9; goto _again;
	tr15: cs = 9; goto f4;
	tr19: cs = 10; goto _again;
	tr20: cs = 11; goto _again;
	tr14: cs = 12; goto f5;
	tr22: cs = 13; goto _again;
	tr24: cs = 14; goto _again;
	tr25: cs = 15; goto _again;
	tr27: cs = 16; goto _again;
	tr28: cs = 17; goto _again;
	tr30: cs = 18; goto _again;
	tr31: cs = 19; goto _again;
	tr33: cs = 20; goto _again;
	tr29: cs = 21; goto _again;
	tr34: cs = 22; goto _again;
	tr26: cs = 23; goto _again;
	tr35: cs = 24; goto _again;
	tr23: cs = 25; goto _again;
	tr36: cs = 26; goto _again;
	tr16: cs = 27; goto f4;
	tr37: cs = 28; goto _again;
	tr38: cs = 29; goto _again;
	tr39: cs = 30; goto _again;
	tr40: cs = 31; goto _again;
	tr41: cs = 32; goto f8;
	tr43: cs = 33; goto _again;
	tr45: cs = 34; goto _again;
	tr46: cs = 35; goto _again;
	tr44: cs = 36; goto _again;
	tr47: cs = 37; goto _again;
	tr49: cs = 38; goto _again;
	tr51: cs = 39; goto _again;
	tr52: cs = 40; goto _again;
	tr50: cs = 41; goto _again;
	tr53: cs = 42; goto _again;
	tr54: cs = 43; goto _again;
	tr56: cs = 44; goto _again;
	tr57: cs = 45; goto _again;
	tr55: cs = 46; goto _again;
	tr58: cs = 47; goto _again;
	tr59: cs = 48; goto _again;
	tr61: cs = 49; goto _again;
	tr62: cs = 50; goto _again;
	tr60: cs = 51; goto _again;
	tr63: cs = 52; goto _again;
	tr64: cs = 53; goto _again;
	tr66: cs = 54; goto _again;
	tr67: cs = 55; goto _again;
	tr65: cs = 56; goto _again;
	tr68: cs = 57; goto _again;
	tr70: cs = 58; goto _again;
	tr72: cs = 59; goto _again;
	tr73: cs = 60; goto _again;
	tr71: cs = 61; goto _again;
	tr74: cs = 62; goto f9;
	tr76: cs = 63; goto _again;
	tr80: cs = 64; goto _again;
	tr81: cs = 65; goto _again;
	tr83: cs = 66; goto _again;
	tr84: cs = 67; goto _again;
	tr86: cs = 68; goto _again;
	tr87: cs = 69; goto _again;
	tr89: cs = 70; goto _again;
	tr85: cs = 71; goto _again;
	tr90: cs = 72; goto _again;
	tr82: cs = 73; goto _again;
	tr91: cs = 74; goto _again;
	tr77: cs = 75; goto _again;
	tr92: cs = 76; goto _again;
	tr94: cs = 77; goto _again;
	tr78: cs = 78; goto _again;
	tr95: cs = 79; goto _again;
	tr96: cs = 80; goto _again;
	tr98: cs = 81; goto _again;
	tr99: cs = 82; goto _again;
	tr93: cs = 83; goto _again;
	tr79: cs = 84; goto _again;
	tr69: cs = 85; goto _again;
	tr100: cs = 86; goto _again;
	tr101: cs = 87; goto _again;
	tr103: cs = 88; goto _again;
	tr104: cs = 89; goto _again;
	tr102: cs = 90; goto _again;
	tr105: cs = 91; goto _again;
	tr106: cs = 92; goto _again;
	tr108: cs = 93; goto _again;
	tr109: cs = 94; goto _again;
	tr107: cs = 95; goto _again;
	tr110: cs = 96; goto _again;
	tr111: cs = 97; goto _again;
	tr113: cs = 98; goto _again;
	tr114: cs = 99; goto _again;
	tr112: cs = 100; goto _again;
	tr115: cs = 101; goto _again;
	tr116: cs = 102; goto _again;
	tr118: cs = 103; goto _again;
	tr119: cs = 104; goto _again;
	tr117: cs = 105; goto _again;
	tr120: cs = 106; goto _again;
	tr121: cs = 107; goto _again;
	tr122: cs = 108; goto _again;
	tr123: cs = 109; goto _again;
	tr75: cs = 110; goto _again;
	tr48: cs = 111; goto _again;
	tr124: cs = 112; goto f9;
	tr126: cs = 113; goto _again;
	tr129: cs = 114; goto _again;
	tr131: cs = 115; goto _again;
	tr127: cs = 116; goto _again;
	tr132: cs = 117; goto f9;
	tr134: cs = 118; goto _again;
	tr137: cs = 119; goto _again;
	tr139: cs = 120; goto _again;
	tr135: cs = 121; goto _again;
	tr140: cs = 122; goto f9;
	tr142: cs = 123; goto _again;
	tr145: cs = 124; goto _again;
	tr147: cs = 125; goto _again;
	tr143: cs = 126; goto _again;
	tr148: cs = 127; goto f9;
	tr150: cs = 128; goto _again;
	tr153: cs = 129; goto _again;
	tr155: cs = 130; goto _again;
	tr151: cs = 131; goto _again;
	tr156: cs = 132; goto f9;
	tr157: cs = 133; goto _again;
	tr158: cs = 134; goto _again;
	tr154: cs = 135; goto _again;
	tr152: cs = 136; goto _again;
	tr149: cs = 137; goto _again;
	tr146: cs = 138; goto _again;
	tr144: cs = 139; goto _again;
	tr141: cs = 140; goto _again;
	tr138: cs = 141; goto _again;
	tr136: cs = 142; goto _again;
	tr133: cs = 143; goto _again;
	tr130: cs = 144; goto _again;
	tr128: cs = 145; goto _again;
	tr125: cs = 146; goto _again;
	tr42: cs = 147; goto f8;
	tr3: cs = 148; goto f1;
	tr162: cs = 149; goto _again;
	tr159: cs = 149; goto f12;
	tr167: cs = 149; goto f15;
	tr163: cs = 150; goto f2;
	tr160: cs = 150; goto f13;
	tr168: cs = 150; goto f16;
	tr164: cs = 151; goto _again;
	tr161: cs = 151; goto f12;
	tr169: cs = 151; goto f15;
	tr166: cs = 152; goto _again;
	tr4: cs = 153; goto _again;
	tr174: cs = 154; goto _again;
	tr170: cs = 154; goto f0;
	tr175: cs = 155; goto _again;
	tr176: cs = 156; goto f2;
	tr336: cs = 156; goto f14;
	tr181: cs = 157; goto _again;
	tr177: cs = 157; goto f3;
	tr179: cs = 158; goto _again;
	tr180: cs = 159; goto _again;
	tr178: cs = 160; goto _again;
	tr187: cs = 161; goto _again;
	tr183: cs = 161; goto f4;
	tr188: cs = 162; goto _again;
	tr185: cs = 162; goto f4;
	tr189: cs = 163; goto _again;
	tr190: cs = 164; goto _again;
	tr191: cs = 165; goto f6;
	tr203: cs = 165; goto f7;
	tr259: cs = 165; goto f10;
	tr268: cs = 165; goto f11;
	tr184: cs = 166; goto f5;
	tr193: cs = 167; goto _again;
	tr195: cs = 168; goto _again;
	tr196: cs = 169; goto _again;
	tr198: cs = 170; goto _again;
	tr199: cs = 171; goto _again;
	tr201: cs = 172; goto _again;
	tr202: cs = 173; goto _again;
	tr204: cs = 174; goto _again;
	tr200: cs = 175; goto _again;
	tr205: cs = 176; goto _again;
	tr197: cs = 177; goto _again;
	tr206: cs = 178; goto _again;
	tr194: cs = 179; goto _again;
	tr207: cs = 180; goto _again;
	tr186: cs = 181; goto f4;
	tr208: cs = 182; goto _again;
	tr209: cs = 183; goto _again;
	tr210: cs = 184; goto _again;
	tr211: cs = 185; goto _again;
	tr212: cs = 186; goto f8;
	tr214: cs = 187; goto _again;
	tr216: cs = 188; goto _again;
	tr217: cs = 189; goto _again;
	tr215: cs = 190; goto _again;
	tr218: cs = 191; goto _again;
	tr220: cs = 192; goto _again;
	tr222: cs = 193; goto _again;
	tr223: cs = 194; goto _again;
	tr221: cs = 195; goto _again;
	tr224: cs = 196; goto _again;
	tr225: cs = 197; goto _again;
	tr227: cs = 198; goto _again;
	tr228: cs = 199; goto _again;
	tr226: cs = 200; goto _again;
	tr229: cs = 201; goto _again;
	tr230: cs = 202; goto _again;
	tr232: cs = 203; goto _again;
	tr233: cs = 204; goto _again;
	tr231: cs = 205; goto _again;
	tr234: cs = 206; goto _again;
	tr235: cs = 207; goto _again;
	tr237: cs = 208; goto _again;
	tr238: cs = 209; goto _again;
	tr236: cs = 210; goto _again;
	tr239: cs = 211; goto _again;
	tr241: cs = 212; goto _again;
	tr243: cs = 213; goto _again;
	tr244: cs = 214; goto _again;
	tr242: cs = 215; goto _again;
	tr245: cs = 216; goto f9;
	tr247: cs = 217; goto _again;
	tr251: cs = 218; goto _again;
	tr252: cs = 219; goto _again;
	tr254: cs = 220; goto _again;
	tr255: cs = 221; goto _again;
	tr257: cs = 222; goto _again;
	tr258: cs = 223; goto _again;
	tr260: cs = 224; goto _again;
	tr256: cs = 225; goto _again;
	tr261: cs = 226; goto _again;
	tr253: cs = 227; goto _again;
	tr262: cs = 228; goto _again;
	tr248: cs = 229; goto _again;
	tr263: cs = 230; goto _again;
	tr265: cs = 231; goto _again;
	tr249: cs = 232; goto _again;
	tr266: cs = 233; goto _again;
	tr267: cs = 234; goto _again;
	tr269: cs = 235; goto _again;
	tr270: cs = 236; goto _again;
	tr264: cs = 237; goto _again;
	tr250: cs = 238; goto _again;
	tr240: cs = 239; goto _again;
	tr271: cs = 240; goto _again;
	tr272: cs = 241; goto _again;
	tr274: cs = 242; goto _again;
	tr275: cs = 243; goto _again;
	tr273: cs = 244; goto _again;
	tr276: cs = 245; goto _again;
	tr277: cs = 246; goto _again;
	tr279: cs = 247; goto _again;
	tr280: cs = 248; goto _again;
	tr278: cs = 249; goto _again;
	tr281: cs = 250; goto _again;
	tr282: cs = 251; goto _again;
	tr284: cs = 252; goto _again;
	tr285: cs = 253; goto _again;
	tr283: cs = 254; goto _again;
	tr286: cs = 255; goto _again;
	tr287: cs = 256; goto _again;
	tr289: cs = 257; goto _again;
	tr290: cs = 258; goto _again;
	tr288: cs = 259; goto _again;
	tr291: cs = 260; goto _again;
	tr292: cs = 261; goto _again;
	tr293: cs = 262; goto _again;
	tr294: cs = 263; goto _again;
	tr246: cs = 264; goto _again;
	tr219: cs = 265; goto _again;
	tr295: cs = 266; goto f9;
	tr297: cs = 267; goto _again;
	tr300: cs = 268; goto _again;
	tr302: cs = 269; goto _again;
	tr298: cs = 270; goto _again;
	tr303: cs = 271; goto f9;
	tr305: cs = 272; goto _again;
	tr308: cs = 273; goto _again;
	tr310: cs = 274; goto _again;
	tr306: cs = 275; goto _again;
	tr311: cs = 276; goto f9;
	tr313: cs = 277; goto _again;
	tr316: cs = 278; goto _again;
	tr318: cs = 279; goto _again;
	tr314: cs = 280; goto _again;
	tr319: cs = 281; goto f9;
	tr321: cs = 282; goto _again;
	tr324: cs = 283; goto _again;
	tr326: cs = 284; goto _again;
	tr322: cs = 285; goto _again;
	tr327: cs = 286; goto f9;
	tr328: cs = 287; goto _again;
	tr329: cs = 288; goto _again;
	tr325: cs = 289; goto _again;
	tr323: cs = 290; goto _again;
	tr320: cs = 291; goto _again;
	tr317: cs = 292; goto _again;
	tr315: cs = 293; goto _again;
	tr312: cs = 294; goto _again;
	tr309: cs = 295; goto _again;
	tr307: cs = 296; goto _again;
	tr304: cs = 297; goto _again;
	tr301: cs = 298; goto _again;
	tr299: cs = 299; goto _again;
	tr296: cs = 300; goto _again;
	tr213: cs = 301; goto f8;
	tr171: cs = 302; goto f1;
	tr333: cs = 303; goto _again;
	tr330: cs = 303; goto f12;
	tr338: cs = 303; goto f15;
	tr334: cs = 304; goto f2;
	tr331: cs = 304; goto f13;
	tr339: cs = 304; goto f16;
	tr335: cs = 305; goto _again;
	tr332: cs = 305; goto f12;
	tr340: cs = 305; goto f15;
	tr337: cs = 306; goto _again;
	tr173: cs = 307; goto _again;
	tr341: cs = 308; goto _again;
	tr342: cs = 309; goto _again;
	tr343: cs = 310; goto _again;
	tr344: cs = 311; goto _again;
	tr5: cs = 312; goto _again;
	tr345: cs = 313; goto _again;
	tr346: cs = 314; goto _again;
	tr347: cs = 315; goto _again;
	tr348: cs = 316; goto _again;
	tr12: cs = 317; goto _again;
	tr9: cs = 317; goto f3;
	tr351: cs = 318; goto _again;
	tr349: cs = 318; goto f19;
	tr352: cs = 318; goto f20;
	tr353: cs = 318; goto f21;
	tr354: cs = 318; goto f22;
	tr21: cs = 319; goto f6;
	tr32: cs = 319; goto f7;
	tr88: cs = 319; goto f10;
	tr97: cs = 319; goto f11;
	tr182: cs = 320; goto f17;
	tr192: cs = 320; goto f18;
	tr172: cs = 321; goto _again;

f8:
#line 5 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{}
	goto _again;
f9:
#line 7 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{}
	goto _again;
f12:
#line 10 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->user = p;
  }
	goto _again;
f2:
#line 14 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->user) {
      addr->user_len = p - addr->user;
    }
  }
	goto _again;
f3:
#line 20 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->domain = p;
  }
	goto _again;
f4:
#line 30 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->domain = p;
    addr->flags |= RSPAMD_EMAIL_ADDR_IP;
  }
	goto _again;
f6:
#line 35 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
	goto _again;
f15:
#line 41 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_HAS_BACKSLASH;
  }
	goto _again;
f14:
#line 45 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_QUOTED;
  }
	goto _again;
f1:
#line 64 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->addr = p;
  }
	goto _again;
f18:
#line 68 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
	goto _again;
f11:
#line 6 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{}
#line 35 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
	goto _again;
f7:
#line 8 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{}
#line 35 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
	goto _again;
f13:
#line 10 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->user = p;
  }
#line 14 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->user) {
      addr->user_len = p - addr->user;
    }
  }
	goto _again;
f17:
#line 24 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
#line 68 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
	goto _again;
f5:
#line 30 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->domain = p;
    addr->flags |= RSPAMD_EMAIL_ADDR_IP;
  }
#line 7 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{}
	goto _again;
f16:
#line 41 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_HAS_BACKSLASH;
  }
#line 14 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->user) {
      addr->user_len = p - addr->user;
    }
  }
	goto _again;
f22:
#line 49 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_EMPTY;
    addr->addr = "";
    addr->user = addr->addr;
    addr->domain = addr->addr;
  }
#line 56 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	goto _again;
f21:
#line 60 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_BRACED;
  }
#line 56 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	goto _again;
f0:
#line 64 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->addr = p;
  }
#line 10 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->user = p;
  }
	goto _again;
f20:
#line 68 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
#line 56 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	goto _again;
f10:
#line 8 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{}
#line 6 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{}
#line 35 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
	goto _again;
f19:
#line 24 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
#line 68 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
#line 56 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	goto _again;

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	if ( p == eof )
	{
	switch ( _smtp_addr_parser_eof_actions[cs] ) {
	case 23:
#line 49 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_EMPTY;
    addr->addr = "";
    addr->user = addr->addr;
    addr->domain = addr->addr;
  }
#line 56 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	break;
	case 22:
#line 60 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_BRACED;
  }
#line 56 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	break;
	case 21:
#line 68 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
#line 56 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	break;
	case 20:
#line 24 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
#line 68 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
#line 56 "../rspamd/src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	break;
#line 7419 "../rspamd/src/libmime/parsers/smtp_addr_parser.c"
	}
	}

	_out: {}
	}

#line 95 "../rspamd/src/ragel/smtp_addr_parser.rl"

  return cs;
}
