
#line 1 "src/ragel/smtp_addr_parser.rl"

#line 72 "src/ragel/smtp_addr_parser.rl"



#line 9 "src/libmime/parsers/smtp_addr_parser.c"
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
	0, 0, 0, 14, 0, 15, 16, 17
};

static const int smtp_addr_parser_start = 1;
static const int smtp_addr_parser_first_final = 75;
static const int smtp_addr_parser_error = 0;

static const int smtp_addr_parser_en_main = 1;


#line 75 "src/ragel/smtp_addr_parser.rl"

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


#line 45 "src/libmime/parsers/smtp_addr_parser.c"
	{
	cs = smtp_addr_parser_start;
	}

#line 89 "src/ragel/smtp_addr_parser.rl"

#line 52 "src/libmime/parsers/smtp_addr_parser.c"
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
case 75:
	switch( (*p) ) {
		case 32: goto tr101;
		case 45: goto tr11;
		case 46: goto tr102;
		case 95: goto tr11;
	}
	if ( (*p) < 48 ) {
		if ( 9 <= (*p) && (*p) <= 13 )
			goto tr101;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr12;
		} else if ( (*p) >= 65 )
			goto tr12;
	} else
		goto tr12;
	goto tr1;
case 76:
	if ( (*p) == 32 )
		goto tr103;
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr103;
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
		case 45: goto tr16;
		case 95: goto tr16;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr17;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr17;
	} else
		goto tr17;
	goto tr1;
case 9:
	switch( (*p) ) {
		case 45: goto tr16;
		case 58: goto tr18;
		case 95: goto tr16;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr17;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr17;
	} else
		goto tr17;
	goto tr1;
case 10:
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr19;
	} else if ( (*p) >= 33 )
		goto tr19;
	goto tr1;
case 11:
	if ( (*p) == 93 )
		goto tr20;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr19;
	} else if ( (*p) >= 33 )
		goto tr19;
	goto tr1;
case 77:
	if ( (*p) == 32 )
		goto tr104;
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr104;
	goto tr1;
case 12:
	switch( (*p) ) {
		case 45: goto tr16;
		case 46: goto tr21;
		case 58: goto tr18;
		case 95: goto tr16;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr22;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr17;
	} else
		goto tr17;
	goto tr1;
case 13:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr23;
	goto tr1;
case 14:
	if ( (*p) == 46 )
		goto tr24;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr25;
	goto tr1;
case 15:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr26;
	goto tr1;
case 16:
	if ( (*p) == 46 )
		goto tr27;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr28;
	goto tr1;
case 17:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr29;
	goto tr1;
case 18:
	if ( (*p) == 93 )
		goto tr20;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr30;
	goto tr1;
case 19:
	if ( (*p) == 93 )
		goto tr20;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr31;
	goto tr1;
case 20:
	if ( (*p) == 93 )
		goto tr20;
	goto tr1;
case 21:
	if ( (*p) == 46 )
		goto tr27;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr32;
	goto tr1;
case 22:
	if ( (*p) == 46 )
		goto tr27;
	goto tr1;
case 23:
	if ( (*p) == 46 )
		goto tr24;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr33;
	goto tr1;
case 24:
	if ( (*p) == 46 )
		goto tr24;
	goto tr1;
case 25:
	switch( (*p) ) {
		case 45: goto tr16;
		case 46: goto tr21;
		case 58: goto tr18;
		case 95: goto tr16;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr34;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr17;
	} else
		goto tr17;
	goto tr1;
case 26:
	switch( (*p) ) {
		case 45: goto tr16;
		case 46: goto tr21;
		case 58: goto tr18;
		case 95: goto tr16;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr17;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr17;
	} else
		goto tr17;
	goto tr1;
case 27:
	switch( (*p) ) {
		case 34: goto tr36;
		case 92: goto tr37;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr35;
	goto tr1;
case 28:
	switch( (*p) ) {
		case 34: goto tr39;
		case 92: goto tr40;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr38;
	goto tr1;
case 29:
	if ( (*p) == 64 )
		goto tr41;
	goto tr1;
case 30:
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr42;
	goto tr1;
case 31:
	switch( (*p) ) {
		case 34: goto tr44;
		case 92: goto tr45;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr43;
	goto tr1;
case 32:
	switch( (*p) ) {
		case 34: goto tr47;
		case 45: goto tr46;
		case 62: goto tr48;
		case 64: goto tr49;
	}
	if ( (*p) < 47 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr46;
		} else if ( (*p) >= 33 )
			goto tr46;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr46;
		} else if ( (*p) >= 61 )
			goto tr46;
	} else
		goto tr46;
	goto tr1;
case 33:
	switch( (*p) ) {
		case 33: goto tr50;
		case 46: goto tr51;
		case 61: goto tr50;
		case 64: goto tr52;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr50;
		} else if ( (*p) >= 35 )
			goto tr50;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr50;
		} else if ( (*p) >= 63 )
			goto tr50;
	} else
		goto tr50;
	goto tr1;
case 34:
	switch( (*p) ) {
		case 33: goto tr50;
		case 45: goto tr50;
		case 61: goto tr50;
		case 63: goto tr50;
	}
	if ( (*p) < 47 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr50;
		} else if ( (*p) >= 35 )
			goto tr50;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr50;
		} else if ( (*p) >= 65 )
			goto tr50;
	} else
		goto tr50;
	goto tr1;
case 35:
	if ( (*p) == 91 )
		goto tr54;
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr53;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr53;
	} else
		goto tr53;
	goto tr1;
case 36:
	switch( (*p) ) {
		case 45: goto tr55;
		case 46: goto tr56;
		case 62: goto tr58;
		case 95: goto tr55;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr57;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr57;
	} else
		goto tr57;
	goto tr1;
case 37:
	switch( (*p) ) {
		case 45: goto tr55;
		case 95: goto tr55;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr57;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr57;
	} else
		goto tr57;
	goto tr1;
case 38:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr57;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr57;
	} else
		goto tr57;
	goto tr1;
case 78:
	if ( (*p) == 32 )
		goto tr105;
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr105;
	goto tr1;
case 39:
	switch( (*p) ) {
		case 45: goto tr59;
		case 95: goto tr59;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr60;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr61;
	} else
		goto tr61;
	goto tr1;
case 40:
	switch( (*p) ) {
		case 45: goto tr62;
		case 95: goto tr62;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr63;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr63;
	} else
		goto tr63;
	goto tr1;
case 41:
	switch( (*p) ) {
		case 45: goto tr62;
		case 58: goto tr64;
		case 95: goto tr62;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr63;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr63;
	} else
		goto tr63;
	goto tr1;
case 42:
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr65;
	} else if ( (*p) >= 33 )
		goto tr65;
	goto tr1;
case 43:
	if ( (*p) == 93 )
		goto tr66;
	if ( (*p) > 90 ) {
		if ( 94 <= (*p) && (*p) <= 126 )
			goto tr65;
	} else if ( (*p) >= 33 )
		goto tr65;
	goto tr1;
case 44:
	if ( (*p) == 62 )
		goto tr67;
	goto tr1;
case 45:
	switch( (*p) ) {
		case 45: goto tr62;
		case 46: goto tr68;
		case 58: goto tr64;
		case 95: goto tr62;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr69;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr63;
	} else
		goto tr63;
	goto tr1;
case 46:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr70;
	goto tr1;
case 47:
	if ( (*p) == 46 )
		goto tr71;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr72;
	goto tr1;
case 48:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr73;
	goto tr1;
case 49:
	if ( (*p) == 46 )
		goto tr74;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr75;
	goto tr1;
case 50:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr76;
	goto tr1;
case 51:
	if ( (*p) == 93 )
		goto tr66;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr77;
	goto tr1;
case 52:
	if ( (*p) == 93 )
		goto tr66;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr78;
	goto tr1;
case 53:
	if ( (*p) == 93 )
		goto tr66;
	goto tr1;
case 54:
	if ( (*p) == 46 )
		goto tr74;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr79;
	goto tr1;
case 55:
	if ( (*p) == 46 )
		goto tr74;
	goto tr1;
case 56:
	if ( (*p) == 46 )
		goto tr71;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr80;
	goto tr1;
case 57:
	if ( (*p) == 46 )
		goto tr71;
	goto tr1;
case 58:
	switch( (*p) ) {
		case 45: goto tr62;
		case 46: goto tr68;
		case 58: goto tr64;
		case 95: goto tr62;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr81;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr63;
	} else
		goto tr63;
	goto tr1;
case 59:
	switch( (*p) ) {
		case 45: goto tr62;
		case 46: goto tr68;
		case 58: goto tr64;
		case 95: goto tr62;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr63;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr63;
	} else
		goto tr63;
	goto tr1;
case 60:
	switch( (*p) ) {
		case 34: goto tr83;
		case 92: goto tr84;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr82;
	goto tr1;
case 61:
	switch( (*p) ) {
		case 34: goto tr86;
		case 92: goto tr87;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr85;
	goto tr1;
case 62:
	if ( (*p) == 64 )
		goto tr88;
	goto tr1;
case 63:
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr89;
	goto tr1;
case 64:
	switch( (*p) ) {
		case 34: goto tr91;
		case 92: goto tr92;
	}
	if ( 32 <= (*p) && (*p) <= 126 )
		goto tr90;
	goto tr1;
case 79:
	if ( (*p) == 32 )
		goto tr106;
	if ( 9 <= (*p) && (*p) <= 13 )
		goto tr106;
	goto tr1;
case 65:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr93;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr93;
	} else
		goto tr93;
	goto tr1;
case 66:
	switch( (*p) ) {
		case 44: goto tr94;
		case 45: goto tr95;
		case 46: goto tr49;
		case 58: goto tr96;
		case 95: goto tr95;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr93;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr93;
	} else
		goto tr93;
	goto tr1;
case 67:
	if ( (*p) == 64 )
		goto tr49;
	goto tr1;
case 68:
	switch( (*p) ) {
		case 45: goto tr95;
		case 95: goto tr95;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr93;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr93;
	} else
		goto tr93;
	goto tr1;
case 69:
	switch( (*p) ) {
		case 34: goto tr47;
		case 45: goto tr46;
		case 61: goto tr46;
		case 63: goto tr46;
	}
	if ( (*p) < 47 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr46;
		} else if ( (*p) >= 33 )
			goto tr46;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 126 )
				goto tr46;
		} else if ( (*p) >= 65 )
			goto tr46;
	} else
		goto tr46;
	goto tr1;
case 70:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr97;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr97;
	} else
		goto tr97;
	goto tr1;
case 71:
	switch( (*p) ) {
		case 44: goto tr98;
		case 45: goto tr99;
		case 46: goto tr5;
		case 58: goto tr100;
		case 95: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr97;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr97;
	} else
		goto tr97;
	goto tr1;
case 72:
	if ( (*p) == 64 )
		goto tr5;
	goto tr1;
case 73:
	switch( (*p) ) {
		case 45: goto tr99;
		case 95: goto tr99;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr97;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr97;
	} else
		goto tr97;
	goto tr1;
case 74:
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
	tr41: cs = 4; goto f8;
	tr11: cs = 5; goto _again;
	tr102: cs = 6; goto _again;
	tr10: cs = 7; goto _again;
	tr16: cs = 8; goto _again;
	tr13: cs = 8; goto f4;
	tr17: cs = 9; goto _again;
	tr15: cs = 9; goto f4;
	tr18: cs = 10; goto _again;
	tr19: cs = 11; goto _again;
	tr14: cs = 12; goto f4;
	tr21: cs = 13; goto _again;
	tr23: cs = 14; goto _again;
	tr24: cs = 15; goto _again;
	tr26: cs = 16; goto _again;
	tr27: cs = 17; goto _again;
	tr29: cs = 18; goto _again;
	tr30: cs = 19; goto _again;
	tr31: cs = 20; goto _again;
	tr28: cs = 21; goto _again;
	tr32: cs = 22; goto _again;
	tr25: cs = 23; goto _again;
	tr33: cs = 24; goto _again;
	tr22: cs = 25; goto _again;
	tr34: cs = 26; goto _again;
	tr3: cs = 27; goto f1;
	tr38: cs = 28; goto _again;
	tr35: cs = 28; goto f6;
	tr43: cs = 28; goto f9;
	tr39: cs = 29; goto f2;
	tr36: cs = 29; goto f7;
	tr44: cs = 29; goto f10;
	tr40: cs = 30; goto _again;
	tr37: cs = 30; goto f6;
	tr45: cs = 30; goto f9;
	tr42: cs = 31; goto _again;
	tr4: cs = 32; goto _again;
	tr50: cs = 33; goto _again;
	tr46: cs = 33; goto f0;
	tr51: cs = 34; goto _again;
	tr52: cs = 35; goto f2;
	tr88: cs = 35; goto f8;
	tr57: cs = 36; goto _again;
	tr53: cs = 36; goto f3;
	tr55: cs = 37; goto _again;
	tr56: cs = 38; goto _again;
	tr54: cs = 39; goto _again;
	tr62: cs = 40; goto _again;
	tr59: cs = 40; goto f4;
	tr63: cs = 41; goto _again;
	tr61: cs = 41; goto f4;
	tr64: cs = 42; goto _again;
	tr65: cs = 43; goto _again;
	tr66: cs = 44; goto f5;
	tr60: cs = 45; goto f4;
	tr68: cs = 46; goto _again;
	tr70: cs = 47; goto _again;
	tr71: cs = 48; goto _again;
	tr73: cs = 49; goto _again;
	tr74: cs = 50; goto _again;
	tr76: cs = 51; goto _again;
	tr77: cs = 52; goto _again;
	tr78: cs = 53; goto _again;
	tr75: cs = 54; goto _again;
	tr79: cs = 55; goto _again;
	tr72: cs = 56; goto _again;
	tr80: cs = 57; goto _again;
	tr69: cs = 58; goto _again;
	tr81: cs = 59; goto _again;
	tr47: cs = 60; goto f1;
	tr85: cs = 61; goto _again;
	tr82: cs = 61; goto f6;
	tr90: cs = 61; goto f9;
	tr86: cs = 62; goto f2;
	tr83: cs = 62; goto f7;
	tr91: cs = 62; goto f10;
	tr87: cs = 63; goto _again;
	tr84: cs = 63; goto f6;
	tr92: cs = 63; goto f9;
	tr89: cs = 64; goto _again;
	tr49: cs = 65; goto _again;
	tr93: cs = 66; goto _again;
	tr94: cs = 67; goto _again;
	tr95: cs = 68; goto _again;
	tr96: cs = 69; goto _again;
	tr5: cs = 70; goto _again;
	tr97: cs = 71; goto _again;
	tr98: cs = 72; goto _again;
	tr99: cs = 73; goto _again;
	tr100: cs = 74; goto _again;
	tr12: cs = 75; goto _again;
	tr9: cs = 75; goto f3;
	tr103: cs = 76; goto _again;
	tr101: cs = 76; goto f13;
	tr104: cs = 76; goto f14;
	tr105: cs = 76; goto f15;
	tr106: cs = 76; goto f16;
	tr20: cs = 77; goto f5;
	tr58: cs = 78; goto f11;
	tr67: cs = 78; goto f12;
	tr48: cs = 79; goto _again;

f6:
#line 5 "src/ragel/smtp_addr_parser.rl"
	{
    addr->user = p;
  }
	goto _again;
f2:
#line 9 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->user) {
      addr->user_len = p - addr->user;
    }
  }
	goto _again;
f3:
#line 15 "src/ragel/smtp_addr_parser.rl"
	{
    addr->domain = p;
  }
	goto _again;
f4:
#line 25 "src/ragel/smtp_addr_parser.rl"
	{
    addr->domain = p;
    addr->flags |= RSPAMD_EMAIL_ADDR_IP;
  }
	goto _again;
f5:
#line 30 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
	goto _again;
f9:
#line 36 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_HAS_BACKSLASH;
  }
	goto _again;
f8:
#line 40 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_QUOTED;
  }
	goto _again;
f1:
#line 59 "src/ragel/smtp_addr_parser.rl"
	{
    addr->addr = p;
  }
	goto _again;
f12:
#line 63 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
	goto _again;
f7:
#line 5 "src/ragel/smtp_addr_parser.rl"
	{
    addr->user = p;
  }
#line 9 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->user) {
      addr->user_len = p - addr->user;
    }
  }
	goto _again;
f11:
#line 19 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
#line 63 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
	goto _again;
f10:
#line 36 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_HAS_BACKSLASH;
  }
#line 9 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->user) {
      addr->user_len = p - addr->user;
    }
  }
	goto _again;
f16:
#line 44 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_EMPTY;
    addr->addr = "";
    addr->user = addr->addr;
    addr->domain = addr->addr;
  }
#line 51 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	goto _again;
f15:
#line 55 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_BRACED;
  }
#line 51 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	goto _again;
f0:
#line 59 "src/ragel/smtp_addr_parser.rl"
	{
    addr->addr = p;
  }
#line 5 "src/ragel/smtp_addr_parser.rl"
	{
    addr->user = p;
  }
	goto _again;
f14:
#line 63 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
#line 51 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	goto _again;
f13:
#line 19 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
#line 63 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
#line 51 "src/ragel/smtp_addr_parser.rl"
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
	case 17:
#line 44 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_EMPTY;
    addr->addr = "";
    addr->user = addr->addr;
    addr->domain = addr->addr;
  }
#line 51 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	break;
	case 16:
#line 55 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_BRACED;
  }
#line 51 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	break;
	case 15:
#line 63 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
#line 51 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	break;
	case 14:
#line 19 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->domain) {
      addr->domain_len = p - addr->domain;
    }
  }
#line 63 "src/ragel/smtp_addr_parser.rl"
	{
    if (addr->addr) {
      addr->addr_len = p - addr->addr;
    }
  }
#line 51 "src/ragel/smtp_addr_parser.rl"
	{
    addr->flags |= RSPAMD_EMAIL_ADDR_VALID;
  }
	break;
#line 1201 "src/libmime/parsers/smtp_addr_parser.c"
	}
	}

	_out: {}
	}

#line 90 "src/ragel/smtp_addr_parser.rl"

  return cs;
}
