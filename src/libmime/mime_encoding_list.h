/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SRC_LIBMIME_MIME_ENCODING_LIST_H_
#define SRC_LIBMIME_MIME_ENCODING_LIST_H_

static const struct rspamd_charset_substitution sub[] = {
		{
			.input = "iso-646-us",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "ansi_x3.4-1968",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "iso-ir-6",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "iso_646.irv:1991",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "ascii",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "iso646-us",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "us",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "ibm367",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "cp367",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "csascii",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "ascii7",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "default",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "646",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "iso_646.irv:1983",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "iso969-us",
			.canon = "ansi_x3.4-1986",
			.flags = RSPAMD_CHARSET_FLAG_ASCII,
		},
		{
			.input = "tw-big5",
			.canon = "big5",
			.flags = 0,
		},
		{
			.input = "csbig5",
			.canon = "big5",
			.flags = 0,
		},
		{
			.input = "hkscs-big5",
			.canon = "big5-hkscs",
			.flags = 0,
		},
		{
			.input = "big5hk",
			.canon = "big5-hkscs",
			.flags = 0,
		},
		{
			.input = "big5-hkscs:unicode",
			.canon = "big5-hkscs",
			.flags = 0,
		},
		{
			.input = "extended_unix_code_packed_format_for_japanese",
			.canon = "euc-jp",
			.flags = 0,
		},
		{
			.input = "cseucpkdfmtjapanese",
			.canon = "euc-jp",
			.flags = 0,
		},
		{
			.input = "x-eucjp",
			.canon = "euc-jp",
			.flags = 0,
		},
		{
			.input = "x-euc-jp",
			.canon = "euc-jp",
			.flags = 0,
		},
		{
			.input = "unicode-1-1-utf-8",
			.canon = "utf-8",
			.flags = RSPAMD_CHARSET_FLAG_UTF,
		},
		{
			.input = "cseuckr",
			.canon = "euc-kr",
			.flags = 0,
		},
		{
			.input = "5601",
			.canon = "euc-kr",
			.flags = 0,
		},
		{
			.input = "ksc-5601",
			.canon = "euc-kr",
			.flags = 0,
		},
		{
			.input = "ksc-5601-1987",
			.canon = "euc-kr",
			.flags = 0,
		},
		{
			.input = "ksc-5601_1987",
			.canon = "euc-kr",
			.flags = 0,
		},
		{
			.input = "ksc5601",
			.canon = "euc-kr",
			.flags = 0,
		},
		{
			.input = "cns11643",
			.canon = "euc-tw",
			.flags = 0,
		},
		{
			.input = "ibm-euctw",
			.canon = "euc-tw",
			.flags = 0,
		},
		{
			.input = "gb-18030",
			.canon = "gb18030",
			.flags = 0,
		},
		{
			.input = "ibm1392",
			.canon = "gb18030",
			.flags = 0,
		},
		{
			.input = "ibm-1392",
			.canon = "gb18030",
			.flags = 0,
		},
		{
			.input = "gb18030-2000",
			.canon = "gb18030",
			.flags = 0,
		},
		{
			.input = "gb-2312",
			.canon = "gb2312",
			.flags = 0,
		},
		{
			.input = "csgb2312",
			.canon = "gb2312",
			.flags = 0,
		},
		{
			.input = "euc_cn",
			.canon = "gb2312",
			.flags = 0,
		},
		{
			.input = "euccn",
			.canon = "gb2312",
			.flags = 0,
		},
		{
			.input = "euc-cn",
			.canon = "gb2312",
			.flags = 0,
		},
		{
			.input = "gb-k",
			.canon = "gbk",
			.flags = 0,
		},
		{
			.input = "iso_8859-1:1987",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "iso-ir-100",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "iso_8859-1",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "latin1",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "l1",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "ibm819",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "cp819",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "csisolatin1",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "819",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "cp819",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "iso8859-1",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "8859-1",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "iso8859_1",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "iso_8859_1",
			.canon = "iso-8859-1",
			.flags = 0,
		},
		{
			.input = "iso_8859-2:1987",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "iso-ir-101",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "iso_8859-2",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "latin2",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "l2",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "csisolatin2",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "912",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "cp912",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "ibm-912",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "ibm912",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "iso8859-2",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "8859-2",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "iso8859_2",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "iso_8859_2",
			.canon = "iso-8859-2",
			.flags = 0,
		},
		{
			.input = "iso_8859-3:1988",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "iso-ir-109",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "iso_8859-3",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "latin3",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "l3",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "csisolatin3",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "913",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "cp913",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "ibm-913",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "ibm913",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "iso8859-3",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "8859-3",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "iso8859_3",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "iso_8859_3",
			.canon = "iso-8859-3",
			.flags = 0,
		},
		{
			.input = "iso_8859-4:1988",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "iso-ir-110",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "iso_8859-4",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "latin4",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "l4",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "csisolatin4",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "914",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "cp914",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "ibm-914",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "ibm914",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "iso8859-4",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "8859-4",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "iso8859_4",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "iso_8859_4",
			.canon = "iso-8859-4",
			.flags = 0,
		},
		{
			.input = "iso_8859-5:1988",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "iso-ir-144",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "iso_8859-5",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "cyrillic",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "csisolatincyrillic",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "915",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "cp915",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "ibm-915",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "ibm915",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "iso8859-5",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "8859-5",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "iso8859_5",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "iso_8859_5",
			.canon = "iso-8859-5",
			.flags = 0,
		},
		{
			.input = "iso_8859-6:1987",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "iso-ir-127",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "iso_8859-6",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "ecma-114",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "asmo-708",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "arabic",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "csisolatinarabic",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "1089",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "cp1089",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "ibm-1089",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "ibm1089",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "iso8859-6",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "8859-6",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "iso8859_6",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "iso_8859_6",
			.canon = "iso-8859-6",
			.flags = 0,
		},
		{
			.input = "iso_8859-7:1987",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "iso-ir-126",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "iso_8859-7",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "elot_928",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "ecma-118",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "greek",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "greek8",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "csisolatingreek",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "813",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "cp813",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "ibm-813",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "ibm813",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "iso8859-7",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "8859-7",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "iso8859_7",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "iso_8859_7",
			.canon = "iso-8859-7",
			.flags = 0,
		},
		{
			.input = "iso_8859-8:1988",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "iso-ir-138",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "iso_8859-8",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "hebrew",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "csisolatinhebrew",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "916",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "cp916",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "ibm-916",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "ibm916",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "iso8859-8",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "8859-8",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "iso8859_8",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "iso_8859_8",
			.canon = "iso-8859-8",
			.flags = 0,
		},
		{
			.input = "iso_8859-9:1989",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "iso-ir-148",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "iso_8859-9",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "latin5",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "l5",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "csisolatin5",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "920",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "cp920",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "ibm-920",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "ibm920",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "iso8859-9",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "8859-9",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "iso8859_9",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "iso_8859_9",
			.canon = "iso-8859-9",
			.flags = 0,
		},
		{
			.input = "iso_8859-13",
			.canon = "iso-8859-13",
			.flags = 0,
		},
		{
			.input = "iso8859-13",
			.canon = "iso-8859-13",
			.flags = 0,
		},
		{
			.input = "8859-13",
			.canon = "iso-8859-13",
			.flags = 0,
		},
		{
			.input = "iso8859_13",
			.canon = "iso-8859-13",
			.flags = 0,
		},
		{
			.input = "iso_8859_13",
			.canon = "iso-8859-13",
			.flags = 0,
		},
		{
			.input = "iso-ir-199",
			.canon = "iso-8859-14",
			.flags = 0,
		},
		{
			.input = "iso_8859-14:1998",
			.canon = "iso-8859-14",
			.flags = 0,
		},
		{
			.input = "iso_8859-14",
			.canon = "iso-8859-14",
			.flags = 0,
		},
		{
			.input = "latin8",
			.canon = "iso-8859-14",
			.flags = 0,
		},
		{
			.input = "iso-celtic",
			.canon = "iso-8859-14",
			.flags = 0,
		},
		{
			.input = "l8",
			.canon = "iso-8859-14",
			.flags = 0,
		},
		{
			.input = "csisolatin9",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "csisolatin0",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "latin9",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "latin0",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "923",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "cp923",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "ibm-923",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "ibm923",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "iso8859-15",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "iso_8859-15",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "8859-15",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "iso_8859-15_fdis",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "l9",
			.canon = "iso-8859-15",
			.flags = 0,
		},
		{
			.input = "koi-8-r",
			.canon = "koi8-r",
			.flags = 0,
		},
		{
			.input = "cskoi8r",
			.canon = "koi8-r",
			.flags = 0,
		},
		{
			.input = "koi8",
			.canon = "koi8-r",
			.flags = 0,
		},
		{
			.input = "koi-8-u",
			.canon = "koi8-u",
			.flags = 0,
		},
		{
			.input = "koi-8-t",
			.canon = "koi8-t",
			.flags = 0,
		},
		{
			.input = "shiftjis",
			.canon = "shift_jis",
			.flags = 0,
		},
		{
			.input = "ms_kanji",
			.canon = "shift_jis",
			.flags = 0,
		},
		{
			.input = "csshiftjis",
			.canon = "shift_jis",
			.flags = 0,
		},
		{
			.input = "cp-437",
			.canon = "ibm437",
			.flags = 0,
		},
		{
			.input = "cp437",
			.canon = "ibm437",
			.flags = 0,
		},
		{
			.input = "437",
			.canon = "ibm437",
			.flags = 0,
		},
		{
			.input = "cspc8codepage437437",
			.canon = "ibm437",
			.flags = 0,
		},
		{
			.input = "cspc8codepage437",
			.canon = "ibm437",
			.flags = 0,
		},
		{
			.input = "ibm-437",
			.canon = "ibm437",
			.flags = 0,
		},
		{
			.input = "cp-850",
			.canon = "ibm850",
			.flags = 0,
		},
		{
			.input = "cp850",
			.canon = "ibm850",
			.flags = 0,
		},
		{
			.input = "850",
			.canon = "ibm850",
			.flags = 0,
		},
		{
			.input = "cspc850multilingual850",
			.canon = "ibm850",
			.flags = 0,
		},
		{
			.input = "cspc850multilingual",
			.canon = "ibm850",
			.flags = 0,
		},
		{
			.input = "ibm-850",
			.canon = "ibm850",
			.flags = 0,
		},
		{
			.input = "cp-851",
			.canon = "ibm851",
			.flags = 0,
		},
		{
			.input = "cp851",
			.canon = "ibm851",
			.flags = 0,
		},
		{
			.input = "851",
			.canon = "ibm851",
			.flags = 0,
		},
		{
			.input = "csibm851",
			.canon = "ibm851",
			.flags = 0,
		},
		{
			.input = "cp-852",
			.canon = "ibm852",
			.flags = 0,
		},
		{
			.input = "cp852",
			.canon = "ibm852",
			.flags = 0,
		},
		{
			.input = "852",
			.canon = "ibm852",
			.flags = 0,
		},
		{
			.input = "cspcp852",
			.canon = "ibm852",
			.flags = 0,
		},
		{
			.input = "852",
			.canon = "ibm852",
			.flags = 0,
		},
		{
			.input = "cspcp852",
			.canon = "ibm852",
			.flags = 0,
		},
		{
			.input = "ibm-852",
			.canon = "ibm852",
			.flags = 0,
		},
		{
			.input = "cp-855",
			.canon = "ibm855",
			.flags = 0,
		},
		{
			.input = "cp855",
			.canon = "ibm855",
			.flags = 0,
		},
		{
			.input = "855",
			.canon = "ibm855",
			.flags = 0,
		},
		{
			.input = "csibm855",
			.canon = "ibm855",
			.flags = 0,
		},
		{
			.input = "cspcp855",
			.canon = "ibm855",
			.flags = 0,
		},
		{
			.input = "ibm-855",
			.canon = "ibm855",
			.flags = 0,
		},
		{
			.input = "cp-857",
			.canon = "ibm857",
			.flags = 0,
		},
		{
			.input = "cp857",
			.canon = "ibm857",
			.flags = 0,
		},
		{
			.input = "857",
			.canon = "ibm857",
			.flags = 0,
		},
		{
			.input = "csibm857",
			.canon = "ibm857",
			.flags = 0,
		},
		{
			.input = "857",
			.canon = "ibm857",
			.flags = 0,
		},
		{
			.input = "csibm857",
			.canon = "ibm857",
			.flags = 0,
		},
		{
			.input = "ibm-857",
			.canon = "ibm857",
			.flags = 0,
		},
		{
			.input = "cp-860",
			.canon = "ibm860",
			.flags = 0,
		},
		{
			.input = "cp860",
			.canon = "ibm860",
			.flags = 0,
		},
		{
			.input = "860",
			.canon = "ibm860",
			.flags = 0,
		},
		{
			.input = "csibm860",
			.canon = "ibm860",
			.flags = 0,
		},
		{
			.input = "860",
			.canon = "ibm860",
			.flags = 0,
		},
		{
			.input = "csibm860",
			.canon = "ibm860",
			.flags = 0,
		},
		{
			.input = "ibm-860",
			.canon = "ibm860",
			.flags = 0,
		},
		{
			.input = "cp-861",
			.canon = "ibm861",
			.flags = 0,
		},
		{
			.input = "cp861",
			.canon = "ibm861",
			.flags = 0,
		},
		{
			.input = "861",
			.canon = "ibm861",
			.flags = 0,
		},
		{
			.input = "cp-is",
			.canon = "ibm861",
			.flags = 0,
		},
		{
			.input = "csibm861",
			.canon = "ibm861",
			.flags = 0,
		},
		{
			.input = "861",
			.canon = "ibm861",
			.flags = 0,
		},
		{
			.input = "cp-is",
			.canon = "ibm861",
			.flags = 0,
		},
		{
			.input = "csibm861",
			.canon = "ibm861",
			.flags = 0,
		},
		{
			.input = "ibm-861",
			.canon = "ibm861",
			.flags = 0,
		},
		{
			.input = "cp-862",
			.canon = "ibm862",
			.flags = 0,
		},
		{
			.input = "cp862",
			.canon = "ibm862",
			.flags = 0,
		},
		{
			.input = "862",
			.canon = "ibm862",
			.flags = 0,
		},
		{
			.input = "cspc862latinhebrew862",
			.canon = "ibm862",
			.flags = 0,
		},
		{
			.input = "cspc862latinhebrew",
			.canon = "ibm862",
			.flags = 0,
		},
		{
			.input = "ibm-862",
			.canon = "ibm862",
			.flags = 0,
		},
		{
			.input = "cp-863",
			.canon = "ibm863",
			.flags = 0,
		},
		{
			.input = "cp863",
			.canon = "ibm863",
			.flags = 0,
		},
		{
			.input = "863",
			.canon = "ibm863",
			.flags = 0,
		},
		{
			.input = "csibm863",
			.canon = "ibm863",
			.flags = 0,
		},
		{
			.input = "863",
			.canon = "ibm863",
			.flags = 0,
		},
		{
			.input = "csibm863",
			.canon = "ibm863",
			.flags = 0,
		},
		{
			.input = "ibm-863",
			.canon = "ibm863",
			.flags = 0,
		},
		{
			.input = "cp-864",
			.canon = "ibm864",
			.flags = 0,
		},
		{
			.input = "cp864",
			.canon = "ibm864",
			.flags = 0,
		},
		{
			.input = "csibm864",
			.canon = "ibm864",
			.flags = 0,
		},
		{
			.input = "csibm864",
			.canon = "ibm864",
			.flags = 0,
		},
		{
			.input = "ibm-864",
			.canon = "ibm864",
			.flags = 0,
		},
		{
			.input = "cp-865",
			.canon = "ibm865",
			.flags = 0,
		},
		{
			.input = "cp865",
			.canon = "ibm865",
			.flags = 0,
		},
		{
			.input = "865",
			.canon = "ibm865",
			.flags = 0,
		},
		{
			.input = "csibm865",
			.canon = "ibm865",
			.flags = 0,
		},
		{
			.input = "865",
			.canon = "ibm865",
			.flags = 0,
		},
		{
			.input = "csibm865",
			.canon = "ibm865",
			.flags = 0,
		},
		{
			.input = "ibm-865",
			.canon = "ibm865",
			.flags = 0,
		},
		{
			.input = "cp-866",
			.canon = "ibm866",
			.flags = 0,
		},
		{
			.input = "cp866",
			.canon = "ibm866",
			.flags = 0,
		},
		{
			.input = "866",
			.canon = "ibm866",
			.flags = 0,
		},
		{
			.input = "csibm866",
			.canon = "ibm866",
			.flags = 0,
		},
		{
			.input = "866",
			.canon = "ibm866",
			.flags = 0,
		},
		{
			.input = "csibm866",
			.canon = "ibm866",
			.flags = 0,
		},
		{
			.input = "ibm-866",
			.canon = "ibm866",
			.flags = 0,
		},
		{
			.input = "cp-868",
			.canon = "ibm868",
			.flags = 0,
		},
		{
			.input = "cp868",
			.canon = "ibm868",
			.flags = 0,
		},
		{
			.input = "cp-ar",
			.canon = "ibm868",
			.flags = 0,
		},
		{
			.input = "csibm868",
			.canon = "ibm868",
			.flags = 0,
		},
		{
			.input = "ibm-868",
			.canon = "ibm868",
			.flags = 0,
		},
		{
			.input = "cp-869",
			.canon = "ibm869",
			.flags = 0,
		},
		{
			.input = "cp869",
			.canon = "ibm869",
			.flags = 0,
		},
		{
			.input = "869",
			.canon = "ibm869",
			.flags = 0,
		},
		{
			.input = "cp-gr",
			.canon = "ibm869",
			.flags = 0,
		},
		{
			.input = "csibm869",
			.canon = "ibm869",
			.flags = 0,
		},
		{
			.input = "cp-891",
			.canon = "ibm891",
			.flags = 0,
		},
		{
			.input = "cp891",
			.canon = "ibm891",
			.flags = 0,
		},
		{
			.input = "csibm891",
			.canon = "ibm891",
			.flags = 0,
		},
		{
			.input = "cp-903",
			.canon = "ibm903",
			.flags = 0,
		},
		{
			.input = "cp903",
			.canon = "ibm903",
			.flags = 0,
		},
		{
			.input = "csibm903",
			.canon = "ibm903",
			.flags = 0,
		},
		{
			.input = "cp-904",
			.canon = "ibm904",
			.flags = 0,
		},
		{
			.input = "cp904",
			.canon = "ibm904",
			.flags = 0,
		},
		{
			.input = "904",
			.canon = "ibm904",
			.flags = 0,
		},
		{
			.input = "csibm904",
			.canon = "ibm904",
			.flags = 0,
		},
		{
			.input = "cp-1251",
			.canon = "cp1251",
			.flags = 0,
		},
		{
			.input = "windows-1251",
			.canon = "cp1251",
			.flags = 0,
		},
		{
			.input = "cp-1255",
			.canon = "cp1255",
			.flags = 0,
		},
		{
			.input = "windows-1255",
			.canon = "cp1255",
			.flags = 0,
		},
		{
			.input = "tis620.2533",
			.canon = "tis-620",
			.flags = 0,
		},
};

#endif /* SRC_LIBMIME_MIME_ENCODING_LIST_H_ */
