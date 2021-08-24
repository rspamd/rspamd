#include <algorithm>
#include <string>
#include <cstring>
#include <cctype>
#include <clocale>

#include "unicode/utf8.h"
#include "conversion.hxx"

#ifdef _WIN32
#define strdup _strdup
#endif

using namespace std;

namespace replxx {

namespace locale {

void to_lower( std::string& s_ ) {
	transform( s_.begin(), s_.end(), s_.begin(), static_cast<int(*)(int)>( &tolower ) );
}

bool is_8bit_encoding( void ) {
	bool is8BitEncoding( false );
	string origLC( setlocale( LC_CTYPE, nullptr ) );
	string lc( origLC );
	to_lower( lc );
	if ( lc == "c" ) {
		setlocale( LC_CTYPE, "" );
	}
	lc = setlocale( LC_CTYPE, nullptr );
	setlocale( LC_CTYPE, origLC.c_str() );
	to_lower( lc );
	if ( lc.find( "8859" ) != std::string::npos ) {
		is8BitEncoding = true;
	}
	return ( is8BitEncoding );
}

bool is8BitEncoding( is_8bit_encoding() );

}

ConversionResult copyString8to32(char32_t* dst, int dstSize, int& dstCount, const char* src) {
	ConversionResult res = ConversionResult::conversionOK;
	if ( ! locale::is8BitEncoding ) {
		auto sourceStart = reinterpret_cast<const unsigned char*>(src);
		auto slen = strlen(src);
		auto targetStart = reinterpret_cast<UChar32*>(dst);
		int i = 0, j = 0;

		while (i < slen && j < dstSize) {
			UChar32 uc;
			auto prev_i = i;
			U8_NEXT (sourceStart, i, slen, uc);

			if (uc <= 0) {
				if (U8_IS_LEAD (sourceStart[prev_i])) {
					auto lead_byte = sourceStart[prev_i];
					auto trailing_bytes = (((uint8_t)(lead_byte)>=0xc2)+
										   ((uint8_t)(lead_byte)>=0xe0)+
										   ((uint8_t)(lead_byte)>=0xf0));

					if (trailing_bytes + i > slen) {
						return ConversionResult::sourceExhausted;
					}
				}

				/* Replace with 0xFFFD */
				uc = 0x0000FFFD;
			}
			targetStart[j++] = uc;
		}

		dstCount = j;

		if (j < dstSize) {
			targetStart[j] = 0;
		}
	} else {
		for ( dstCount = 0; ( dstCount < dstSize ) && src[dstCount]; ++ dstCount ) {
			dst[dstCount] = src[dstCount];
		}
	}
	return res;
}

ConversionResult copyString8to32(char32_t* dst, int dstSize, int& dstCount, const char8_t* src) {
	return copyString8to32(
			dst, dstSize, dstCount, reinterpret_cast<const char*>(src)
	);
}

int copyString32to8(
		char* dst, int dstSize, const char32_t* src, int srcSize
) {
	int resCount = 0;

	if ( ! locale::is8BitEncoding ) {
		int j = 0;
		UBool is_error = 0;

		for (auto i = 0; i < srcSize; i ++) {
			U8_APPEND ((uint8_t *)dst, j, dstSize, src[i], is_error);

			if (is_error) {
				break;
			}
		}

		if (!is_error) {
			resCount = j;

			if (j < dstSize) {
				dst[j] = '\0';
			}
		}
	} else {
		int i( 0 );
		for ( i = 0; ( i < dstSize ) && ( i < srcSize ) && src[i]; ++ i ) {
			dst[i] = static_cast<char>( src[i] );
		}
		resCount = i;
		if ( i < dstSize ) {
			dst[i] = 0;
		}
	}

	return resCount;
}

}

