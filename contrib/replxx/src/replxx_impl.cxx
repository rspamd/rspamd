#include <algorithm>
#include <memory>
#include <cerrno>
#include <iostream>

#ifdef _WIN32

#include <windows.h>
#include <io.h>
#if _MSC_VER < 1900
#define snprintf _snprintf // Microsoft headers use underscores in some names
#endif
#define strcasecmp _stricmp
#define write _write
#define STDIN_FILENO 0

#else /* _WIN32 */

#include <unistd.h>
#include <signal.h>

#endif /* _WIN32 */

#ifdef _WIN32
#include "windows.hxx"
#endif

#include "replxx_impl.hxx"
#include "utf8string.hxx"
#include "prompt.hxx"
#include "util.hxx"
#include "io.hxx"
#include "history.hxx"
#include "replxx.hxx"

using namespace std;

namespace replxx {

#ifndef _WIN32

bool gotResize = false;

#endif

namespace {

static int const REPLXX_MAX_HINT_ROWS( 4 );
/*
 * All whitespaces and all non-alphanumerical characters from ASCII range
 * with an exception of an underscore ('_').
 */
char const defaultBreakChars[] = " \t\v\f\a\b\r\n`~!@#$%^&*()-=+[{]}\\|;:'\",<.>/?";

#ifndef _WIN32

static void WindowSizeChanged(int) {
	// do nothing here but setting this flag
	gotResize = true;
}

#endif

static const char* unsupported_term[] = {"dumb", "cons25", "emacs", NULL};

static bool isUnsupportedTerm(void) {
	char* term = getenv("TERM");
	if (term == NULL) {
		return false;
	}
	for (int j = 0; unsupported_term[j]; ++j) {
		if (!strcasecmp(term, unsupported_term[j])) {
			return true;
		}
	}
	return false;
}

}

Replxx::ReplxxImpl::ReplxxImpl( FILE*, FILE*, FILE* )
	: _utf8Buffer()
	, _data()
	, _charWidths()
	, _display()
	, _displayInputLength( 0 )
	, _hint()
	, _pos( 0 )
	, _prefix( 0 )
	, _hintSelection( -1 )
	, _history()
	, _killRing()
	, _maxHintRows( REPLXX_MAX_HINT_ROWS )
	, _hintDelay( 0 )
	, _breakChars( defaultBreakChars )
	, _completionCountCutoff( 100 )
	, _overwrite( false )
	, _doubleTabCompletion( false )
	, _completeOnEmpty( true )
	, _beepOnAmbiguousCompletion( false )
	, _noColor( false )
	, _keyPressHandlers()
	, _terminal()
	, _currentThread()
	, _prompt( _terminal )
	, _completionCallback( nullptr )
	, _highlighterCallback( nullptr )
	, _hintCallback( nullptr )
	, _keyPresses()
	, _messages()
	, _completions()
	, _completionContextLength( 0 )
	, _completionSelection( -1 )
	, _preloadedBuffer()
	, _errorMessage()
	, _modifiedState( false )
	, _mutex() {
	using namespace std::placeholders;
	bind_key( Replxx::KEY::control( 'A' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_TO_BEGINING_OF_LINE, _1 ) );
	bind_key( Replxx::KEY::HOME + 0,                       std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_TO_BEGINING_OF_LINE, _1 ) );
	bind_key( Replxx::KEY::control( 'E' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_TO_END_OF_LINE,      _1 ) );
	bind_key( Replxx::KEY::END + 0,                        std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_TO_END_OF_LINE,      _1 ) );
	bind_key( Replxx::KEY::control( 'B' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_LEFT,                _1 ) );
	bind_key( Replxx::KEY::LEFT + 0,                       std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_LEFT,                _1 ) );
	bind_key( Replxx::KEY::control( 'F' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_RIGHT,               _1 ) );
	bind_key( Replxx::KEY::RIGHT + 0,                      std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_RIGHT,               _1 ) );
	bind_key( Replxx::KEY::meta( 'b' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_ONE_WORD_LEFT,       _1 ) );
	bind_key( Replxx::KEY::meta( 'B' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_ONE_WORD_LEFT,       _1 ) );
	bind_key( Replxx::KEY::control( Replxx::KEY::LEFT ),   std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_ONE_WORD_LEFT,       _1 ) );
	bind_key( Replxx::KEY::meta( Replxx::KEY::LEFT ),      std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_ONE_WORD_LEFT,       _1 ) ); // Emacs allows Meta, readline don't
	bind_key( Replxx::KEY::meta( 'f' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_ONE_WORD_RIGHT,      _1 ) );
	bind_key( Replxx::KEY::meta( 'F' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_ONE_WORD_RIGHT,      _1 ) );
	bind_key( Replxx::KEY::control( Replxx::KEY::RIGHT ),  std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_ONE_WORD_RIGHT,      _1 ) );
	bind_key( Replxx::KEY::meta( Replxx::KEY::RIGHT ),     std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::MOVE_CURSOR_ONE_WORD_RIGHT,      _1 ) ); // Emacs allows Meta, readline don't
	bind_key( Replxx::KEY::meta( Replxx::KEY::BACKSPACE ), std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::KILL_TO_WHITESPACE_ON_LEFT,      _1 ) );
	bind_key( Replxx::KEY::meta( 'd' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::KILL_TO_END_OF_WORD,             _1 ) );
	bind_key( Replxx::KEY::meta( 'D' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::KILL_TO_END_OF_WORD,             _1 ) );
	bind_key( Replxx::KEY::control( 'W' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::KILL_TO_BEGINING_OF_WORD,        _1 ) );
	bind_key( Replxx::KEY::control( 'U' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::KILL_TO_BEGINING_OF_LINE,        _1 ) );
	bind_key( Replxx::KEY::control( 'K' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::KILL_TO_END_OF_LINE,             _1 ) );
	bind_key( Replxx::KEY::control( 'Y' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::YANK,                            _1 ) );
	bind_key( Replxx::KEY::meta( 'y' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::YANK_CYCLE,                      _1 ) );
	bind_key( Replxx::KEY::meta( 'Y' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::YANK_CYCLE,                      _1 ) );
	bind_key( Replxx::KEY::meta( 'c' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::CAPITALIZE_WORD,                 _1 ) );
	bind_key( Replxx::KEY::meta( 'C' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::CAPITALIZE_WORD,                 _1 ) );
	bind_key( Replxx::KEY::meta( 'l' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::LOWERCASE_WORD,                  _1 ) );
	bind_key( Replxx::KEY::meta( 'L' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::LOWERCASE_WORD,                  _1 ) );
	bind_key( Replxx::KEY::meta( 'u' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::UPPERCASE_WORD,                  _1 ) );
	bind_key( Replxx::KEY::meta( 'U' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::UPPERCASE_WORD,                  _1 ) );
	bind_key( Replxx::KEY::control( 'T' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::TRANSPOSE_CHARACTERS,            _1 ) );
	bind_key( Replxx::KEY::control( 'C' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::ABORT_LINE,                      _1 ) );
	bind_key( Replxx::KEY::control( 'D' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::SEND_EOF,                        _1 ) );
	bind_key( Replxx::KEY::INSERT + 0,                     std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::TOGGLE_OVERWRITE_MODE,           _1 ) );
	bind_key( 127,                                         std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::DELETE_CHARACTER_UNDER_CURSOR,   _1 ) );
	bind_key( Replxx::KEY::DELETE + 0,                     std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::DELETE_CHARACTER_UNDER_CURSOR,   _1 ) );
	bind_key( Replxx::KEY::BACKSPACE + 0,                  std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::DELETE_CHARACTER_LEFT_OF_CURSOR, _1 ) );
	bind_key( Replxx::KEY::control( 'J' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::COMMIT_LINE,                     _1 ) );
	bind_key( Replxx::KEY::ENTER + 0,                      std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::COMMIT_LINE,                     _1 ) );
	bind_key( Replxx::KEY::control( 'L' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::CLEAR_SCREEN,                    _1 ) );
	bind_key( Replxx::KEY::control( 'N' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::COMPLETE_NEXT,                   _1 ) );
	bind_key( Replxx::KEY::control( 'P' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::COMPLETE_PREVIOUS,               _1 ) );
	bind_key( Replxx::KEY::DOWN + 0,                       std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_NEXT,                    _1 ) );
	bind_key( Replxx::KEY::UP + 0,                         std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_PREVIOUS,                _1 ) );
	bind_key( Replxx::KEY::meta( '>' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_LAST,                    _1 ) );
	bind_key( Replxx::KEY::meta( '<' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_FIRST,                   _1 ) );
	bind_key( Replxx::KEY::PAGE_DOWN + 0,                  std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_LAST,                    _1 ) );
	bind_key( Replxx::KEY::PAGE_UP + 0,                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_FIRST,                   _1 ) );
	bind_key( Replxx::KEY::control( Replxx::KEY::UP ),     std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HINT_PREVIOUS,                   _1 ) );
	bind_key( Replxx::KEY::control( Replxx::KEY::DOWN ),   std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HINT_NEXT,                       _1 ) );
#ifndef _WIN32
	bind_key( Replxx::KEY::control( 'V' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::VERBATIM_INSERT,                 _1 ) );
	bind_key( Replxx::KEY::control( 'Z' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::SUSPEND,                         _1 ) );
#endif
	bind_key( Replxx::KEY::TAB + 0,                        std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::COMPLETE_LINE,                   _1 ) );
	bind_key( Replxx::KEY::control( 'R' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_INCREMENTAL_SEARCH,      _1 ) );
	bind_key( Replxx::KEY::control( 'S' ),                 std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_INCREMENTAL_SEARCH,      _1 ) );
	bind_key( Replxx::KEY::meta( 'p' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_COMMON_PREFIX_SEARCH,    _1 ) );
	bind_key( Replxx::KEY::meta( 'P' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_COMMON_PREFIX_SEARCH,    _1 ) );
	bind_key( Replxx::KEY::meta( 'n' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_COMMON_PREFIX_SEARCH,    _1 ) );
	bind_key( Replxx::KEY::meta( 'N' ),                    std::bind( &ReplxxImpl::invoke, this, Replxx::ACTION::HISTORY_COMMON_PREFIX_SEARCH,    _1 ) );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::invoke( Replxx::ACTION action_, char32_t code ) {
	switch ( action_ ) {
		case ( Replxx::ACTION::INSERT_CHARACTER ):                return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::insert_character, code ) );
		case ( Replxx::ACTION::DELETE_CHARACTER_UNDER_CURSOR ):   return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::delete_character, code ) );
		case ( Replxx::ACTION::DELETE_CHARACTER_LEFT_OF_CURSOR ): return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::backspace_character, code ) );
		case ( Replxx::ACTION::KILL_TO_END_OF_LINE ):             return ( action( WANT_REFRESH | SET_KILL_ACTION, &Replxx::ReplxxImpl::kill_to_end_of_line, code ) );
		case ( Replxx::ACTION::KILL_TO_BEGINING_OF_LINE ):        return ( action( SET_KILL_ACTION, &Replxx::ReplxxImpl::kill_to_begining_of_line, code ) );
		case ( Replxx::ACTION::KILL_TO_END_OF_WORD ):             return ( action( SET_KILL_ACTION, &Replxx::ReplxxImpl::kill_word_to_right, code ) );
		case ( Replxx::ACTION::KILL_TO_BEGINING_OF_WORD ):        return ( action( SET_KILL_ACTION, &Replxx::ReplxxImpl::kill_word_to_left, code ) );
		case ( Replxx::ACTION::KILL_TO_WHITESPACE_ON_LEFT ):      return ( action( SET_KILL_ACTION, &Replxx::ReplxxImpl::kill_to_whitespace_to_left, code ) );
		case ( Replxx::ACTION::YANK ):                            return ( action( NOOP, &Replxx::ReplxxImpl::yank, code ) );
		case ( Replxx::ACTION::YANK_CYCLE ):                      return ( action( NOOP, &Replxx::ReplxxImpl::yank_cycle, code ) );
		case ( Replxx::ACTION::MOVE_CURSOR_TO_BEGINING_OF_LINE ): return ( action( WANT_REFRESH, &Replxx::ReplxxImpl::go_to_begining_of_line, code ) );
		case ( Replxx::ACTION::MOVE_CURSOR_TO_END_OF_LINE ):      return ( action( WANT_REFRESH, &Replxx::ReplxxImpl::go_to_end_of_line, code ) );
		case ( Replxx::ACTION::MOVE_CURSOR_ONE_WORD_LEFT ):       return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::move_one_word_left, code ) );
		case ( Replxx::ACTION::MOVE_CURSOR_ONE_WORD_RIGHT ):      return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::move_one_word_right, code ) );
		case ( Replxx::ACTION::MOVE_CURSOR_LEFT ):                return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::move_one_char_left, code ) );
		case ( Replxx::ACTION::MOVE_CURSOR_RIGHT ):               return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::move_one_char_right, code ) );
		case ( Replxx::ACTION::HISTORY_NEXT ):                    return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::history_next, code ) );
		case ( Replxx::ACTION::HISTORY_PREVIOUS ):                return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::history_previous, code ) );
		case ( Replxx::ACTION::HISTORY_FIRST ):                   return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::history_first, code ) );
		case ( Replxx::ACTION::HISTORY_LAST ):                    return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::history_last, code ) );
		case ( Replxx::ACTION::HISTORY_INCREMENTAL_SEARCH ):      return ( action( NOOP, &Replxx::ReplxxImpl::incremental_history_search, code ) );
		case ( Replxx::ACTION::HISTORY_COMMON_PREFIX_SEARCH ):    return ( action( RESET_KILL_ACTION | DONT_RESET_PREFIX, &Replxx::ReplxxImpl::common_prefix_search, code ) );
		case ( Replxx::ACTION::HINT_NEXT ):                       return ( action( NOOP, &Replxx::ReplxxImpl::hint_next, code ) );
		case ( Replxx::ACTION::HINT_PREVIOUS ):                   return ( action( NOOP, &Replxx::ReplxxImpl::hint_previous, code ) );
		case ( Replxx::ACTION::CAPITALIZE_WORD ):                 return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::capitalize_word, code ) );
		case ( Replxx::ACTION::LOWERCASE_WORD ):                  return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::lowercase_word, code ) );
		case ( Replxx::ACTION::UPPERCASE_WORD ):                  return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::uppercase_word, code ) );
		case ( Replxx::ACTION::TRANSPOSE_CHARACTERS ):            return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::transpose_characters, code ) );
		case ( Replxx::ACTION::TOGGLE_OVERWRITE_MODE ):           return ( action( NOOP, &Replxx::ReplxxImpl::toggle_overwrite_mode, code ) );
#ifndef _WIN32
		case ( Replxx::ACTION::VERBATIM_INSERT ):                 return ( action( WANT_REFRESH | RESET_KILL_ACTION, &Replxx::ReplxxImpl::verbatim_insert, code ) );
		case ( Replxx::ACTION::SUSPEND ):                         return ( action( WANT_REFRESH, &Replxx::ReplxxImpl::suspend, code ) );
#endif
		case ( Replxx::ACTION::CLEAR_SCREEN ):                    return ( action( NOOP, &Replxx::ReplxxImpl::clear_screen, code ) );
		case ( Replxx::ACTION::CLEAR_SELF ): clear_self_to_end_of_screen(); return ( Replxx::ACTION_RESULT::CONTINUE );
		case ( Replxx::ACTION::REPAINT ):    repaint();           return ( Replxx::ACTION_RESULT::CONTINUE );
		case ( Replxx::ACTION::COMPLETE_LINE ):                   return ( action( NOOP, &Replxx::ReplxxImpl::complete_line, code ) );
		case ( Replxx::ACTION::COMPLETE_NEXT ):                   return ( action( DONT_RESET_COMPLETIONS, &Replxx::ReplxxImpl::complete_next, code ) );
		case ( Replxx::ACTION::COMPLETE_PREVIOUS ):               return ( action( DONT_RESET_COMPLETIONS, &Replxx::ReplxxImpl::complete_previous, code ) );
		case ( Replxx::ACTION::COMMIT_LINE ):                     return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::commit_line, code ) );
		case ( Replxx::ACTION::ABORT_LINE ):                      return ( action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::abort_line, code ) );
		case ( Replxx::ACTION::SEND_EOF ):                        return ( action( NOOP, &Replxx::ReplxxImpl::send_eof, code ) );
	}
	return ( Replxx::ACTION_RESULT::BAIL );
}

void Replxx::ReplxxImpl::bind_key( char32_t code_, Replxx::key_press_handler_t handler_ ) {
	_keyPressHandlers[code_] = handler_;
}

Replxx::State Replxx::ReplxxImpl::get_state( void ) const {
	_utf8Buffer.assign( _data );
	return ( Replxx::State( _utf8Buffer.get(), _pos ) );
}

void Replxx::ReplxxImpl::set_state( Replxx::State const& state_ ) {
	_data.assign( state_.text() );
	if ( state_.cursor_position() >= 0 ) {
		_pos = min( state_.cursor_position(), _data.length() );
	}
	_modifiedState = true;
}

char32_t Replxx::ReplxxImpl::read_char( HINT_ACTION hintAction_ ) {
	/* try scheduled key presses */ {
		std::lock_guard<std::mutex> l( _mutex );
		if ( !_keyPresses.empty() ) {
			char32_t keyPress( _keyPresses.front() );
			_keyPresses.pop_front();
			return ( keyPress );
		}
	}
	int hintDelay( hintAction_ != HINT_ACTION::SKIP ? _hintDelay : 0 );
	while ( true ) {
		Terminal::EVENT_TYPE eventType( _terminal.wait_for_input( hintDelay ) );
		if ( eventType == Terminal::EVENT_TYPE::TIMEOUT ) {
			refresh_line( HINT_ACTION::REPAINT );
			hintDelay = 0;
			continue;
		}
		if ( eventType == Terminal::EVENT_TYPE::KEY_PRESS ) {
			break;
		}
		std::lock_guard<std::mutex> l( _mutex );
		clear_self_to_end_of_screen();
		while ( ! _messages.empty() ) {
			string const& message( _messages.front() );
			_terminal.write8( message.data(), message.length() );
			_messages.pop_front();
		}
		repaint();
	}
	/* try scheduled key presses */ {
		std::lock_guard<std::mutex> l( _mutex );
		if ( !_keyPresses.empty() ) {
			char32_t keyPress( _keyPresses.front() );
			_keyPresses.pop_front();
			return ( keyPress );
		}
	}
	return ( _terminal.read_char() );
}

void Replxx::ReplxxImpl::clear( void ) {
	_pos = 0;
	_prefix = 0;
	_completions.clear();
	_completionContextLength = 0;
	_completionSelection = -1;
	_data.clear();
	_hintSelection = -1;
	_hint = UnicodeString();
	_display.clear();
	_displayInputLength = 0;
}

Replxx::ReplxxImpl::completions_t Replxx::ReplxxImpl::call_completer( std::string const& input, int& contextLen_ ) const {
	Replxx::completions_t completionsIntermediary(
		!! _completionCallback
			? _completionCallback( input, contextLen_ )
			: Replxx::completions_t()
	);
	completions_t completions;
	completions.reserve( completionsIntermediary.size() );
	for ( Replxx::Completion const& c : completionsIntermediary ) {
		completions.emplace_back( c );
	}
	return ( completions );
}

Replxx::ReplxxImpl::hints_t Replxx::ReplxxImpl::call_hinter( std::string const& input, int& contextLen, Replxx::Color& color ) const {
	Replxx::hints_t hintsIntermediary(
		!! _hintCallback
			? _hintCallback( input, contextLen, color )
			: Replxx::hints_t()
	);
	hints_t hints;
	hints.reserve( hintsIntermediary.size() );
	for ( std::string const& h : hintsIntermediary ) {
		hints.emplace_back( h.c_str() );
	}
	return ( hints );
}

void Replxx::ReplxxImpl::set_preload_buffer( std::string const& preloadText ) {
	_preloadedBuffer = preloadText;
	// remove characters that won't display correctly
	bool controlsStripped = false;
	int whitespaceSeen( 0 );
	for ( std::string::iterator it( _preloadedBuffer.begin() ); it != _preloadedBuffer.end(); ) {
		unsigned char c = *it;
		if ( '\r' == c ) { // silently skip CR
			_preloadedBuffer.erase( it, it + 1 );
			continue;
		}
		if ( ( '\n' == c ) || ( '\t' == c ) ) { // note newline or tab
			++ whitespaceSeen;
			++ it;
			continue;
		}
		if ( whitespaceSeen > 0 ) {
			it -= whitespaceSeen;
			*it = ' ';
			_preloadedBuffer.erase( it + 1, it + whitespaceSeen - 1 );
		}
		if ( is_control_code( c ) ) { // remove other control characters, flag for message
			controlsStripped = true;
			if ( whitespaceSeen > 0 ) {
				_preloadedBuffer.erase( it, it + 1 );
				-- it;
			} else {
				*it = ' ';
			}
		}
		whitespaceSeen = 0;
		++ it;
	}
	if ( whitespaceSeen > 0 ) {
		std::string::iterator it = _preloadedBuffer.end() - whitespaceSeen;
		*it = ' ';
		if ( whitespaceSeen > 1 ) {
			_preloadedBuffer.erase( it + 1, _preloadedBuffer.end() );
		}
	}
	_errorMessage.clear();
	if ( controlsStripped ) {
		_errorMessage.assign( " [Edited line: control characters were converted to spaces]\n" );
	}
}

char const* Replxx::ReplxxImpl::read_from_stdin( void ) {
	if ( _preloadedBuffer.empty() ) {
		getline( cin, _preloadedBuffer );
		if ( ! cin.good() ) {
			return nullptr;
		}
	}
	while ( ! _preloadedBuffer.empty() && ( ( _preloadedBuffer.back() == '\r' ) || ( _preloadedBuffer.back() == '\n' ) ) ) {
		_preloadedBuffer.pop_back();
	}
	_utf8Buffer.assign( _preloadedBuffer );
	_preloadedBuffer.clear();
	return _utf8Buffer.get();
}

void Replxx::ReplxxImpl::emulate_key_press( char32_t keyCode_ ) {
	std::lock_guard<std::mutex> l( _mutex );
	_keyPresses.push_back( keyCode_ );
	if ( ( _currentThread != std::thread::id() ) && ( _currentThread != std::this_thread::get_id() ) ) {
		_terminal.notify_event( Terminal::EVENT_TYPE::KEY_PRESS );
	}
}

char const* Replxx::ReplxxImpl::input( std::string const& prompt ) {
#ifndef _WIN32
	gotResize = false;
#endif
	try {
		errno = 0;
		if ( ! tty::in ) { // input not from a terminal, we should work with piped input, i.e. redirected stdin
			return ( read_from_stdin() );
		}
		if (!_errorMessage.empty()) {
			printf("%s", _errorMessage.c_str());
			fflush(stdout);
			_errorMessage.clear();
		}
		if ( isUnsupportedTerm() ) {
			cout << prompt << flush;
			fflush(stdout);
			return ( read_from_stdin() );
		}
		if (_terminal.enable_raw_mode() == -1) {
			return nullptr;
		}
		_prompt.set_text( UnicodeString( prompt ) );
		_currentThread = std::this_thread::get_id();
		clear();
		if (!_preloadedBuffer.empty()) {
			preload_puffer(_preloadedBuffer.c_str());
			_preloadedBuffer.clear();
		}
		if ( get_input_line() == -1 ) {
			return ( finalize_input( nullptr ) );
		}
		printf("\n");
		_utf8Buffer.assign( _data );
		return ( finalize_input( _utf8Buffer.get() ) );
	} catch ( std::exception const& ) {
		return ( finalize_input( nullptr ) );
	}
}

char const* Replxx::ReplxxImpl::finalize_input( char const* retVal_ ) {
	_currentThread = std::thread::id();
	_terminal.disable_raw_mode();
	return ( retVal_ );
}

int Replxx::ReplxxImpl::install_window_change_handler( void ) {
#ifndef _WIN32
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &WindowSizeChanged;

	if (sigaction(SIGWINCH, &sa, nullptr) == -1) {
		return errno;
	}
#endif
	return 0;
}

void Replxx::ReplxxImpl::print( char const* str_, int size_ ) {
	if ( ( _currentThread == std::thread::id() ) || ( _currentThread == std::this_thread::get_id() ) ) {
		_terminal.write8( str_, size_ );
	} else {
		std::lock_guard<std::mutex> l( _mutex );
		_messages.emplace_back( str_, size_ );
		_terminal.notify_event( Terminal::EVENT_TYPE::MESSAGE );
	}
	return;
}

void Replxx::ReplxxImpl::preload_puffer(const char* preloadText) {
	_data.assign( preloadText );
	_charWidths.resize( _data.length() );
	recompute_character_widths( _data.get(), _charWidths.data(), _data.length() );
	_prefix = _pos = _data.length();
}

void Replxx::ReplxxImpl::set_color( Replxx::Color color_ ) {
	char const* code( ansi_color( color_ ) );
	while ( *code ) {
		_display.push_back( *code );
		++ code;
	}
}

void Replxx::ReplxxImpl::render( char32_t ch ) {
	if ( ch == Replxx::KEY::ESCAPE ) {
		_display.push_back( '^' );
		_display.push_back( '[' );
	} else if ( is_control_code( ch ) ) {
		_display.push_back( '^' );
		_display.push_back( ch + 0x40 );
	} else {
		_display.push_back( ch );
	}
	return;
}

void Replxx::ReplxxImpl::render( HINT_ACTION hintAction_ ) {
	if ( hintAction_ == HINT_ACTION::TRIM ) {
		_display.erase( _display.begin() + _displayInputLength, _display.end() );
		return;
	}
	if ( hintAction_ == HINT_ACTION::SKIP ) {
		return;
	}
	_display.clear();
	if ( _noColor ) {
		for ( char32_t ch : _data ) {
			render( ch );
		}
		_displayInputLength = _display.size();
		return;
	}
	Replxx::colors_t colors( _data.length(), Replxx::Color::DEFAULT );
	_utf8Buffer.assign( _data );
	if ( !! _highlighterCallback ) {
		_highlighterCallback( _utf8Buffer.get(), colors );
	}
	paren_info_t pi( matching_paren() );
	if ( pi.index != -1 ) {
		colors[pi.index] = pi.error ? Replxx::Color::ERROR : Replxx::Color::BRIGHTRED;
	}
	Replxx::Color c( Replxx::Color::DEFAULT );
	for ( int i( 0 ); i < _data.length(); ++ i ) {
		if ( colors[i] != c ) {
			c = colors[i];
			set_color( c );
		}
		render( _data[i] );
	}
	set_color( Replxx::Color::DEFAULT );
	_displayInputLength = _display.size();
	_modifiedState = false;
	return;
}

int Replxx::ReplxxImpl::handle_hints( HINT_ACTION hintAction_ ) {
	if ( _noColor ) {
		return ( 0 );
	}
	if ( ! _hintCallback ) {
		return ( 0 );
	}
	if ( ( _hintDelay > 0 ) && ( hintAction_ != HINT_ACTION::REPAINT ) ) {
		_hintSelection = -1;
		return ( 0 );
	}
	if ( ( hintAction_ == HINT_ACTION::SKIP ) || ( hintAction_ == HINT_ACTION::TRIM ) ) {
		return ( 0 );
	}
	if ( _pos != _data.length() ) {
		return ( 0 );
	}
	_hint = UnicodeString();
	int len( 0 );
	if ( hintAction_ == HINT_ACTION::REGENERATE ) {
		_hintSelection = -1;
	}
	Replxx::Color c( Replxx::Color::GRAY );
	_utf8Buffer.assign( _data, _pos );
	int contextLen( context_length() );
	Replxx::ReplxxImpl::hints_t hints( call_hinter( _utf8Buffer.get(), contextLen, c ) );
	int hintCount( hints.size() );
	if ( hintCount == 1 ) {
		_hint = hints.front();
		len = _hint.length() - contextLen;
		if ( len > 0 ) {
			set_color( c );
			for ( int i( 0 ); i < len; ++ i ) {
				_display.push_back( _hint[i + contextLen] );
			}
			set_color( Replxx::Color::DEFAULT );
		}
	} else if ( ( _maxHintRows > 0 ) && ( hintCount > 0 ) ) {
		int startCol( _prompt._indentation + _pos - contextLen );
		int maxCol( _prompt.screen_columns() );
#ifdef _WIN32
		-- maxCol;
#endif
		if ( _hintSelection < -1 ) {
			_hintSelection = hintCount - 1;
		} else if ( _hintSelection >= hintCount ) {
			_hintSelection = -1;
		}
		if ( _hintSelection != -1 ) {
			_hint = hints[_hintSelection];
			len = min<int>( _hint.length(), maxCol - startCol - _data.length() );
			if ( contextLen < len ) {
				set_color( c );
				for ( int i( contextLen ); i < len; ++ i ) {
					_display.push_back( _hint[i] );
				}
				set_color( Replxx::Color::DEFAULT );
			}
		}
		for ( int hintRow( 0 ); hintRow < min( hintCount, _maxHintRows ); ++ hintRow ) {
#ifdef _WIN32
			_display.push_back( '\r' );
#endif
			_display.push_back( '\n' );
			int col( 0 );
			for ( int i( 0 ); ( i < startCol ) && ( col < maxCol ); ++ i, ++ col ) {
				_display.push_back( ' ' );
			}
			set_color( c );
			for ( int i( _pos - contextLen ); ( i < _pos ) && ( col < maxCol ); ++ i, ++ col ) {
				_display.push_back( _data[i] );
			}
			int hintNo( hintRow + _hintSelection + 1 );
			if ( hintNo == hintCount ) {
				continue;
			} else if ( hintNo > hintCount ) {
				-- hintNo;
			}
			UnicodeString const& h( hints[hintNo % hintCount] );
			for ( int i( contextLen ); ( i < h.length() ) && ( col < maxCol ); ++ i, ++ col ) {
				_display.push_back( h[i] );
			}
			set_color( Replxx::Color::DEFAULT );
		}
	}
	return ( len );
}

Replxx::ReplxxImpl::paren_info_t Replxx::ReplxxImpl::matching_paren( void ) {
	if (_pos >= _data.length()) {
		return ( paren_info_t{ -1, false } );
	}
	/* this scans for a brace matching _data[_pos] to highlight */
	unsigned char part1, part2;
	int scanDirection = 0;
	if ( strchr("}])", _data[_pos]) ) {
		scanDirection = -1; /* backwards */
		if (_data[_pos] == '}') {
			part1 = '}'; part2 = '{';
		} else if (_data[_pos] == ']') {
			part1 = ']'; part2 = '[';
		} else {
			part1 = ')'; part2 = '(';
		}
	} else if ( strchr("{[(", _data[_pos]) ) {
		scanDirection = 1; /* forwards */
		if (_data[_pos] == '{') {
			//part1 = '{'; part2 = '}';
			part1 = '}'; part2 = '{';
		} else if (_data[_pos] == '[') {
			//part1 = '['; part2 = ']';
			part1 = ']'; part2 = '[';
		} else {
			//part1 = '('; part2 = ')';
			part1 = ')'; part2 = '(';
		}
	} else {
		return ( paren_info_t{ -1, false } );
	}
	int highlightIdx = -1;
	bool indicateError = false;
	int unmatched = scanDirection;
	int unmatchedOther = 0;
	for (int i = _pos + scanDirection; i >= 0 && i < _data.length(); i += scanDirection) {
		/* TODO: the right thing when inside a string */
		if (strchr("}])", _data[i])) {
			if (_data[i] == part1) {
				--unmatched;
			} else {
				--unmatchedOther;
			}
		} else if (strchr("{[(", _data[i])) {
			if (_data[i] == part2) {
				++unmatched;
			} else {
				++unmatchedOther;
			}
		}

		if (unmatched == 0) {
			highlightIdx = i;
			indicateError = (unmatchedOther != 0);
			break;
		}
	}
	return ( paren_info_t{ highlightIdx, indicateError } );
}

/**
 * Refresh the user's input line: the prompt is already onscreen and is not
 * redrawn here screen position
 */
void Replxx::ReplxxImpl::refresh_line( HINT_ACTION hintAction_ ) {
	// check for a matching brace/bracket/paren, remember its position if found
	render( hintAction_ );
	int hintLen( handle_hints( hintAction_ ) );
	// calculate the position of the end of the input line
	int xEndOfInput( 0 ), yEndOfInput( 0 );
	calculate_screen_position(
		_prompt._indentation, 0, _prompt.screen_columns(),
		calculate_displayed_length( _data.get(), _data.length() ) + hintLen,
		xEndOfInput, yEndOfInput
	);
	yEndOfInput += count( _display.begin(), _display.end(), '\n' );

	// calculate the desired position of the cursor
	int xCursorPos( 0 ), yCursorPos( 0 );
	calculate_screen_position(
		_prompt._indentation, 0, _prompt.screen_columns(),
		calculate_displayed_length( _data.get(), _pos ),
		xCursorPos, yCursorPos
	);

	// position at the end of the prompt, clear to end of previous input
	_terminal.jump_cursor(
		_prompt._indentation, // 0-based on Win32
		-( _prompt._cursorRowOffset - _prompt._extraLines )
	);
	_terminal.clear_screen( Terminal::CLEAR_SCREEN::TO_END );
	_prompt._previousInputLen = _data.length();
	// display the input line
	_terminal.write32( _display.data(), _display.size() );
#ifndef _WIN32
	// we have to generate our own newline on line wrap
	if ( ( xEndOfInput == 0 ) && ( yEndOfInput > 0 ) ) {
		_terminal.write8( "\n", 1 );
	}
#endif
	// position the cursor
	_terminal.jump_cursor( xCursorPos, -( yEndOfInput - yCursorPos ) );
	_prompt._cursorRowOffset = _prompt._extraLines + yCursorPos; // remember row for next pass
}

int Replxx::ReplxxImpl::context_length() {
	int prefixLength = _pos;
	while ( prefixLength > 0 ) {
		if ( is_word_break_character( _data[prefixLength - 1] ) ) {
			break;
		}
		-- prefixLength;
	}
	return ( _pos - prefixLength );
}

void Replxx::ReplxxImpl::repaint( void ) {
	_prompt.write();
	for ( int i( _prompt._extraLines ); i < _prompt._cursorRowOffset; ++ i ) {
		_terminal.write8( "\n", 1 );
	}
	refresh_line( HINT_ACTION::SKIP );
}

void Replxx::ReplxxImpl::clear_self_to_end_of_screen( void ) {
	// position at the start of the prompt, clear to end of previous input
	_terminal.jump_cursor( 0, -_prompt._cursorRowOffset );
	_terminal.clear_screen( Terminal::CLEAR_SCREEN::TO_END );
	return;
}

namespace {
int longest_common_prefix( Replxx::ReplxxImpl::completions_t const& completions ) {
	int completionsCount( completions.size() );
	if ( completionsCount < 1 ) {
		return ( 0 );
	}
	int longestCommonPrefix( 0 );
	UnicodeString const& sample( completions.front().text() );
	while ( true ) {
		if ( longestCommonPrefix >= sample.length() ) {
			return ( longestCommonPrefix );
		}
		char32_t sc( sample[longestCommonPrefix] );
		for ( int i( 1 ); i < completionsCount; ++ i ) {
			UnicodeString const& candidate( completions[i].text() );
			if ( longestCommonPrefix >= candidate.length() ) {
				return ( longestCommonPrefix );
			}
			char32_t cc( candidate[longestCommonPrefix] );
			if ( cc != sc ) {
				return ( longestCommonPrefix );
			}
		}
		++ longestCommonPrefix;
	}
}
}

/**
 * Handle command completion, using a completionCallback() routine to provide
 * possible substitutions
 * This routine handles the mechanics of updating the user's input buffer with
 * possible replacement of text as the user selects a proposed completion string,
 * or cancels the completion attempt.
 * @param pi - Prompt struct holding information about the prompt and our
 * screen position
 */
char32_t Replxx::ReplxxImpl::do_complete_line( bool showCompletions_ ) {
	char32_t c = 0;

	// completionCallback() expects a parsable entity, so find the previous break
	// character and
	// extract a copy to parse.	we also handle the case where tab is hit while
	// not at end-of-line.

	_utf8Buffer.assign( _data, _pos );
	// get a list of completions
	_completionSelection = -1;
	_completionContextLength = context_length();
	_completions = call_completer( _utf8Buffer.get(), _completionContextLength );

	// if no completions, we are done
	if ( _completions.empty() ) {
		beep();
		return 0;
	}

	// at least one completion
	int longestCommonPrefix = 0;
	int completionsCount( _completions.size() );
	int selectedCompletion( 0 );
	if ( _hintSelection != -1 ) {
		selectedCompletion = _hintSelection;
		completionsCount = 1;
	}
	if ( completionsCount == 1 ) {
		longestCommonPrefix = static_cast<int>( _completions[selectedCompletion].text().length() );
	} else {
		longestCommonPrefix = longest_common_prefix( _completions );
	}
	if ( _beepOnAmbiguousCompletion && ( completionsCount != 1 ) ) { // beep if ambiguous
		beep();
	}

	// if we can extend the item, extend it and return to main loop
	if ( ( longestCommonPrefix > _completionContextLength ) || ( completionsCount == 1 ) ) {
		_pos -= _completionContextLength;
		_data.erase( _pos, _completionContextLength );
		_data.insert( _pos, _completions[selectedCompletion].text(), 0, longestCommonPrefix );
		_pos = _pos + longestCommonPrefix;
		_completionContextLength = longestCommonPrefix;
		refresh_line();
		return 0;
	}

	if ( ! showCompletions_ ) {
		return ( 0 );
	}

	if ( _doubleTabCompletion ) {
		// we can't complete any further, wait for second tab
		do {
			c = read_char();
		} while ( c == static_cast<char32_t>( -1 ) );

		// if any character other than tab, pass it to the main loop
		if ( c != Replxx::KEY::TAB ) {
			return c;
		}
	}

	// we got a second tab, maybe show list of possible completions
	bool showCompletions = true;
	bool onNewLine = false;
	if ( static_cast<int>( _completions.size() ) > _completionCountCutoff ) {
		int savePos = _pos; // move cursor to EOL to avoid overwriting the command line
		_pos = _data.length();
		refresh_line();
		_pos = savePos;
		printf( "\nDisplay all %u possibilities? (y or n)", static_cast<unsigned int>( _completions.size() ) );
		fflush(stdout);
		onNewLine = true;
		while (c != 'y' && c != 'Y' && c != 'n' && c != 'N' && c != Replxx::KEY::control('C')) {
			do {
				c = read_char();
			} while (c == static_cast<char32_t>(-1));
		}
		switch (c) {
			case 'n':
			case 'N':
				showCompletions = false;
				break;
			case Replxx::KEY::control('C'):
				showCompletions = false;
				// Display the ^C we got
				_terminal.write8( "^C", 2 );
				c = 0;
				break;
		}
	}

	// if showing the list, do it the way readline does it
	bool stopList( false );
	if ( showCompletions ) {
		int longestCompletion( 0 );
		for ( size_t j( 0 ); j < _completions.size(); ++ j ) {
			int itemLength( static_cast<int>( _completions[j].text().length() ) );
			if ( itemLength > longestCompletion ) {
				longestCompletion = itemLength;
			}
		}
		longestCompletion += 2;
		int columnCount = _prompt.screen_columns() / longestCompletion;
		if ( columnCount < 1 ) {
			columnCount = 1;
		}
		if ( ! onNewLine ) {  // skip this if we showed "Display all %d possibilities?"
			int savePos = _pos; // move cursor to EOL to avoid overwriting the command line
			_pos = _data.length();
			refresh_line( HINT_ACTION::TRIM );
			_pos = savePos;
		} else {
			_terminal.clear_screen( Terminal::CLEAR_SCREEN::TO_END );
		}
		size_t pauseRow = _terminal.get_screen_rows() - 1;
		size_t rowCount = (_completions.size() + columnCount - 1) / columnCount;
		for (size_t row = 0; row < rowCount; ++row) {
			if (row == pauseRow) {
				printf("\n--More--");
				fflush(stdout);
				c = 0;
				bool doBeep = false;
				while (c != ' ' && c != Replxx::KEY::ENTER && c != 'y' && c != 'Y' &&
							 c != 'n' && c != 'N' && c != 'q' && c != 'Q' &&
							 c != Replxx::KEY::control('C')) {
					if (doBeep) {
						beep();
					}
					doBeep = true;
					do {
						c = read_char();
					} while (c == static_cast<char32_t>(-1));
				}
				switch (c) {
					case ' ':
					case 'y':
					case 'Y':
						printf("\r				\r");
						pauseRow += _terminal.get_screen_rows() - 1;
						break;
					case Replxx::KEY::ENTER:
						printf("\r				\r");
						++pauseRow;
						break;
					case 'n':
					case 'N':
					case 'q':
					case 'Q':
						printf("\r				\r");
						stopList = true;
						break;
					case Replxx::KEY::control('C'):
						// Display the ^C we got
						_terminal.write8( "^C", 2 );
						stopList = true;
						break;
				}
			} else {
				printf("\n");
			}
			if (stopList) {
				break;
			}
			static UnicodeString const res( ansi_color( Replxx::Color::DEFAULT ) );
			for (int column = 0; column < columnCount; ++column) {
				size_t index = (column * rowCount) + row;
				if ( index < _completions.size() ) {
					Completion const& c( _completions[index] );
					int itemLength = static_cast<int>(c.text().length());
					fflush(stdout);

					if ( longestCommonPrefix > 0 ) {
						static UnicodeString const col( ansi_color( Replxx::Color::BRIGHTMAGENTA ) );
						if (!_noColor) {
							_terminal.write32(col.get(), col.length());
						}
						_terminal.write32(&_data[_pos - _completionContextLength], longestCommonPrefix);
						if (!_noColor) {
							_terminal.write32(res.get(), res.length());
						}
					}

					if ( !_noColor && ( c.color() != Replxx::Color::DEFAULT ) ) {
						UnicodeString ac( ansi_color( c.color() ) );
						_terminal.write32( ac.get(), ac.length() );
					}
					_terminal.write32( c.text().get() + longestCommonPrefix, itemLength - longestCommonPrefix );
					if ( !_noColor && ( c.color() != Replxx::Color::DEFAULT ) ) {
						_terminal.write32( res.get(), res.length() );
					}

					if ( ((column + 1) * rowCount) + row < _completions.size() ) {
						for ( int k( itemLength ); k < longestCompletion; ++k ) {
							printf( " " );
						}
					}
				}
			}
		}
		fflush(stdout);
	}

	// display the prompt on a new line, then redisplay the input buffer
	if (!stopList || c == Replxx::KEY::control('C')) {
		_terminal.write8( "\n", 1 );
	}
	_prompt.write();
#ifndef _WIN32
	// we have to generate our own newline on line wrap on Linux
	if (_prompt._indentation == 0 && _prompt._extraLines > 0) {
		_terminal.write8( "\n", 1 );
	}
#endif
	_prompt._cursorRowOffset = _prompt._extraLines;
	refresh_line();
	return 0;
}

int Replxx::ReplxxImpl::get_input_line( void ) {
	// The latest history entry is always our current buffer
	if ( _data.length() > 0 ) {
		_history.add( _data );
	} else {
		_history.add( UnicodeString() );
	}
	_history.reset_pos();

	// display the prompt
	_prompt.write();

#ifndef _WIN32
	// we have to generate our own newline on line wrap on Linux
	if ( ( _prompt._indentation == 0 ) && ( _prompt._extraLines > 0 ) ) {
		_terminal.write8( "\n", 1 );
	}
#endif

	// the cursor starts out at the end of the prompt
	_prompt._cursorRowOffset = _prompt._extraLines;

	// kill and yank start in "other" mode
	_killRing.lastAction = KillRing::actionOther;

	// if there is already text in the buffer, display it first
	if (_data.length() > 0) {
		refresh_line();
	}

	// loop collecting characters, respond to line editing characters
	Replxx::ACTION_RESULT next( Replxx::ACTION_RESULT::CONTINUE );
	while ( next == Replxx::ACTION_RESULT::CONTINUE ) {
		int c( read_char( HINT_ACTION::REPAINT ) ); // get a new keystroke
#ifndef _WIN32
		if (c == 0 && gotResize) {
			// caught a window resize event
			// now redraw the prompt and line
			gotResize = false;
			_prompt.update_screen_columns();
			// redraw the original prompt with current input
			dynamicRefresh( _prompt, _data.get(), _data.length(), _pos );
			continue;
		}
#endif

		if (c == 0) {
			return _data.length();
		}

		if (c == -1) {
			refresh_line();
			continue;
		}

		if (c == -2) {
			_prompt.write();
			refresh_line();
			continue;
		}

		key_press_handlers_t::iterator it( _keyPressHandlers.find( c ) );
		if ( it != _keyPressHandlers.end() ) {
			next = it->second( c );
			if ( _modifiedState ) {
				refresh_line();
			}
		} else {
			next = action( RESET_KILL_ACTION, &Replxx::ReplxxImpl::insert_character, c );
		}
	}
	return ( next == Replxx::ACTION_RESULT::RETURN ? _data.length() : -1 );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::action( action_trait_t actionTrait_, key_press_handler_raw_t const& handler_, char32_t code_ ) {
	Replxx::ACTION_RESULT res( ( this->*handler_ )( code_ ) );
	if ( actionTrait_ & RESET_KILL_ACTION ) {
		_killRing.lastAction = KillRing::actionOther;
	}
	if ( actionTrait_ & SET_KILL_ACTION ) {
		_killRing.lastAction = KillRing::actionKill;
	}
	if ( ! ( actionTrait_ & DONT_RESET_PREFIX ) ) {
		_prefix = _pos;
	}
	if ( ! ( actionTrait_ & DONT_RESET_COMPLETIONS ) ) {
		_completions.clear();
		_completionSelection = -1;
		_completionContextLength = 0;
	}
	if ( actionTrait_ & WANT_REFRESH ) {
		_modifiedState = true;
	}
	return ( res );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::insert_character( char32_t c ) {
	_history.reset_recall_most_recent();
	/*
	 * beep on unknown Ctrl and/or Meta keys
	 * don't insert control characters
	 */
	if ( ( c >= static_cast<int>( Replxx::KEY::BASE ) ) || is_control_code( c ) ) {
		beep();
		return ( Replxx::ACTION_RESULT::CONTINUE );
	}
	if ( ! _overwrite || ( _pos >= _data.length() ) ) {
		_data.insert( _pos, c );
	} else {
		_data[_pos] = c;
	}
	++ _pos;
	int inputLen = calculate_displayed_length( _data.get(), _data.length() );
	if (
		( _pos == _data.length() )
		&& ( _noColor || ! ( !! _highlighterCallback || !! _hintCallback ) )
		&& ( _prompt._indentation + inputLen < _prompt.screen_columns() )
	) {
		/* Avoid a full assign of the line in the
		 * trivial case. */
		if (inputLen > _prompt._previousInputLen) {
			_prompt._previousInputLen = inputLen;
		}
		render( c );
		_displayInputLength = _display.size();
		_terminal.write32(reinterpret_cast<char32_t*>(&c), 1);
	} else {
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-A, HOME: move cursor to start of line
Replxx::ACTION_RESULT Replxx::ReplxxImpl::go_to_begining_of_line( char32_t ) {
	_pos = 0;
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::go_to_end_of_line( char32_t ) {
	_pos = _data.length();
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-B, move cursor left by one character
Replxx::ACTION_RESULT Replxx::ReplxxImpl::move_one_char_left( char32_t ) {
	if (_pos > 0) {
		--_pos;
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-F, move cursor right by one character
Replxx::ACTION_RESULT Replxx::ReplxxImpl::move_one_char_right( char32_t ) {
	if ( _pos < _data.length() ) {
		++_pos;
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// meta-B, move cursor left by one word
Replxx::ACTION_RESULT Replxx::ReplxxImpl::move_one_word_left( char32_t ) {
	if (_pos > 0) {
		while (_pos > 0 && is_word_break_character( _data[_pos - 1] ) ) {
			--_pos;
		}
		while (_pos > 0 && !is_word_break_character( _data[_pos - 1] ) ) {
			--_pos;
		}
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// meta-F, move cursor right by one word
Replxx::ACTION_RESULT Replxx::ReplxxImpl::move_one_word_right( char32_t ) {
	if ( _pos < _data.length() ) {
		while ( _pos < _data.length() && is_word_break_character( _data[_pos] ) ) {
			++_pos;
		}
		while ( _pos < _data.length() && !is_word_break_character( _data[_pos] ) ) {
			++_pos;
		}
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// meta-Backspace, kill word to left of cursor
Replxx::ACTION_RESULT Replxx::ReplxxImpl::kill_word_to_left( char32_t ) {
	if ( _pos > 0 ) {
		_history.reset_recall_most_recent();
		int startingPos = _pos;
		while ( _pos > 0 && is_word_break_character( _data[_pos - 1] ) ) {
			-- _pos;
		}
		while ( _pos > 0 && !is_word_break_character( _data[_pos - 1] ) ) {
			-- _pos;
		}
		_killRing.kill( _data.get() + _pos, startingPos - _pos, false);
		_data.erase( _pos, startingPos - _pos );
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// meta-D, kill word to right of cursor
Replxx::ACTION_RESULT Replxx::ReplxxImpl::kill_word_to_right( char32_t ) {
	if ( _pos < _data.length() ) {
		_history.reset_recall_most_recent();
		int endingPos = _pos;
		while ( endingPos < _data.length() && is_word_break_character( _data[endingPos] ) ) {
			++ endingPos;
		}
		while ( endingPos < _data.length() && !is_word_break_character( _data[endingPos] ) ) {
			++ endingPos;
		}
		_killRing.kill( _data.get() + _pos, endingPos - _pos, true );
		_data.erase( _pos, endingPos - _pos );
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-W, kill to whitespace (not word) to left of cursor
Replxx::ACTION_RESULT Replxx::ReplxxImpl::kill_to_whitespace_to_left( char32_t ) {
	if ( _pos > 0 ) {
		_history.reset_recall_most_recent();
		int startingPos = _pos;
		while ( _pos > 0 && _data[_pos - 1] == ' ' ) {
			--_pos;
		}
		while ( _pos > 0 && _data[_pos - 1] != ' ' ) {
			-- _pos;
		}
		_killRing.kill( _data.get() + _pos, startingPos - _pos, false );
		_data.erase( _pos, startingPos - _pos );
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-K, kill from cursor to end of line
Replxx::ACTION_RESULT Replxx::ReplxxImpl::kill_to_end_of_line( char32_t ) {
	_killRing.kill( _data.get() + _pos, _data.length() - _pos, true );
	_data.erase( _pos, _data.length() - _pos );
	_history.reset_recall_most_recent();
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-U, kill all characters to the left of the cursor
Replxx::ACTION_RESULT Replxx::ReplxxImpl::kill_to_begining_of_line( char32_t ) {
	if (_pos > 0) {
		_history.reset_recall_most_recent();
		_killRing.kill( _data.get(), _pos, false );
		_data.erase( 0, _pos );
		_pos = 0;
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-Y, yank killed text
Replxx::ACTION_RESULT Replxx::ReplxxImpl::yank( char32_t ) {
	_history.reset_recall_most_recent();
	UnicodeString* restoredText( _killRing.yank() );
	if ( restoredText ) {
		_data.insert( _pos, *restoredText, 0, restoredText->length() );
		_pos += restoredText->length();
		refresh_line();
		_killRing.lastAction = KillRing::actionYank;
		_killRing.lastYankSize = restoredText->length();
	} else {
		beep();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// meta-Y, "yank-pop", rotate popped text
Replxx::ACTION_RESULT Replxx::ReplxxImpl::yank_cycle( char32_t ) {
	if ( _killRing.lastAction != KillRing::actionYank ) {
		beep();
		return ( Replxx::ACTION_RESULT::CONTINUE );
	}
	_history.reset_recall_most_recent();
	UnicodeString* restoredText = _killRing.yankPop();
	if ( !restoredText ) {
		beep();
		return ( Replxx::ACTION_RESULT::CONTINUE );
	}
	_pos -= _killRing.lastYankSize;
	_data.erase( _pos, _killRing.lastYankSize );
	_data.insert( _pos, *restoredText, 0, restoredText->length() );
	_pos += restoredText->length();
	_killRing.lastYankSize = restoredText->length();
	refresh_line();
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// meta-C, give word initial Cap
Replxx::ACTION_RESULT Replxx::ReplxxImpl::capitalize_word( char32_t ) {
	_history.reset_recall_most_recent();
	if (_pos < _data.length()) {
		while ( _pos < _data.length() && is_word_break_character( _data[_pos] ) ) {
			++_pos;
		}
		if (_pos < _data.length() && !is_word_break_character( _data[_pos] ) ) {
			if ( _data[_pos] >= 'a' && _data[_pos] <= 'z' ) {
				_data[_pos] += 'A' - 'a';
			}
			++_pos;
		}
		while (_pos < _data.length() && !is_word_break_character( _data[_pos] ) ) {
			if ( _data[_pos] >= 'A' && _data[_pos] <= 'Z' ) {
				_data[_pos] += 'a' - 'A';
			}
			++_pos;
		}
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// meta-L, lowercase word
Replxx::ACTION_RESULT Replxx::ReplxxImpl::lowercase_word( char32_t ) {
	if (_pos < _data.length()) {
		_history.reset_recall_most_recent();
		while ( _pos < _data.length() && is_word_break_character( _data[_pos] ) ) {
			++ _pos;
		}
		while (_pos < _data.length() && !is_word_break_character( _data[_pos] ) ) {
			if ( _data[_pos] >= 'A' && _data[_pos] <= 'Z' ) {
				_data[_pos] += 'a' - 'A';
			}
			++ _pos;
		}
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// meta-U, uppercase word
Replxx::ACTION_RESULT Replxx::ReplxxImpl::uppercase_word( char32_t ) {
	if (_pos < _data.length()) {
		_history.reset_recall_most_recent();
		while ( _pos < _data.length() && is_word_break_character( _data[_pos] ) ) {
			++ _pos;
		}
		while ( _pos < _data.length() && !is_word_break_character( _data[_pos] ) ) {
			if ( _data[_pos] >= 'a' && _data[_pos] <= 'z') {
				_data[_pos] += 'A' - 'a';
			}
			++ _pos;
		}
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-T, transpose characters
Replxx::ACTION_RESULT Replxx::ReplxxImpl::transpose_characters( char32_t ) {
	if ( _pos > 0 && _data.length() > 1 ) {
		_history.reset_recall_most_recent();
		size_t leftCharPos = ( _pos == _data.length() ) ? _pos - 2 : _pos - 1;
		char32_t aux = _data[leftCharPos];
		_data[leftCharPos] = _data[leftCharPos + 1];
		_data[leftCharPos + 1] = aux;
		if ( _pos != _data.length() ) {
			++_pos;
		}
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-C, abort this line
Replxx::ACTION_RESULT Replxx::ReplxxImpl::abort_line( char32_t ) {
	_history.reset_recall_most_recent();
	errno = EAGAIN;
	_history.drop_last();
	// we need one last refresh with the cursor at the end of the line
	// so we don't display the next prompt over the previous input line
	_pos = _data.length(); // pass _data.length() as _pos for EOL
	refresh_line( HINT_ACTION::TRIM );
	_terminal.write8( "^C\r\n", 4 );
	return ( Replxx::ACTION_RESULT::BAIL );
}

// DEL, delete the character under the cursor
Replxx::ACTION_RESULT Replxx::ReplxxImpl::delete_character( char32_t ) {
	if ( ( _data.length() > 0 ) && ( _pos < _data.length() ) ) {
		_history.reset_recall_most_recent();
		_data.erase( _pos );
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-D, delete the character under the cursor
// on an empty line, exit the shell
Replxx::ACTION_RESULT Replxx::ReplxxImpl::send_eof( char32_t key_ ) {
	if ( _data.length() == 0 ) {
		_history.drop_last();
		return ( Replxx::ACTION_RESULT::BAIL );
	}
	return ( delete_character( key_ ) );
}

// backspace/ctrl-H, delete char to left of cursor
Replxx::ACTION_RESULT Replxx::ReplxxImpl::backspace_character( char32_t ) {
	if ( _pos > 0 ) {
		_history.reset_recall_most_recent();
		-- _pos;
		_data.erase( _pos );
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-J/linefeed/newline, accept line
// ctrl-M/return/enter
Replxx::ACTION_RESULT Replxx::ReplxxImpl::commit_line( char32_t ) {
	// we need one last refresh with the cursor at the end of the line
	// so we don't display the next prompt over the previous input line
	_pos = _data.length(); // pass _data.length() as _pos for EOL
	refresh_line( HINT_ACTION::TRIM );
	_history.commit_index();
	_history.drop_last();
	return ( Replxx::ACTION_RESULT::RETURN );
}

// ctrl-N, recall next line in history
Replxx::ACTION_RESULT Replxx::ReplxxImpl::history_next( char32_t ) {
	return ( history_move( false ) );
}

// ctrl-P, recall previous line in history
Replxx::ACTION_RESULT Replxx::ReplxxImpl::history_previous( char32_t ) {
	return ( history_move( true ) );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::history_move( bool previous_ ) {
	// if not already recalling, add the current line to the history list so
	// we don't
	// have to special case it
	if ( _history.is_last() ) {
		_history.update_last( _data );
	}
	if ( _history.is_empty() ) {
		return ( Replxx::ACTION_RESULT::CONTINUE );
	}
	if ( ! _history.move( previous_ ) ) {
		return ( Replxx::ACTION_RESULT::CONTINUE );
	}
	_data.assign( _history.current() );
	_pos = _data.length();
	refresh_line();
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// meta-<, beginning of history
// Page Up, beginning of history
Replxx::ACTION_RESULT Replxx::ReplxxImpl::history_first( char32_t ) {
	return ( history_jump( true ) );
}

// meta->, end of history
// Page Down, end of history
Replxx::ACTION_RESULT Replxx::ReplxxImpl::history_last( char32_t ) {
	return ( history_jump( false ) );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::history_jump( bool back_ ) {
	// if not already recalling, add the current line to the history list so
	// we don't
	// have to special case it
	if ( _history.is_last() ) {
		_history.update_last( _data );
	}
	if ( ! _history.is_empty() ) {
		_history.jump( back_ );
		_data.assign( _history.current() );
		_pos = _data.length();
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::hint_next( char32_t ) {
	return ( hint_move( false ) );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::hint_previous( char32_t ) {
	return ( hint_move( true ) );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::hint_move( bool previous_ ) {
	if ( ! _noColor ) {
		_killRing.lastAction = KillRing::actionOther;
		if ( previous_ ) {
			-- _hintSelection;
		} else {
			++ _hintSelection;
		}
		refresh_line( HINT_ACTION::REPAINT );
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::toggle_overwrite_mode( char32_t ) {
	_overwrite = ! _overwrite;
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

#ifndef _WIN32
Replxx::ACTION_RESULT Replxx::ReplxxImpl::verbatim_insert( char32_t ) {
	static int const MAX_ESC_SEQ( 32 );
	char32_t buf[MAX_ESC_SEQ];
	int len( _terminal.read_verbatim( buf, MAX_ESC_SEQ ) );
	_data.insert( _pos, UnicodeString( buf, len ), 0, len );
	_pos += len;
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-Z, job control
Replxx::ACTION_RESULT Replxx::ReplxxImpl::suspend( char32_t ) {
	_terminal.disable_raw_mode(); // Returning to Linux (whatever) shell, leave raw mode
	raise(SIGSTOP);   // Break out in mid-line
	_terminal.enable_raw_mode();  // Back from Linux shell, re-enter raw mode
	// Redraw prompt
	_prompt.write();
	return ( Replxx::ACTION_RESULT::CONTINUE );
}
#endif

Replxx::ACTION_RESULT Replxx::ReplxxImpl::complete_line( char32_t c ) {
	if ( !! _completionCallback && ( _completeOnEmpty || ( _pos > 0 ) ) ) {
		_killRing.lastAction = KillRing::actionOther;
		_history.reset_recall_most_recent();

		// complete_line does the actual completion and replacement
		c = do_complete_line( c != 0 );

		if ( static_cast<int>( c ) < 0 ) {
			return ( Replxx::ACTION_RESULT::BAIL );
		}
		if ( c != 0 ) {
			emulate_key_press( c );
		}
	} else {
		insert_character( c );
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::complete( bool previous_ ) {
	if ( _completions.empty() ) {
		bool first( _completions.empty() );
		complete_line( first ? '\t' : 0 );
		if ( first ) {
			return ( Replxx::ACTION_RESULT::CONTINUE );
		}
	}
	int newSelection( _completionSelection + ( previous_ ? -1 : 1 ) );
	if ( newSelection >= static_cast<int>( _completions.size() ) ) {
		newSelection = -1;
	} else if ( newSelection == -2 ) {
		newSelection = static_cast<int>( _completions.size() ) - 1;
	}
	if ( _completionSelection != -1 ) {
		int oldCompletionLength( _completions[_completionSelection].text().length() - _completionContextLength );
		_pos -= oldCompletionLength;
		_data.erase( _pos, oldCompletionLength );
	}
	if ( newSelection != -1 ) {
		int newCompletionLength( _completions[newSelection].text().length() - _completionContextLength );
		_data.insert( _pos, _completions[newSelection].text(), _completionContextLength, newCompletionLength );
		_pos += newCompletionLength;
	}
	_completionSelection = newSelection;
	refresh_line();  // Refresh the line
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::complete_next( char32_t ) {
	return ( complete( false ) );
}

Replxx::ACTION_RESULT Replxx::ReplxxImpl::complete_previous( char32_t ) {
	return ( complete( true ) );
}

// Alt-P, reverse history search for prefix
// Alt-P, reverse history search for prefix
// Alt-N, forward history search for prefix
// Alt-N, forward history search for prefix
Replxx::ACTION_RESULT Replxx::ReplxxImpl::common_prefix_search( char32_t startChar ) {
	int prefixSize( calculate_displayed_length( _data.get(), _prefix ) );
	if (
		_history.common_prefix_search(
			_data, prefixSize, ( startChar == ( Replxx::KEY::meta( 'p' ) ) ) || ( startChar == ( Replxx::KEY::meta( 'P' ) ) )
		)
	) {
		_data.assign( _history.current() );
		_pos = _data.length();
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-R, reverse history search
// ctrl-S, forward history search
/**
 * Incremental history search -- take over the prompt and keyboard as the user
 * types a search string, deletes characters from it, changes _direction,
 * and either accepts the found line (for execution orediting) or cancels.
 * @param startChar - the character that began the search, used to set the initial
 * _direction
 */
Replxx::ACTION_RESULT Replxx::ReplxxImpl::incremental_history_search( char32_t startChar ) {
	// if not already recalling, add the current line to the history list so we
	// don't have to special case it
	if ( _history.is_last() ) {
		_history.update_last( _data );
	}
	int historyLinePosition( _pos );
	clear_self_to_end_of_screen();

	DynamicPrompt dp( _terminal, (startChar == Replxx::KEY::control('R')) ? -1 : 1 );

	dp._previousLen = _prompt._previousLen;
	dp._previousInputLen = _prompt._previousInputLen;
	// draw user's text with our prompt
	dynamicRefresh(dp, _data.get(), _data.length(), historyLinePosition);

	// loop until we get an exit character
	char32_t c( 0 );
	bool keepLooping = true;
	bool useSearchedLine = true;
	bool searchAgain = false;
	UnicodeString activeHistoryLine;
	while ( keepLooping ) {
		c = read_char();

		switch (c) {
			// these characters keep the selected text but do not execute it
			case Replxx::KEY::control('A'): // ctrl-A, move cursor to start of line
			case Replxx::KEY::HOME:
			case Replxx::KEY::control('B'): // ctrl-B, move cursor left by one character
			case Replxx::KEY::LEFT:
			case Replxx::KEY::meta( 'b' ): // meta-B, move cursor left by one word
			case Replxx::KEY::meta( 'B' ):
			case Replxx::KEY::control( Replxx::KEY::LEFT ):
			case Replxx::KEY::meta( Replxx::KEY::LEFT ): // Emacs allows Meta, bash & readline don't
			case Replxx::KEY::control('D'):
			case Replxx::KEY::meta( 'd' ): // meta-D, kill word to right of cursor
			case Replxx::KEY::meta( 'D' ):
			case Replxx::KEY::control('E'): // ctrl-E, move cursor to end of line
			case Replxx::KEY::END:
			case Replxx::KEY::control('F'): // ctrl-F, move cursor right by one character
			case Replxx::KEY::RIGHT:
			case Replxx::KEY::meta( 'f' ): // meta-F, move cursor right by one word
			case Replxx::KEY::meta( 'F' ):
			case Replxx::KEY::control( Replxx::KEY::RIGHT ):
			case Replxx::KEY::meta( Replxx::KEY::RIGHT ): // Emacs allows Meta, bash & readline don't
			case Replxx::KEY::meta( Replxx::KEY::BACKSPACE ):
			case Replxx::KEY::control('J'):
			case Replxx::KEY::control('K'): // ctrl-K, kill from cursor to end of line
			case Replxx::KEY::ENTER:
			case Replxx::KEY::control('N'): // ctrl-N, recall next line in history
			case Replxx::KEY::control('P'): // ctrl-P, recall previous line in history
			case Replxx::KEY::DOWN:
			case Replxx::KEY::UP:
			case Replxx::KEY::control('T'): // ctrl-T, transpose characters
			case Replxx::KEY::control('U'): // ctrl-U, kill all characters to the left of the cursor
			case Replxx::KEY::control('W'):
			case Replxx::KEY::meta( 'y' ): // meta-Y, "yank-pop", rotate popped text
			case Replxx::KEY::meta( 'Y' ):
			case 127:
			case Replxx::KEY::DELETE:
			case Replxx::KEY::meta( '<' ): // start of history
			case Replxx::KEY::PAGE_UP:
			case Replxx::KEY::meta( '>' ): // end of history
			case Replxx::KEY::PAGE_DOWN:
				keepLooping = false;
				break;

			// these characters revert the input line to its previous state
			case Replxx::KEY::control('C'): // ctrl-C, abort this line
			case Replxx::KEY::control('G'):
			case Replxx::KEY::control('L'): // ctrl-L, clear screen and redisplay line
				keepLooping = false;
				useSearchedLine = false;
				if (c != Replxx::KEY::control('L')) {
					c = -1; // ctrl-C and ctrl-G just abort the search and do nothing else
				}
				break;

			// these characters stay in search mode and assign the display
			case Replxx::KEY::control('S'):
			case Replxx::KEY::control('R'):
				if ( dp._searchText.length() == 0 ) { // if no current search text, recall previous text
					if ( previousSearchText.length() > 0 ) {
						dp._searchText = previousSearchText;
					}
				}
				if ((dp._direction == 1 && c == Replxx::KEY::control('R')) ||
						(dp._direction == -1 && c == Replxx::KEY::control('S'))) {
					dp._direction = 0 - dp._direction; // reverse _direction
					dp.updateSearchPrompt();         // change the prompt
				} else {
					searchAgain = true; // same _direction, search again
				}
				break;

// job control is its own thing
#ifndef _WIN32
			case Replxx::KEY::control('Z'): { // ctrl-Z, job control
				_terminal.disable_raw_mode(); // Returning to Linux (whatever) shell, leave raw mode
				raise(SIGSTOP);   // Break out in mid-line
				_terminal.enable_raw_mode();  // Back from Linux shell, re-enter raw mode
				dynamicRefresh(dp, activeHistoryLine.get(), activeHistoryLine.length(), historyLinePosition);
				continue;
			} break;
#endif

			// these characters assign the search string, and hence the selected input
			// line
			case Replxx::KEY::BACKSPACE: // backspace/ctrl-H, delete char to left of cursor
				if ( dp._searchText.length() > 0 ) {
					dp._searchText.erase( dp._searchText.length() - 1 );
					dp.updateSearchPrompt();
					_history.reset_pos( dp._direction == -1 ? _history.size() - 1 : 0 );
				} else {
					beep();
				}
				break;

			case Replxx::KEY::control('Y'): // ctrl-Y, yank killed text
				break;

			default: {
				if ( ! is_control_code( c ) && ( c < static_cast<int>( Replxx::KEY::BASE ) ) ) { // not an action character
					dp._searchText.insert( dp._searchText.length(), c );
					dp.updateSearchPrompt();
				} else {
					beep();
				}
			}
		} // switch

		// if we are staying in search mode, search now
		if ( ! keepLooping ) {
			break;
		}
		activeHistoryLine.assign( _history.current() );
		if ( dp._searchText.length() > 0 ) {
			bool found = false;
			int historySearchIndex = _history.current_pos();
			int lineSearchPos = historyLinePosition;
			if ( searchAgain ) {
				lineSearchPos += dp._direction;
			}
			searchAgain = false;
			while ( true ) {
				while ( ( ( lineSearchPos + dp._searchText.length() ) <= activeHistoryLine.length() ) && ( lineSearchPos >= 0 ) ) {
					if ( std::equal( dp._searchText.begin(), dp._searchText.end(), activeHistoryLine.begin() + lineSearchPos ) ) {
						found = true;
						break;
					}
					lineSearchPos += dp._direction;
				}
				if ( found ) {
					_history.reset_pos( historySearchIndex );
					historyLinePosition = lineSearchPos;
					break;
				} else if ( ( dp._direction > 0 ) ? ( historySearchIndex < _history.size() ) : ( historySearchIndex > 0 ) ) {
					historySearchIndex += dp._direction;
					activeHistoryLine.assign( _history[historySearchIndex] );
					lineSearchPos = ( dp._direction > 0 ) ? 0 : ( activeHistoryLine.length() - dp._searchText.length() );
				} else {
					beep();
					break;
				}
			} // while
		}
		activeHistoryLine.assign( _history.current() );
		dynamicRefresh(dp, activeHistoryLine.get(), activeHistoryLine.length(), historyLinePosition); // draw user's text with our prompt
	} // while

	// leaving history search, restore previous prompt, maybe make searched line
	// current
	Prompt pb( _terminal );
	pb._characterCount = _prompt._indentation;
	pb._byteCount = _prompt._byteCount;
	UnicodeString tempUnicode( &_prompt._text[_prompt._lastLinePosition], pb._byteCount - _prompt._lastLinePosition );
	pb._text = tempUnicode;
	pb._extraLines = 0;
	pb._indentation = _prompt._indentation;
	pb._lastLinePosition = 0;
	pb._previousInputLen = activeHistoryLine.length();
	pb._cursorRowOffset = dp._cursorRowOffset;
	pb.update_screen_columns();
	pb._previousLen = dp._characterCount;
	if ( useSearchedLine && ( activeHistoryLine.length() > 0 ) ) {
		_history.set_recall_most_recent();
		_data.assign( activeHistoryLine );
		_pos = historyLinePosition;
	}
	dynamicRefresh(pb, _data.get(), _data.length(), _pos); // redraw the original prompt with current input
	_prompt._previousInputLen = _data.length();
	_prompt._cursorRowOffset = _prompt._extraLines + pb._cursorRowOffset;
	previousSearchText = dp._searchText; // save search text for possible reuse on ctrl-R ctrl-R
	emulate_key_press( c ); // pass a character or -1 back to main loop
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

// ctrl-L, clear screen and redisplay line
Replxx::ACTION_RESULT Replxx::ReplxxImpl::clear_screen( char32_t c ) {
	_terminal.clear_screen( Terminal::CLEAR_SCREEN::WHOLE );
	if ( c ) {
		_prompt.write();
#ifndef _WIN32
		// we have to generate our own newline on line wrap on Linux
		if (_prompt._indentation == 0 && _prompt._extraLines > 0) {
			_terminal.write8( "\n", 1 );
		}
#endif
		_prompt._cursorRowOffset = _prompt._extraLines;
		refresh_line();
	}
	return ( Replxx::ACTION_RESULT::CONTINUE );
}

bool Replxx::ReplxxImpl::is_word_break_character( char32_t char_ ) const {
	bool wbc( false );
	if ( char_ < 128 ) {
		wbc = strchr( _breakChars, static_cast<char>( char_ ) ) != nullptr;
	}
	return ( wbc );
}

void Replxx::ReplxxImpl::history_add( std::string const& line ) {
	_history.add( UnicodeString( line ) );
}

int Replxx::ReplxxImpl::history_save( std::string const& filename ) {
	return ( _history.save( filename ) );
}

int Replxx::ReplxxImpl::history_load( std::string const& filename ) {
	return ( _history.load( filename ) );
}

int Replxx::ReplxxImpl::history_size( void ) const {
	return ( _history.size() );
}

std::string Replxx::ReplxxImpl::history_line( int index ) {
	_utf8Buffer.assign( _history[index] );
	return ( _utf8Buffer.get() );
}

void Replxx::ReplxxImpl::set_completion_callback( Replxx::completion_callback_t const& fn ) {
	_completionCallback = fn;
}

void Replxx::ReplxxImpl::set_highlighter_callback( Replxx::highlighter_callback_t const& fn ) {
	_highlighterCallback = fn;
}

void Replxx::ReplxxImpl::set_hint_callback( Replxx::hint_callback_t const& fn ) {
	_hintCallback = fn;
}

void Replxx::ReplxxImpl::set_max_history_size( int len ) {
	_history.set_max_size( len );
}

void Replxx::ReplxxImpl::set_completion_count_cutoff( int count ) {
	_completionCountCutoff = count;
}

void Replxx::ReplxxImpl::set_max_hint_rows( int count ) {
	_maxHintRows = count;
}

void Replxx::ReplxxImpl::set_hint_delay( int hintDelay_ ) {
	_hintDelay = hintDelay_;
}

void Replxx::ReplxxImpl::set_word_break_characters( char const* wordBreakers ) {
	_breakChars = wordBreakers;
}

void Replxx::ReplxxImpl::set_double_tab_completion( bool val ) {
	_doubleTabCompletion = val;
}

void Replxx::ReplxxImpl::set_complete_on_empty( bool val ) {
	_completeOnEmpty = val;
}

void Replxx::ReplxxImpl::set_beep_on_ambiguous_completion( bool val ) {
	_beepOnAmbiguousCompletion = val;
}

void Replxx::ReplxxImpl::set_no_color( bool val ) {
	_noColor = val;
}

/**
 * Display the dynamic incremental search prompt and the current user input
 * line.
 * @param pi    Prompt struct holding information about the prompt and our
 * screen position
 * @param buf32 input buffer to be displayed
 * @param len   count of characters in the buffer
 * @param pos   current cursor position within the buffer (0 <= pos <= len)
 */
void Replxx::ReplxxImpl::dynamicRefresh(Prompt& pi, char32_t* buf32, int len, int pos) {
	clear_self_to_end_of_screen();
	// calculate the position of the end of the prompt
	int xEndOfPrompt, yEndOfPrompt;
	calculate_screen_position(
		0, 0, pi.screen_columns(), pi._characterCount,
		xEndOfPrompt, yEndOfPrompt
	);
	pi._indentation = xEndOfPrompt;

	// calculate the position of the end of the input line
	int xEndOfInput, yEndOfInput;
	calculate_screen_position(
		xEndOfPrompt, yEndOfPrompt, pi.screen_columns(),
		calculate_displayed_length(buf32, len), xEndOfInput,
		yEndOfInput
	);

	// calculate the desired position of the cursor
	int xCursorPos, yCursorPos;
	calculate_screen_position(
		xEndOfPrompt, yEndOfPrompt, pi.screen_columns(),
		calculate_displayed_length(buf32, pos), xCursorPos,
		yCursorPos
	);

	pi._previousLen = pi._indentation;
	pi._previousInputLen = len;

	// display the prompt
	pi.write();

	// display the input line
	_terminal.write32( buf32, len );

#ifndef _WIN32
	// we have to generate our own newline on line wrap
	if (xEndOfInput == 0 && yEndOfInput > 0) {
		_terminal.write8( "\n", 1 );
	}
#endif
	// position the cursor
	_terminal.jump_cursor(
		xCursorPos, // 0-based on Win32
		-( yEndOfInput - yCursorPos )
	);
	pi._cursorRowOffset = pi._extraLines + yCursorPos; // remember row for next pass
}

}

