#ifndef REPLXX_HISTORY_HXX_INCLUDED
#define REPLXX_HISTORY_HXX_INCLUDED 1

#include <vector>

#include "unicodestring.hxx"
#include "conversion.hxx"

namespace replxx {

class History {
public:
	typedef std::vector<UnicodeString> lines_t;
private:
	lines_t _data;
	int _maxSize;
	int _maxLineLength;
	int _index;
	int _previousIndex;
	bool _recallMostRecent;
public:
	History( void );
	void add( UnicodeString const& line );
	int save( std::string const& filename );
	int load( std::string const& filename );
	void set_max_size( int len );
	void reset_pos( int = -1 );
	UnicodeString const& operator[] ( int ) const;
	void set_recall_most_recent( void ) {
		_recallMostRecent = true;
	}
	void reset_recall_most_recent( void ) {
		_recallMostRecent = false;
	}
	void drop_last( void ) {
		_data.pop_back();
	}
	void commit_index( void ) {
		_previousIndex = _recallMostRecent ? _index : -2;
	}
	int current_pos( void ) const {
		return ( _index );
	}
	bool is_last( void ) const {
		return ( _index == ( size() - 1 ) );
	}
	bool is_empty( void ) const {
		return ( _data.empty() );
	}
	void update_last( UnicodeString const& line_ ) {
		_data.back() = line_;
	}
	bool move( bool );
	UnicodeString const& current( void ) const {
		return ( _data[_index] );
	}
	void jump( bool );
	bool common_prefix_search( UnicodeString const&, int, bool );
	int size( void ) const {
		return ( static_cast<int>( _data.size() ) );
	}
	int max_line_length( void ) {
		return ( _maxLineLength );
	}
private:
	History( History const& ) = delete;
	History& operator = ( History const& ) = delete;
};

}

#endif

