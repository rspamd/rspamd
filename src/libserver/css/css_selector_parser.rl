%%{
  machine css_parser;
  alphtype unsigned char;
  include css_syntax "css_syntax.rl";

  main := selectors_group;
}%%

%% write data;

#include <cstddef>

namespace rspamd::css {

int
parse_css_selector (const unsigned char *data, std::size_t len)
{
  const unsigned char *p = data, *pe = data + len, *eof;
  int cs;

  %% write init;
  %% write exec;

  return cs;
}

}