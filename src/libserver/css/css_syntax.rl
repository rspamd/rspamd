%%{
  # CSS3 EBNF derived
  machine css_syntax;

  # Primitive Atoms
  COMMENT = (
    '/*' ( any )* :>> '*/'
  );
  QUOTED_STRING = ('"' ( [^"\\] | /\\./ )* "'");
  BARE_URL_CHARS = ((0x21
                                | 0x23..0x26
                                | 0x2A..0xFF)+);
  BARE_URL = BARE_URL_CHARS;
  URL = 'url(' ( QUOTED_STRING | space* BARE_URL space* ) ')';
  nonascii = [^0x00-0x7F];
  nmstart = ([_a-zA-Z] | nonascii);
  nmchar  = ([_a-zA-Z0-9] | 0x2D | nonascii);
  name = nmchar+;
  num  = ([0-9]+ | ([0-9]* '.' [0-9]+));
  CRLF = "\r\n" | ("\r" [^\n]) | ([^\r] "\n");
  IDENT = ([\-]? nmstart nmchar*);
  ATTR = 'attr('  IDENT  ')';

  DIMENSION = '-'? num space? ( 'ch' | 'cm' | 'em' | 'ex' | 'fr' | 'in' | 'mm' | 'pc' | 'pt' | 'px' | 'Q' | 'rem' | 'vh' | 'vmax' | 'vmin' | 'vw' | 'dpi' );
  NUMBER = '-'? num;
  HASH  = '#' name;
  HEX  = '#' [0-9a-fA-F]{1,6};
  PERCENTAGE = '-'? num '%';
  INCLUDES = '~=';
  DASHMATCH = '|=';
  PREFIXMATCH = '^=';
  SUFFIXMATCH = '$=';
  SUBSTRINGMATCH = '*=';
  PLUS = '+';
  GREATER = '>';
  COMMA = ',';
  TILDE = '~';
  S = space;

  # Property name
  property = ( QUOTED_STRING | IDENT );

  # Values
  important = space* '!' space* 'important';
  expression = ( ( '+' | PERCENTAGE | URL | ATTR | HEX | '-' | DIMENSION  | NUMBER | QUOTED_STRING | IDENT | ',') S* )+;
  functional_pseudo = (IDENT - ('attr'|'url')) '(' space* expression? ')';
  value = ( URL | ATTR | PLUS | HEX | PERCENTAGE | '-' | DIMENSION | NUMBER | QUOTED_STRING | IDENT | functional_pseudo);
  values = value (space value | '/' value )* ( space* ',' space* value (space value | '/' value )* )* important?;

  # Declaration definition
  declaration = (property space? ':'  (property ':')* space? values);

  # Selectors
  class = '.' IDENT;
  element_name = IDENT;
  namespace_prefix = ( IDENT | '*' )? '|';
  type_selector = namespace_prefix? element_name;
  universal = namespace_prefix? '*';
  attrib = '[' space* namespace_prefix? IDENT space* ( ( PREFIXMATCH  | SUFFIXMATCH | SUBSTRINGMATCH | '=' | INCLUDES | DASHMATCH ) space* ( IDENT | QUOTED_STRING ) space* )? ']';
  pseudo = ':' ':'? ( IDENT | functional_pseudo );
  atrule = '@' IDENT;
  mediaquery_selector = '(' declaration ')';
  negation_arg = type_selector
                 | universal
                 | HASH
                 | class
                 | attrib
                 | pseudo;
  negation = 'NOT'|'not' space* negation_arg space* ')';
  # Haha, so simple...
  # there should be also mediaquery_selector but it makes grammar too large, so rip it off
  simple_selector_sequence = ( type_selector | universal ) ( HASH | class | attrib | pseudo | negation | atrule )*
               | ( HASH | class | attrib | pseudo | negation | atrule )+;
  combinator = space* PLUS space*
           | space* GREATER space*
           | space* TILDE space*
           | space+;
  # Combine simple stuff and obtain just... an ordinary selector, bingo
  selector = simple_selector_sequence ( combinator simple_selector_sequence )*;
  # Multiple beasts
  selectors_group = selector ( COMMENT? ',' space* selector )*;

  # Rules
  # This is mostly used stuff
  rule = selectors_group space? "{" space*
        (COMMENT? space* declaration ( space? ";" space? declaration?)* ";"? space?)* COMMENT* space* '}';
  query_declaration = rule;

  # Areas used in css
  arearule = '@'('bottom-left'|'bottom-right'|'top-left'|'top-right');
  areaquery = arearule space? '{' space* (COMMENT? space* declaration ( S? ';' S? declaration?)* ';'? space?)* COMMENT* space* '}';
  # Printed media stuff, useless but we have to parse it :(
  printcssrule = '@media print';
  pagearea = ':'('left'|'right');
  pagerule = '@page' space? pagearea?;
  pagequery = pagerule space? '{' space* (areaquery| (COMMENT? space* declaration ( space? ';' space? declaration?)* ';'? S?)*) COMMENT* space* '}';
  printcssquery = printcssrule S? '{' ( S? COMMENT* S? (pagequery| COMMENT|query_declaration) S*)* S? '}';
  # Something that defines media
  conditions =  ('and'|'screen'|'or'|'only'|'not'|'amzn-mobi'|'amzn-kf8'|'amzn-mobi7'|',');
  mediarule = '@media' space conditions ( space? conditions| space?  mediaquery_selector )*;
  mediaquery = mediarule space? '{' ( space? COMMENT* query_declaration)* S? '}';

  simple_atrule  = ("@charset"|"@namespace") space+ QUOTED_STRING space* ";";

  import_rule = "@import" space+ ( QUOTED_STRING | URL ) space* ";";

  # Final css definition
  css_style = space* ( (  rule | simple_atrule | import_rule | mediaquery | printcssquery | COMMENT) space* )*;

}%%