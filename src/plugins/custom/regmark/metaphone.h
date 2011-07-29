#ifndef RSPAMD_METAPHONE_H
#define RSPAMD_METAPHONE_H

#include "config.h"


#define ENCODE(c) (g_ascii_isalpha(c) ? _codes[((g_ascii_toupper(c)) - 'A')] : 0)

#define isvowel(c)	(ENCODE(c) & 1)		/* AEIOU */

/* These letters are passed through unchanged */
#define NOCHANGE(c)	(ENCODE(c) & 2) 	/* FJMNR */

/* These form dipthongs when preceding H */
#define AFFECTH(c)	(ENCODE(c) & 4) 	/* CGPST */

/* These make C and G soft */
#define MAKESOFT(c)	(ENCODE(c) & 8) 	/* EIY */

/* These prevent GH from becoming F */
#define NOGHTOF(c)	(ENCODE(c) & 16) 	/* BDH */

#undef USE_TRADITIONAL_METAPHONE

gboolean metaphone (char *word, int max_phonemes, char **phoned_word);

#endif
