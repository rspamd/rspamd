
typedef unsigned char byte;
typedef unsigned short symbol;

#define true 1
#define false 0
#define repeat while(true)
#define unless(C) if(!(C))
#define until(C) while(!(C))

#define MALLOC check_malloc
#define FREE check_free

#define NEW(type, p) struct type * p = (struct type *) MALLOC(sizeof(struct type))
#define NEWVEC(type, p, n) struct type * p = (struct type *) MALLOC(sizeof(struct type) * n)

#define STARTSIZE   10
#define SIZE(p)     ((int *)(p))[-1]
#define CAPACITY(p) ((int *)(p))[-2]

extern symbol * create_b(int n);
extern void report_b(FILE * out, symbol * p);
extern void lose_b(symbol * p);
extern symbol * increase_capacity(symbol * p, int n);
extern symbol * move_to_b(symbol * p, int n, symbol * q);
extern symbol * add_to_b(symbol * p, int n, symbol * q);
extern symbol * copy_b(symbol * p);
extern char * b_to_s(symbol * p);
extern symbol * add_s_to_b(symbol * p, const char * s);

struct str; /* defined in space.c */

extern struct str * str_new(void);
extern void str_delete(struct str * str);
extern void str_append(struct str * str, struct str * add);
extern void str_append_ch(struct str * str, char add);
extern void str_append_b(struct str * str, symbol * q);
extern void str_append_string(struct str * str, const char * s);
extern void str_append_int(struct str * str, int i);
extern void str_clear(struct str * str);
extern void str_assign(struct str * str, char * s);
extern struct str * str_copy(struct str * old);
extern symbol * str_data(struct str * str);
extern int str_len(struct str * str);
extern int get_utf8(const symbol * p, int * slot);
extern int put_utf8(int ch, symbol * p);

struct m_pair {

    struct m_pair * next;
    symbol * name;
    symbol * value;

};

/* struct input must be a prefix of struct tokeniser. */
struct input {

    struct input * next;
    symbol * p;
    int c;
    char * file;
    int line_number;

};

struct include {

    struct include * next;
    symbol * b;

};

/* struct input must be a prefix of struct tokeniser. */
struct tokeniser {

    struct input * next;
    symbol * p;
    int c;
    char * file;
    int line_number;
    symbol * b;
    symbol * b2;
    int number;
    int m_start;
    int m_end;
    struct m_pair * m_pairs;
    int get_depth;
    int error_count;
    int token;
    int previous_token;
    byte token_held;
    byte widechars;
    byte utf8;

    int omission;
    struct include * includes;

};

extern symbol * get_input(symbol * p, char ** p_file);
extern struct tokeniser * create_tokeniser(symbol * b, char * file);
extern int read_token(struct tokeniser * t);
extern const char * name_of_token(int code);
extern void close_tokeniser(struct tokeniser * t);

enum token_codes {

#include "syswords2.h"

    c_mathassign,
    c_name,
    c_number,
    c_literalstring,
    c_neg,
    c_call,
    c_grouping,
    c_booltest
};

extern int space_count;
extern void * check_malloc(int n);
extern void check_free(void * p);

struct node;

struct name {

    struct name * next;
    symbol * b;
    int type;                   /* t_string etc */
    int mode;                   /*    )_  for routines, externals */
    struct node * definition;   /*    )                           */
    int count;                  /* 0, 1, 2 for each type */
    struct grouping * grouping; /* for grouping names */
    byte referenced;
    byte used;

};

struct literalstring {

    struct literalstring * next;
    symbol * b;

};

struct amongvec {

    symbol * b;      /* the string giving the case */
    int size;        /* - and its size */
    struct node * p; /* the corresponding command */
    int i;           /* the amongvec index of the longest substring of b */
    int result;      /* the numeric result for the case */
    struct name * function;

};

struct among {

    struct among * next;
    struct amongvec * b;      /* pointer to the amongvec */
    int number;               /* amongs are numbered 0, 1, 2 ... */
    int literalstring_count;  /* in this among */
    int command_count;        /* in this among */
    struct node * starter;    /* i.e. among( (starter) 'string' ... ) */
    struct node * substring;  /* i.e. substring ... among ( ... ) */
};

struct grouping {

    struct grouping * next;
    int number;               /* groupings are numbered 0, 1, 2 ... */
    symbol * b;               /* the characters of this group */
    int largest_ch;           /* character with max code */
    int smallest_ch;          /* character with min code */
    byte no_gaps;             /* not used in generator.c after 11/5/05 */
    struct name * name;       /* so g->name->grouping == g */
};

struct node {

    struct node * next;
    struct node * left;
    struct node * aux;     /* used in setlimit */
    struct among * among;  /* used in among */
    struct node * right;
    int type;
    int mode;
    struct node * AE;
    struct name * name;
    symbol * literalstring;
    int number;
    int line_number;
    int amongvar_needed;   /* used in routine definitions */
};

enum name_types {

    t_size = 6,

    t_string = 0, t_boolean = 1, t_integer = 2, t_routine = 3, t_external = 4,
    t_grouping = 5

/*  If this list is extended, adjust wvn in generator.c  */
};

/*  In name_count[i] below, remember that
    type   is
    ----+----
      0 |  string
      1 |  boolean
      2 |  integer
      3 |  routine
      4 |  external
      5 |  grouping
*/

struct analyser {

    struct tokeniser * tokeniser;
    struct node * nodes;
    struct name * names;
    struct literalstring * literalstrings;
    int mode;
    byte modifyable;          /* false inside reverse(...) */
    struct node * program;
    struct node * program_end;
    int name_count[t_size];   /* name_count[i] counts the number of names of type i */
    struct among * amongs;
    struct among * amongs_end;
    int among_count;
    int amongvar_needed;      /* used in reading routine definitions */
    struct grouping * groupings;
    struct grouping * groupings_end;
    struct node * substring;  /* pending 'substring' in current routine definition */
    byte utf8;
};

enum analyser_modes {

    m_forward = 0, m_backward /*, m_integer */

};

extern void print_program(struct analyser * a);
extern struct analyser * create_analyser(struct tokeniser * t);
extern void close_analyser(struct analyser * a);

extern void read_program(struct analyser * a);

struct generator {

    struct analyser * analyser;
    struct options * options;
    int unreachable;           /* 0 if code can be reached, 1 if current code
                                * is unreachable. */
    int var_number;            /* Number of next variable to use. */
    struct str * outbuf;       /* temporary str to store output */
    struct str * declarations; /* str storing variable declarations */
    int next_label;
    int margin;

    const char * failure_string;     /* String to output in case of a failure. */
#ifndef DISABLE_JAVA
    struct str * failure_str;  /* This is used by the java generator instead of failure_string */
#endif

    int label_used;     /* Keep track of whether the failure label is used. */
    int failure_label;
    int debug_count;

    const char * S[10];  /* strings */
    symbol * B[10];      /* blocks */
    int I[10];           /* integers */
    struct name * V[5];  /* variables */
    symbol * L[5];       /* literals, used in formatted write */

    int line_count;      /* counts number of lines output */
    int line_labelled;   /* in ANSI C, will need extra ';' if it is a block end */
    int literalstring_count;
    int keep_count;      /* used to number keep/restore pairs to avoid compiler warnings
                            about shadowed variables */
};

struct options {

    /* for the command line: */

    char * output_file;
    char * name;
    FILE * output_c;
    FILE * output_h;
#ifndef DISABLE_JAVA
    FILE * output_java;
#endif
    byte syntax_tree;
    byte widechars;
    enum { LANG_JAVA, LANG_C, LANG_CPLUSPLUS } make_lang;
    char * externals_prefix;
    char * variables_prefix;
    char * runtime_path;
    char * parent_class_name;
    char * package;
    char * string_class;
    char * among_class;
    struct include * includes;
    struct include * includes_end;
    byte utf8;
};

/* Generator for C code. */
extern struct generator * create_generator_c(struct analyser * a, struct options * o);
extern void close_generator_c(struct generator * g);

extern void generate_program_c(struct generator * g);

#ifndef DISABLE_JAVA
/* Generator for Java code. */
extern struct generator * create_generator_java(struct analyser * a, struct options * o);
extern void close_generator_java(struct generator * g);

extern void generate_program_java(struct generator * g);
#endif
