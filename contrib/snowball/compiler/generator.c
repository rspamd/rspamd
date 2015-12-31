
#include <limits.h>  /* for INT_MAX */
#include <stdio.h>   /* for fprintf etc */
#include <stdlib.h>  /* for free etc */
#include <string.h>  /* for strlen */
#include "header.h"

/* Define this to get warning messages when optimisations can't be used. */
/* #define OPTIMISATION_WARNINGS */

/* recursive use: */

static void generate(struct generator * g, struct node * p);

enum special_labels {

    x_return = -1

};

static int new_label(struct generator * g) {
    return g->next_label++;
}

/* Output routines */
static void output_str(FILE * outfile, struct str * str) {

    char * s = b_to_s(str_data(str));
    fprintf(outfile, "%s", s);
    free(s);
}

static void wch(struct generator * g, int ch) {
    str_append_ch(g->outbuf, ch); /* character */
}

static void wnl(struct generator * g) {
    str_append_ch(g->outbuf, '\n'); /* newline */
    g->line_count++;
}

static void ws(struct generator * g, const char * s) {
    str_append_string(g->outbuf, s); /* string */
}

static void wi(struct generator * g, int i) {
    str_append_int(g->outbuf, i); /* integer */
}

static void wh_ch(struct generator * g, int i) {
    str_append_ch(g->outbuf, "0123456789ABCDEF"[i & 0xF]); /* hexchar */
}

static void wh(struct generator * g, int i) {
    if (i >> 4) wh(g, i >> 4);
    wh_ch(g, i); /* hex integer */
}

static void wi3(struct generator * g, int i) {
    if (i < 100) wch(g, ' ');
    if (i < 10)  wch(g, ' ');
    wi(g, i); /* integer (width 3) */
}

static void wvn(struct generator * g, struct name * p) {  /* variable name */

    int ch = "SBIrxg"[p->type];
    switch (p->type) {
        case t_string:
        case t_boolean:
        case t_integer:
            wch(g, ch); wch(g, '['); wi(g, p->count); wch(g, ']'); return;
        case t_external:
            ws(g, g->options->externals_prefix); break;
        default:
            wch(g, ch); wch(g, '_');
    }
    str_append_b(g->outbuf, p->b);
}

static void wv(struct generator * g, struct name * p) {  /* reference to variable */
    if (p->type < t_routine) ws(g, "z->");
    wvn(g, p);
}

static void wlitarray(struct generator * g, symbol * p) {  /* write literal array */

    ws(g, "{ ");
    {
        int i;
        for (i = 0; i < SIZE(p); i++) {
            int ch = p[i];
            if (32 <= ch && ch < 127) {
                wch(g, '\'');
                switch (ch) {
                    case '\'':
                    case '\\': wch(g, '\\');
                    default:   wch(g, ch);
                }
                wch(g, '\'');
            }  else {
                wch(g, '0'); wch(g, 'x'); wh(g, ch);
            }
            if (i < SIZE(p) - 1) ws(g, ", ");
        }
    }
    ws(g, " }");
}

static void wlitref(struct generator * g, symbol * p) {  /* write ref to literal array */

    if (SIZE(p) == 0) ws(g, "0"); else {
        struct str * s = g->outbuf;
        g->outbuf = g->declarations;
        ws(g, "static const symbol s_"); wi(g, g->literalstring_count); ws(g, "[] = ");
        wlitarray(g, p);
        ws(g, ";\n");
        g->outbuf = s;
        ws(g, "s_"); wi(g, g->literalstring_count);
        g->literalstring_count++;
    }
}


static void wm(struct generator * g) {       /* margin */
    int i;
    for (i = 0; i < g->margin; i++) ws(g, "    ");
}

static void wc(struct generator * g, struct node * p) { /* comment */

    ws(g, " /* ");
    switch (p->type) {
        case c_mathassign:
        case c_plusassign:
        case c_minusassign:
        case c_multiplyassign:
        case c_divideassign:
        case c_eq:
        case c_ne:
        case c_gr:
        case c_ge:
        case c_ls:
        case c_le:
            if (p->name) {
                wch(g, '$');
                str_append_b(g->outbuf, p->name->b);
                wch(g, ' ');
            }
            ws(g, name_of_token(p->type));
            ws(g, " <integer expression>");
            break;
        default:
            ws(g, name_of_token(p->type));
            if (p->name) {
                wch(g, ' ');
                str_append_b(g->outbuf, p->name->b);
            }
    }
    ws(g, ", line "); wi(g, p->line_number); ws(g, " */");
    wnl(g);
}

static void wms(struct generator * g, const char * s) {
    wm(g); ws(g, s);   } /* margin + string */

static void wbs(struct generator * g) { /* block start */
    wms(g, "{   ");
    g->margin++;
}

static void wbe(struct generator * g) {    /* block end */

    if (g->line_labelled == g->line_count) { wms(g, ";"); wnl(g); }
    g->margin--;
    wms(g, "}"); wnl(g);
}

static void wk(struct generator * g, struct node * p) {     /* keep c */
    ++g->keep_count;
    if (p->mode == m_forward) {
        ws(g, "int c"); wi(g, g->keep_count); ws(g, " = z->c;");
    } else {
        ws(g, "int m"); wi(g, g->keep_count); ws(g, " = z->l - z->c; (void)m");
        wi(g, g->keep_count); ws(g, ";");
    }
}

static void wrestore(struct generator * g, struct node * p, int keep_token) {     /* restore c */
    if (p->mode == m_forward) {
        ws(g, "z->c = c");
    } else {
        ws(g, "z->c = z->l - m");
    }
    wi(g, keep_token); ws(g, ";");
}

static void winc(struct generator * g, struct node * p) {     /* increment c */
    ws(g, p->mode == m_forward ? "z->c++;" :
                                 "z->c--;");
}

static void wsetl(struct generator * g, int n) {

    g->margin--;
    wms(g, "lab"); wi(g, n); wch(g, ':'); wnl(g);
    g->line_labelled = g->line_count;
    g->margin++;
}

static void wgotol(struct generator * g, int n) {
    wms(g, "goto lab"); wi(g, n); wch(g, ';'); wnl(g);
}

static void wf(struct generator * g) {          /* fail */
    if (g->failure_string != 0) { ws(g, "{ "); ws(g, g->failure_string); wch(g, ' '); }
    switch (g->failure_label)
    {
        case x_return:
           ws(g, "return 0;");
           break;
        default:
           ws(g, "goto lab");
           wi(g, g->failure_label);
           wch(g, ';');
           g->label_used = 1;
    }
    if (g->failure_string != 0) ws(g, " }");
}

static void wlim(struct generator * g, struct node * p) {     /* if at limit fail */

    ws(g, p->mode == m_forward ? "if (z->c >= z->l) " :
                                 "if (z->c <= z->lb) ");
    wf(g);
}

static void wp(struct generator * g, const char * s, struct node * p) { /* formatted write */
    int i = 0;
    int l = strlen(s);
    until (i >= l) {
        int ch = s[i++];
        if (ch != '~') wch(g, ch); else
        switch(s[i++]) {
            default:  wch(g, s[i - 1]); continue;
            case 'C': wc(g, p); continue;
            case 'k': wk(g, p); continue;
            case 'K': /* keep for c_test */
                ws(g, p->mode == m_forward ? "int c_test = z->c;" :
                                             "int m_test = z->l - z->c;");
                continue;
            case 'R': /* restore for c_test */
                ws(g, p->mode == m_forward ? "z->c = c_test;" :
                                             "z->c = z->l - m_test;");
                continue;
            case 'i': winc(g, p); continue;
            case 'l': wlim(g, p); continue;
            case 'f': wf(g); continue;
            case 'M': wm(g); continue;
            case 'N': wnl(g); continue;
            case '{': wbs(g); continue;
            case '}': wbe(g); continue;
            case 'S': ws(g, g->S[s[i++] - '0']); continue;
            case 'I': wi(g, g->I[s[i++] - '0']); continue;
            case 'J': wi3(g, g->I[s[i++] - '0']); continue;
            case 'V': wv(g, g->V[s[i++] - '0']); continue;
            case 'W': wvn(g, g->V[s[i++] - '0']); continue;
            case 'L': wlitref(g, g->L[s[i++] - '0']); continue;
            case 'A': wlitarray(g, g->L[s[i++] - '0']); continue;
            case '+': g->margin++; continue;
            case '-': g->margin--; continue;
            case '$': /* insert_s, insert_v etc */
                wch(g, p->literalstring == 0 ? 'v' : 's');
                continue;
            case 'p': ws(g, g->options->externals_prefix); continue;
        }
    }
}

static void w(struct generator * g, const char * s) { wp(g, s, 0); }

static void generate_AE(struct generator * g, struct node * p) {
    char * s;
    switch (p->type) {
        case c_name:
            wv(g, p->name); break;
        case c_number:
            wi(g, p->number); break;
        case c_maxint:
            ws(g, "MAXINT"); break;
        case c_minint:
            ws(g, "MININT"); break;
        case c_neg:
            wch(g, '-'); generate_AE(g, p->right); break;
        case c_multiply:
            s = " * "; goto label0;
        case c_plus:
            s = " + "; goto label0;
        case c_minus:
            s = " - "; goto label0;
        case c_divide:
            s = " / ";
        label0:
            wch(g, '('); generate_AE(g, p->left);
            ws(g, s); generate_AE(g, p->right); wch(g, ')'); break;
        case c_sizeof:
            g->V[0] = p->name;
            w(g, "SIZE(~V0)"); break;
        case c_cursor:
            w(g, "z->c"); break;
        case c_limit:
            w(g, p->mode == m_forward ? "z->l" : "z->lb"); break;
        case c_size:
            w(g, "SIZE(z->p)"); break;
    }
}

/* K_needed() tests to see if we really need to keep c. Not true when the
   the command does not touch the cursor. This and repeat_score() could be
   elaborated almost indefinitely.
*/

static int K_needed(struct generator * g, struct node * p) {
    until (p == 0) {
        switch (p->type) {
            case c_dollar:
            case c_leftslice:
            case c_rightslice:
            case c_mathassign:
            case c_plusassign:
            case c_minusassign:
            case c_multiplyassign:
            case c_divideassign:
            case c_eq:
            case c_ne:
            case c_gr:
            case c_ge:
            case c_ls:
            case c_le:
            case c_sliceto:
            case c_true:
            case c_false:
            case c_debug:
                break;

            case c_call:
                if (K_needed(g, p->name->definition)) return true;
                break;

            case c_bra:
                if (K_needed(g, p->left)) return true;
                break;

            default: return true;
        }
        p = p->right;
    }
    return false;
}

static int repeat_score(struct generator * g, struct node * p) {
    int score = 0;
    until (p == 0)
    {
        switch (p->type) {
            case c_dollar:
            case c_leftslice:
            case c_rightslice:
            case c_mathassign:
            case c_plusassign:
            case c_minusassign:
            case c_multiplyassign:
            case c_divideassign:
            case c_eq:
            case c_ne:
            case c_gr:
            case c_ge:
            case c_ls:
            case c_le:
            case c_sliceto:   /* case c_not: must not be included here! */
            case c_debug:
                break;

            case c_call:
                score += repeat_score(g, p->name->definition);
                break;

            case c_bra:
                score += repeat_score(g, p->left);
                break;

            case c_name:
            case c_literalstring:
            case c_next:
            case c_grouping:
            case c_non:
            case c_hop:
                score = score + 1; break;

            default: score = 2; break;
        }
        p = p->right;
    }
    return score;
}

/* tests if an expression requires cursor reinstatement in a repeat */

static int repeat_restore(struct generator * g, struct node * p) {
    return repeat_score(g, p) >= 2;
}

static void generate_bra(struct generator * g, struct node * p) {
    p = p->left;
    until (p == 0) { generate(g, p); p = p->right; }
}

static void generate_and(struct generator * g, struct node * p) {
    int keep_c = 0;
    if (K_needed(g, p->left)) {
        wp(g, "~{~k~C", p);
        keep_c = g->keep_count;
    } else {
        wp(g, "~M~C", p);
    }
    p = p->left;
    until (p == 0) {
        generate(g, p);
        if (keep_c && p->right != 0) {
            w(g, "~M"); wrestore(g, p, keep_c); w(g, "~N");
        }
        p = p->right;
    }
    if (keep_c) w(g, "~}");
}

static void generate_or(struct generator * g, struct node * p) {
    int keep_c = 0;

    int used = g->label_used;
    int a0 = g->failure_label;
    const char * a1 = g->failure_string;

    int out_lab = new_label(g);

    if (K_needed(g, p->left)) {
        wp(g, "~{~k~C", p);
        keep_c = g->keep_count;
    } else {
        wp(g, "~M~C", p);
    }
    p = p->left;
    g->failure_string = 0;
    until (p->right == 0) {
        g->failure_label = new_label(g);
        g->label_used = 0;
        generate(g, p);
        wgotol(g, out_lab);
        if (g->label_used)
            wsetl(g, g->failure_label);
        if (keep_c) {
            w(g, "~M"); wrestore(g, p, keep_c); w(g, "~N");
        }
        p = p->right;
    }
    g->label_used = used;
    g->failure_label = a0;
    g->failure_string = a1;

    generate(g, p);
    if (keep_c) w(g, "~}");
    wsetl(g, out_lab);
}

static void generate_backwards(struct generator * g, struct node * p) {

    wp(g,"~Mz->lb = z->c; z->c = z->l;~C~N", p);
    generate(g, p->left);
    w(g, "~Mz->c = z->lb;~N");
}


static void generate_not(struct generator * g, struct node * p) {
    int keep_c = 0;

    int used = g->label_used;
    int a0 = g->failure_label;
    const char * a1 = g->failure_string;

    if (K_needed(g, p->left)) {
        wp(g, "~{~k~C", p);
        keep_c = g->keep_count;
    } else {
        wp(g, "~M~C", p);
    }

    g->failure_label = new_label(g);
    g->label_used = 0;
    g->failure_string = 0;
    generate(g, p->left);

    {
        int l = g->failure_label;
        int u = g->label_used;

        g->label_used = used;
        g->failure_label = a0;
        g->failure_string = a1;

        w(g, "~M~f~N");
        if (u)
            wsetl(g, l);
    }
    if (keep_c) {
        w(g, "~M"); wrestore(g, p, keep_c); w(g, "~N~}");
    }
}


static void generate_try(struct generator * g, struct node * p) {
    int keep_c = K_needed(g, p->left);

    if (keep_c) {
        if (p->mode == m_forward) {
            wp(g, "~{int c_keep = z->c;~C", p);
            g->failure_string = "z->c = c_keep;";
        } else {
            wp(g, "~{int m_keep = z->l - z->c;/* (void) m_keep;*/~C", p);
            g->failure_string = "z->c = z->l - m_keep;";
        }
    } else {
        wp(g, "~M~C", p);
        g->failure_string = 0;
    }

    g->failure_label = new_label(g);
    g->label_used = 0;
    generate(g, p->left);

    if (g->label_used)
        wsetl(g, g->failure_label);

    if (keep_c) w(g, "~}");
}

static void generate_set(struct generator * g, struct node * p) {
    g->V[0] = p->name; wp(g, "~M~V0 = 1;~C", p);
}

static void generate_unset(struct generator * g, struct node * p) {
    g->V[0] = p->name; wp(g, "~M~V0 = 0;~C", p);
}

static void generate_fail(struct generator * g, struct node * p) {
    generate(g, p->left);
    wp(g, "~M~f~C", p);
}

/* generate_test() also implements 'reverse' */

static void generate_test(struct generator * g, struct node * p) {
    int keep_c = K_needed(g, p->left);
    if (keep_c) wp(g, "~{~K~C", p);
           else wp(g, "~M~C", p);

    generate(g, p->left);

    if (keep_c) wp(g, "~M~R~N"
                   "~}", p);
}

static void generate_do(struct generator * g, struct node * p) {
    int keep_c = 0;
    if (K_needed(g, p->left)) {
        wp(g, "~{~k~C", p);
        keep_c = g->keep_count;
    } else {
        wp(g, "~M~C", p);
    }

    g->failure_label = new_label(g);
    g->label_used = 0;
    g->failure_string = 0;
    generate(g, p->left);

    if (g->label_used)
        wsetl(g, g->failure_label);
    if (keep_c) {
        w(g, "~M"); wrestore(g, p, keep_c);
        w(g, "~N~}");
    }
}

static void generate_next(struct generator * g, struct node * p) {
    if (g->options->utf8) {
        if (p->mode == m_forward)
            w(g, "~{int ret = skip_utf8(z->p, z->c, 0, z->l, 1");
        else
            w(g, "~{int ret = skip_utf8(z->p, z->c, z->lb, 0, -1");
        wp(g, ");~N"
              "~Mif (ret < 0) ~f~N"
              "~Mz->c = ret;~C"
              "~}", p);
    } else
        wp(g, "~M~l~N"
              "~M~i~C", p);
}

static void generate_GO_grouping(struct generator * g, struct node * p, int is_goto, int complement) {

    struct grouping * q = p->name->grouping;
    g->S[0] = p->mode == m_forward ? "" : "_b";
    g->S[1] = complement ? "in" : "out";
    g->S[2] = g->options->utf8 ? "_U" : "";
    g->V[0] = p->name;
    g->I[0] = q->smallest_ch;
    g->I[1] = q->largest_ch;
    if (is_goto) {
	wp(g, "~Mif (~S1_grouping~S0~S2(z, ~V0, ~I0, ~I1, 1) < 0) ~f /* goto */~C", p);
    } else {
	wp(g, "~{ /* gopast */~C"
	      "~Mint ret = ~S1_grouping~S0~S2(z, ~V0, ~I0, ~I1, 1);~N"
	      "~Mif (ret < 0) ~f~N", p);
	if (p->mode == m_forward)
	    w(g, "~Mz->c += ret;~N");
	else
	    w(g, "~Mz->c -= ret;~N");
	w(g, "~}");
    }
}

static void generate_GO(struct generator * g, struct node * p, int style) {
    int keep_c = 0;

    int used = g->label_used;
    int a0 = g->failure_label;
    const char * a1 = g->failure_string;

    if (p->left->type == c_grouping || p->left->type == c_non) {
	/* Special case for "goto" or "gopast" when used on a grouping or an
	 * inverted grouping - the movement of c by the matching action is
	 * exactly what we want! */
#ifdef OPTIMISATION_WARNINGS
	printf("Optimising %s %s\n", style ? "goto" : "gopast", p->left->type == c_non ? "non" : "grouping");
#endif
	generate_GO_grouping(g, p->left, style, p->left->type == c_non);
	return;
    }

    w(g, "~Mwhile(1) {"); wp(g, "~C~+", p);

    if (style == 1 || repeat_restore(g, p->left)) {
        wp(g, "~M~k~N", p);
        keep_c = g->keep_count;
    }

    g->failure_label = new_label(g);
    g->label_used = 0;
    generate(g, p->left);

    if (style == 1) {
        /* include for goto; omit for gopast */
        w(g, "~M"); wrestore(g, p, keep_c); w(g, "~N");
    }
    w(g, "~Mbreak;~N");
    if (g->label_used)
        wsetl(g, g->failure_label);
    if (keep_c) {
        w(g, "~M"); wrestore(g, p, keep_c); w(g, "~N");
    }

    g->label_used = used;
    g->failure_label = a0;
    g->failure_string = a1;

/*  wp(g, "~M~l~N"
          "~M~i~N", p);  */
    generate_next(g, p);
    w(g, "~}");
}

static void generate_loop(struct generator * g, struct node * p) {
    w(g, "~{int i; for (i = "); generate_AE(g, p->AE); wp(g, "; i > 0; i--)~C"
            "~{", p);

    generate(g, p->left);

    w(g,    "~}"
         "~}");
}

static void generate_repeat(struct generator * g, struct node * p, int atleast_case) {
    int keep_c = 0;
    wp(g, "~Mwhile(1) {~C~+", p);

    if (repeat_restore(g, p->left)) {
        wp(g, "~M~k~N", p);
        keep_c = g->keep_count;
    }

    g->failure_label = new_label(g);
    g->label_used = 0;
    g->failure_string = 0;
    generate(g, p->left);

    if (atleast_case) w(g, "~Mi--;~N");

    w(g, "~Mcontinue;~N");
    if (g->label_used)
        wsetl(g, g->failure_label);

    if (keep_c) {
        w(g, "~M"); wrestore(g, p, keep_c); w(g, "~N");
    }

    w(g, "~Mbreak;~N"
      "~}");
}

static void generate_atleast(struct generator * g, struct node * p) {
    w(g, "~{int i = "); generate_AE(g, p->AE); w(g, ";~N");
    {
        int used = g->label_used;
        int a0 = g->failure_label;
        const char * a1 = g->failure_string;

        generate_repeat(g, p, true);

        g->label_used = used;
        g->failure_label = a0;
        g->failure_string = a1;
    }
    w(g, "~Mif (i > 0) ~f~N"
      "~}");
}

static void generate_setmark(struct generator * g, struct node * p) {
    g->V[0] = p->name;
    wp(g, "~M~V0 = z->c;~C", p);
}

static void generate_tomark(struct generator * g, struct node * p) {
    g->S[0] = p->mode == m_forward ? ">" : "<";

    w(g, "~Mif (z->c ~S0 "); generate_AE(g, p->AE); w(g, ") ~f~N");
    w(g, "~Mz->c = "); generate_AE(g, p->AE); wp(g, ";~C", p);
}

static void generate_atmark(struct generator * g, struct node * p) {

    w(g, "~Mif (z->c != "); generate_AE(g, p->AE); wp(g, ") ~f~C", p);
}

static void generate_hop(struct generator * g, struct node * p) {
    g->S[0] = p->mode == m_forward ? "+" : "-";
    g->S[1] = p->mode == m_forward ? "0" : "z->lb";
    if (g->options->utf8) {
        w(g, "~{int ret = skip_utf8(z->p, z->c, ~S1, z->l, ~S0 ");
        generate_AE(g, p->AE); wp(g, ");~C", p);
        w(g, "~Mif (ret < 0) ~f~N");
    } else {
        w(g, "~{int ret = z->c ~S0 ");
        generate_AE(g, p->AE); wp(g, ";~C", p);
        w(g, "~Mif (~S1 > ret || ret > z->l) ~f~N");
    }
    wp(g, "~Mz->c = ret;~C"
          "~}", p);
}

static void generate_delete(struct generator * g, struct node * p) {
    wp(g, "~{int ret = slice_del(z);~C", p);
    wp(g, "~Mif (ret < 0) return ret;~N"
          "~}", p);
}

static void generate_tolimit(struct generator * g, struct node * p) {
    g->S[0] = p->mode == m_forward ? "" : "b";
    wp(g, "~Mz->c = z->l~S0;~C", p);
}

static void generate_atlimit(struct generator * g, struct node * p) {
    g->S[0] = p->mode == m_forward ? "" : "b";
    g->S[1] = p->mode == m_forward ? "<" : ">";
    wp(g, "~Mif (z->c ~S1 z->l~S0) ~f~C", p);
}

static void generate_leftslice(struct generator * g, struct node * p) {
    g->S[0] = p->mode == m_forward ? "bra" : "ket";
    wp(g, "~Mz->~S0 = z->c;~C", p);
}

static void generate_rightslice(struct generator * g, struct node * p) {
    g->S[0] = p->mode == m_forward ? "ket" : "bra";
    wp(g, "~Mz->~S0 = z->c;~C", p);
}

static void generate_assignto(struct generator * g, struct node * p) {
    g->V[0] = p->name;
    wp(g, "~M~V0 = assign_to(z, ~V0);~C"
          "~Mif (~V0 == 0) return -1;~C", p);
}

static void generate_sliceto(struct generator * g, struct node * p) {
    g->V[0] = p->name;
    wp(g, "~M~V0 = slice_to(z, ~V0);~C"
          "~Mif (~V0 == 0) return -1;~C", p);
}

static void generate_data_address(struct generator * g, struct node * p) {

    symbol * b = p->literalstring;
    if (b != 0) {
        wi(g, SIZE(b)); w(g, ", ");
        wlitref(g, b);
    } else
        wv(g, p->name);
}

static void generate_insert(struct generator * g, struct node * p, int style) {

    int keep_c = style == c_attach;
    if (p->mode == m_backward) keep_c = !keep_c;
    wp(g, "~{", p);
    if (keep_c) w(g, "int c_keep = z->c;~N~M");
    wp(g, "int ret = insert_~$(z, z->c, z->c, ", p);
    generate_data_address(g, p);
    wp(g, ");~C", p);
    if (keep_c) w(g, "~Mz->c = c_keep;~N");
    wp(g, "~Mif (ret < 0) return ret;~N"
          "~}", p);
}

static void generate_assignfrom(struct generator * g, struct node * p) {

    int keep_c = p->mode == m_forward; /* like 'attach' */
    wp(g, "~{", p);
    if (keep_c) wp(g, "int c_keep = z->c;~N"
                   "~Mret = insert_~$(z, z->c, z->l, ", p);
                else wp(g, "ret = insert_~$(z, z->lb, z->c, ", p);
    generate_data_address(g, p);
    wp(g, ");~C", p);
    if (keep_c) w(g, "~Mz->c = c_keep;~N");
    wp(g, "~Mif (ret < 0) return ret;~N"
          "~}", p);
}

/* bugs marked <======= fixed 22/7/02. Similar fixes required for Java */

static void generate_slicefrom(struct generator * g, struct node * p) {

/*  w(g, "~Mslice_from_s(z, ");   <============= bug! should be: */
    wp(g, "~{int ret = slice_from_~$(z, ", p);
    generate_data_address(g, p);
    wp(g, ");~C", p);
    wp(g, "~Mif (ret < 0) return ret;~N"
          "~}", p);
}

static void generate_setlimit(struct generator * g, struct node * p) {
    int keep_c;
    wp(g, "~{int mlimit;~C"
          "~M~k~N"
          , p);
    keep_c = g->keep_count;
    generate(g, p->left);
    if (p->mode == m_forward) w(g, "~Mmlimit = z->l - z->c; z->l = z->c;~N");
                         else w(g, "~Mmlimit = z->lb; z->lb = z->c;~N");
    w(g, "~M"); wrestore(g, p, keep_c); w(g, "~N");
    g->failure_string = p->mode == m_forward ? "z->l += mlimit;" :
                                               "z->lb = mlimit;";
    generate(g, p->aux);
    wms(g, g->failure_string);
    w(g, "~N"
      "~}");
}

static void generate_dollar(struct generator * g, struct node * p) {

    int used = g->label_used;
    int a0 = g->failure_label;
    const char * a1 = g->failure_string;
    g->failure_label = new_label(g);
    g->label_used = 0;
    g->failure_string = 0;

    g->V[0] = p->name;
    wp(g, "~{struct SN_env env = * z;~C"
             "~Mint failure = 1; /* assume failure */~N"
             "~Mz->p = ~V0;~N"
             "~Mz->lb = z->c = 0;~N"
             "~Mz->l = SIZE(z->p);~N", p);
    generate(g, p->left);
    w(g, "~Mfailure = 0; /* mark success */~N");
    if (g->label_used)
        wsetl(g, g->failure_label);
    g->V[0] = p->name; /* necessary */

    g->label_used = used;
    g->failure_label = a0;
    g->failure_string = a1;

    w(g, "~M~V0 = z->p;~N"
         "~M* z = env;~N"
         "~Mif (failure) ~f~N~}");
}

static void generate_integer_assign(struct generator * g, struct node * p, char * s) {

    g->V[0] = p->name;
    g->S[0] = s;
    w(g, "~M~V0 ~S0 "); generate_AE(g, p->AE); wp(g, ";~C", p);
}

static void generate_integer_test(struct generator * g, struct node * p, char * s) {

    g->V[0] = p->name;
    g->S[0] = s;
    w(g, "~Mif (!(~V0 ~S0 "); generate_AE(g, p->AE); wp(g, ")) ~f~C", p);
}

static void generate_call(struct generator * g, struct node * p) {

    g->V[0] = p->name;
    wp(g, "~{int ret = ~V0(z);~C"
          "~Mif (ret == 0) ~f~N"
          "~Mif (ret < 0) return ret;~N~}", p);
}

static void generate_grouping(struct generator * g, struct node * p, int complement) {

    struct grouping * q = p->name->grouping;
    g->S[0] = p->mode == m_forward ? "" : "_b";
    g->S[1] = complement ? "out" : "in";
    g->S[2] = g->options->utf8 ? "_U" : "";
    g->V[0] = p->name;
    g->I[0] = q->smallest_ch;
    g->I[1] = q->largest_ch;
    wp(g, "~Mif (~S1_grouping~S0~S2(z, ~V0, ~I0, ~I1, 0)) ~f~C", p);
}

static void generate_namedstring(struct generator * g, struct node * p) {

    g->S[0] = p->mode == m_forward ? "" : "_b";
    g->V[0] = p->name;
    wp(g, "~Mif (!(eq_v~S0(z, ~V0))) ~f~C", p);
}

static void generate_literalstring(struct generator * g, struct node * p) {
    symbol * b = p->literalstring;
    g->S[0] = p->mode == m_forward ? "" : "_b";
    g->I[0] = SIZE(b);
    g->L[0] = b;

    wp(g, "~Mif (!(eq_s~S0(z, ~I0, ~L0))) ~f~C", p);
}

static void generate_define(struct generator * g, struct node * p) {
    struct name * q = p->name;
    g->next_label = 0;

    g->S[0] = q->type == t_routine ? "static" : "extern";
    g->V[0] = q;

    w(g, "~N~S0 int ~V0(struct SN_env * z) {~N~+");
    if (p->amongvar_needed) w(g, "~Mint among_var;~N");
    g->failure_string = 0;
    g->failure_label = x_return;
    g->label_used = 0;
    g->keep_count = 0;
    generate(g, p->left);
    w(g, "~Mreturn 1;~N~}");
}

static void generate_substring(struct generator * g, struct node * p) {

    struct among * x = p->among;
    int block = -1;
    unsigned int bitmap = 0;
    struct amongvec * among_cases = x->b;
    int c;
    int empty_case = -1;
    int n_cases = 0;
    symbol cases[2];
    int shortest_size = INT_MAX;

    g->S[0] = p->mode == m_forward ? "" : "_b";
    g->I[0] = x->number;
    g->I[1] = x->literalstring_count;

    /* In forward mode with non-ASCII UTF-8 characters, the first character
     * of the string will often be the same, so instead look at the last
     * common character position.
     *
     * In backward mode, we can't match if there are fewer characters before
     * the current position than the minimum length.
     */
    for (c = 0; c < x->literalstring_count; ++c) {
        int size = among_cases[c].size;
        if (size != 0 && size < shortest_size) {
            shortest_size = size;
        }
    }

    for (c = 0; c < x->literalstring_count; ++c) {
        symbol ch;
        if (among_cases[c].size == 0) {
            empty_case = c;
            continue;
        }
        if (p->mode == m_forward) {
            ch = among_cases[c].b[shortest_size - 1];
        } else {
            ch = among_cases[c].b[among_cases[c].size - 1];
        }
        if (n_cases == 0) {
            block = ch >> 5;
        } else if (ch >> 5 != block) {
            block = -1;
            if (n_cases > 2) break;
        }
        if (block == -1) {
            if (ch == cases[0]) continue;
            if (n_cases < 2) {
            cases[n_cases++] = ch;
            } else if (ch != cases[1]) {
            ++n_cases;
            break;
            }
        } else {
            if ((bitmap & (1u << (ch & 0x1f))) == 0) {
            bitmap |= 1u << (ch & 0x1f);
            if (n_cases < 2)
                cases[n_cases] = ch;
            ++n_cases;
            }
        }
    }

    if (block != -1 || n_cases <= 2) {
        char buf[64];
        g->I[2] = block;
        g->I[3] = bitmap;
        g->I[4] = shortest_size - 1;
        if (p->mode == m_forward) {
            sprintf(buf, "z->p[z->c + %d]", shortest_size - 1);
            g->S[1] = buf;
            if (shortest_size == 1) {
                wp(g, "~Mif (z->c >= z->l || ", p);
            } else {
                wp(g, "~Mif (z->c + ~I4 >= z->l || ", p);
            }
        } else {
            g->S[1] = "z->p[z->c - 1]";
            if (shortest_size == 1) {
                wp(g, "~Mif (z->c <= z->lb || ", p);
            } else {
                wp(g, "~Mif (z->c - ~I4 <= z->lb || ", p);
            }
        }
        if (n_cases == 0) {
            /* We get this for the degenerate case: among { '' }
             * This doesn't seem to be a useful construct, but it is
             * syntactically valid.
             */
            wp(g, "0", p);
        } else if (n_cases == 1) {
            g->I[4] = cases[0];
            wp(g, "~S1 != ~I4", p);
        } else if (n_cases == 2) {
            g->I[4] = cases[0];
            g->I[5] = cases[1];
            wp(g, "(~S1 != ~I4 && ~S1 != ~I5)", p);
        } else {
            wp(g, "~S1 >> 5 != ~I2 || !((~I3 >> (~S1 & 0x1f)) & 1)", p);
        }
        ws(g, ") ");
        if (empty_case != -1) {
            /* If the among includes the empty string, it can never fail
             * so not matching the bitmap means we match the empty string.
             */
            g->I[4] = among_cases[empty_case].result;
            wp(g, "among_var = ~I4; else~C", p);
        } else {
            wp(g, "~f~C", p);
        }
    } else {
#ifdef OPTIMISATION_WARNINGS
        printf("Couldn't shortcut among %d\n", x->number);
#endif
    }

    if (x->command_count == 0 && x->starter == 0)
        wp(g, "~Mif (!(find_among~S0(z, a_~I0, ~I1))) ~f~C", p);
    else
        wp(g, "~Mamong_var = find_among~S0(z, a_~I0, ~I1);~C"
              "~Mif (!(among_var)) ~f~N", p);
}

static void generate_among(struct generator * g, struct node * p) {

    struct among * x = p->among;
    int case_number = 1;

    if (x->substring == 0) generate_substring(g, p);
    if (x->command_count == 0 && x->starter == 0) return;

    unless (x->starter == 0) generate(g, x->starter);

    p = p->left;
    if (p != 0 && p->type != c_literalstring) p = p->right;
    w(g, "~Mswitch(among_var) {~N~+"
             "~Mcase 0: ~f~N");

    until (p == 0) {
         if (p->type == c_bra && p->left != 0) {
             g->I[0] = case_number++;
             w(g, "~Mcase ~I0:~N~+"); generate(g, p); w(g, "~Mbreak;~N~-");
         }
         p = p->right;
    }
    w(g, "~}");
}

static void generate_booltest(struct generator * g, struct node * p) {

    g->V[0] = p->name;
    wp(g, "~Mif (!(~V0)) ~f~C", p);
}

static void generate_false(struct generator * g, struct node * p) {

    wp(g, "~M~f~C", p);
}

static void generate_debug(struct generator * g, struct node * p) {

    g->I[0] = g->debug_count++;
    g->I[1] = p->line_number;
    wp(g, "~Mdebug(z, ~I0, ~I1);~C", p);

}

static void generate(struct generator * g, struct node * p) {

    int used = g->label_used;
    int a0 = g->failure_label;
    const char * a1 = g->failure_string;

    switch (p->type)
    {
        case c_define:        generate_define(g, p); break;
        case c_bra:           generate_bra(g, p); break;
        case c_and:           generate_and(g, p); break;
        case c_or:            generate_or(g, p); break;
        case c_backwards:     generate_backwards(g, p); break;
        case c_not:           generate_not(g, p); break;
        case c_set:           generate_set(g, p); break;
        case c_unset:         generate_unset(g, p); break;
        case c_try:           generate_try(g, p); break;
        case c_fail:          generate_fail(g, p); break;
        case c_reverse:
        case c_test:          generate_test(g, p); break;
        case c_do:            generate_do(g, p); break;
        case c_goto:          generate_GO(g, p, 1); break;
        case c_gopast:        generate_GO(g, p, 0); break;
        case c_repeat:        generate_repeat(g, p, false); break;
        case c_loop:          generate_loop(g, p); break;
        case c_atleast:       generate_atleast(g, p); break;
        case c_setmark:       generate_setmark(g, p); break;
        case c_tomark:        generate_tomark(g, p); break;
        case c_atmark:        generate_atmark(g, p); break;
        case c_hop:           generate_hop(g, p); break;
        case c_delete:        generate_delete(g, p); break;
        case c_next:          generate_next(g, p); break;
        case c_tolimit:       generate_tolimit(g, p); break;
        case c_atlimit:       generate_atlimit(g, p); break;
        case c_leftslice:     generate_leftslice(g, p); break;
        case c_rightslice:    generate_rightslice(g, p); break;
        case c_assignto:      generate_assignto(g, p); break;
        case c_sliceto:       generate_sliceto(g, p); break;
        case c_assign:        generate_assignfrom(g, p); break;
        case c_insert:
        case c_attach:        generate_insert(g, p, p->type); break;
        case c_slicefrom:     generate_slicefrom(g, p); break;
        case c_setlimit:      generate_setlimit(g, p); break;
        case c_dollar:        generate_dollar(g, p); break;
        case c_mathassign:    generate_integer_assign(g, p, "="); break;
        case c_plusassign:    generate_integer_assign(g, p, "+="); break;
        case c_minusassign:   generate_integer_assign(g, p, "-="); break;
        case c_multiplyassign:generate_integer_assign(g, p, "*="); break;
        case c_divideassign:  generate_integer_assign(g, p, "/="); break;
        case c_eq:            generate_integer_test(g, p, "=="); break;
        case c_ne:            generate_integer_test(g, p, "!="); break;
        case c_gr:            generate_integer_test(g, p, ">"); break;
        case c_ge:            generate_integer_test(g, p, ">="); break;
        case c_ls:            generate_integer_test(g, p, "<"); break;
        case c_le:            generate_integer_test(g, p, "<="); break;
        case c_call:          generate_call(g, p); break;
        case c_grouping:      generate_grouping(g, p, false); break;
        case c_non:           generate_grouping(g, p, true); break;
        case c_name:          generate_namedstring(g, p); break;
        case c_literalstring: generate_literalstring(g, p); break;
        case c_among:         generate_among(g, p); break;
        case c_substring:     generate_substring(g, p); break;
        case c_booltest:      generate_booltest(g, p); break;
        case c_false:         generate_false(g, p); break;
        case c_true:          break;
        case c_debug:         generate_debug(g, p); break;
        default: fprintf(stderr, "%d encountered\n", p->type);
                 exit(1);
    }

    if (g->failure_label != a0)
        g->label_used = used;
    g->failure_label = a0;
    g->failure_string = a1;
}

static void generate_start_comment(struct generator * g) {

    w(g, "~N/* This file was generated automatically by the Snowball to ANSI C compiler */~N");
}

static void generate_head(struct generator * g) {

    if (g->options->runtime_path == 0) {
        w(g, "~N#include \"header.h\"~N~N");
    } else {
        w(g, "~N#include \"");
        ws(g, g->options->runtime_path);
        if (g->options->runtime_path[strlen(g->options->runtime_path) - 1] != '/')
            wch(g, '/');
        w(g, "header.h\"~N~N");
    }
}

static void generate_routine_headers(struct generator * g) {
    struct name * q = g->analyser->names;
    until (q == 0) {
        g->V[0] = q;
        switch (q->type) {
            case t_routine:
                w(g, "static int ~W0(struct SN_env * z);~N");
                break;
            case t_external:
                w(g,
                  "#ifdef __cplusplus~N"
                  "extern \"C\" {~N"
                  "#endif~N"
                  "extern int ~W0(struct SN_env * z);~N"
                  "#ifdef __cplusplus~N"
                  "}~N"
                  "#endif~N"
                  );
                break;
        }
        q = q->next;
    }
}

static void generate_among_table(struct generator * g, struct among * x) {

    struct amongvec * v = x->b;

    g->I[0] = x->number;
    {
        int i;
        for (i = 0; i < x->literalstring_count; i++)
        {
            g->I[1] = i;
            g->I[2] = v->size;
            g->L[0] = v->b;
            unless (v->size == 0)
                w(g, "static const symbol s_~I0_~I1[~I2] = ~A0;~N");
            v++;
        }
    }

    g->I[1] = x->literalstring_count;
    w(g, "~N~Mstatic const struct among a_~I0[~I1] =~N{~N");

    v = x->b;
    {
        int i;
        for (i = 0; i < x->literalstring_count; i++) {
            g->I[1] = i;
            g->I[2] = v->size;
            g->I[3] = v->i;
            g->I[4] = v->result;
            g->S[0] = i < x->literalstring_count - 1 ? "," : "";

            w(g, "/*~J1 */ { ~I2, ");
            if (v->size == 0) w(g, "0,");
                         else w(g, "s_~I0_~I1,");
            w(g, " ~I3, ~I4, ");
            if (v->function == 0) w(g, "0"); else
                                  wvn(g, v->function);
            w(g, "}~S0~N");
            v++;
        }
    }
    w(g, "};~N~N");
}

static void generate_amongs(struct generator * g) {
    struct among * x = g->analyser->amongs;
    until (x == 0) {
        generate_among_table(g, x);
        x = x->next;
    }
}

static void set_bit(symbol * b, int i) { b[i/8] |= 1 << i%8; }

static void generate_grouping_table(struct generator * g, struct grouping * q) {

    int range = q->largest_ch - q->smallest_ch + 1;
    int size = (range + 7)/ 8;  /* assume 8 bits per symbol */
    symbol * b = q->b;
    symbol * map = create_b(size);
    int i;
    for (i = 0; i < size; i++) map[i] = 0;

    for (i = 0; i < SIZE(b); i++) set_bit(map, b[i] - q->smallest_ch);

    {
        g->V[0] = q->name;

        w(g, "static const unsigned char ~V0[] = { ");
        for (i = 0; i < size; i++) {
             wi(g, map[i]);
             if (i < size - 1) w(g, ", ");
        }
        w(g, " };~N~N");
    }
    lose_b(map);
}

static void generate_groupings(struct generator * g) {
    struct grouping * q = g->analyser->groupings;
    until (q == 0) {
        generate_grouping_table(g, q);
        q = q->next;
    }
}

static void generate_create(struct generator * g) {

    int * p = g->analyser->name_count;
    g->I[0] = p[t_string];
    g->I[1] = p[t_integer];
    g->I[2] = p[t_boolean];
    w(g, "~N"
         "extern struct SN_env * ~pcreate_env(void) { return SN_create_env(~I0, ~I1, ~I2); }"
         "~N");
}

static void generate_close(struct generator * g) {

    int * p = g->analyser->name_count;
    g->I[0] = p[t_string];
    w(g, "~Nextern void ~pclose_env(struct SN_env * z) { SN_close_env(z, ~I0); }~N~N");
}

static void generate_create_and_close_templates(struct generator * g) {
    w(g, "~N"
         "extern struct SN_env * ~pcreate_env(void);~N"
         "extern void ~pclose_env(struct SN_env * z);~N"
         "~N");
}

static void generate_header_file(struct generator * g) {

    struct name * q = g->analyser->names;
    char * vp = g->options->variables_prefix;
    g->S[0] = vp;

    w(g, "~N"
         "#ifdef __cplusplus~N"
         "extern \"C\" {~N"
         "#endif~N");            /* for C++ */

    generate_create_and_close_templates(g);
    until (q == 0) {
        g->V[0] = q;
        switch (q->type)
        {
            case t_external:
                w(g, "extern int ~W0(struct SN_env * z);~N");
                break;
            case t_string:  g->S[1] = "S"; goto label0;
            case t_integer: g->S[1] = "I"; goto label0;
            case t_boolean: g->S[1] = "B";
            label0:
                if (vp) {
                    g->I[0] = q->count;
                    w(g, "#define ~S0");
                    str_append_b(g->outbuf, q->b);
                    w(g, " (~S1[~I0])~N");
                }
                break;
        }
        q = q->next;
    }

    w(g, "~N"
         "#ifdef __cplusplus~N"
         "}~N"
         "#endif~N");            /* for C++ */

    w(g, "~N");
}

extern void generate_program_c(struct generator * g) {

    g->outbuf = str_new();
    generate_start_comment(g);
    generate_head(g);
    generate_routine_headers(g);
    w(g, "#ifdef __cplusplus~N"
         "extern \"C\" {~N"
         "#endif~N"
         "~N");
    generate_create_and_close_templates(g);
    w(g, "~N"
         "#ifdef __cplusplus~N"
         "}~N"
         "#endif~N");
    generate_amongs(g);
    generate_groupings(g);
    g->declarations = g->outbuf;
    g->outbuf = str_new();
    g->literalstring_count = 0;
    {
        struct node * p = g->analyser->program;
        until (p == 0) { generate(g, p); p = p->right; }
    }
    generate_create(g);
    generate_close(g);
    output_str(g->options->output_c, g->declarations);
    str_delete(g->declarations);
    output_str(g->options->output_c, g->outbuf);
    str_clear(g->outbuf);

    generate_start_comment(g);
    generate_header_file(g);
    output_str(g->options->output_h, g->outbuf);
    str_delete(g->outbuf);
}

extern struct generator * create_generator_c(struct analyser * a, struct options * o) {
    NEW(generator, g);
    g->analyser = a;
    g->options = o;
    g->margin = 0;
    g->debug_count = 0;
    g->line_count = 0;
    return g;
}

extern void close_generator_c(struct generator * g) {

    FREE(g);
}

