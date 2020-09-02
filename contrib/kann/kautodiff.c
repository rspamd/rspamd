#include "config.h"

#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <float.h>
#include <math.h>
#include "kautodiff.h"
#include "blas-config.h"

typedef struct {
	uint64_t s[2];
	double n_gset;
	int n_iset;
	volatile int lock;
} kad_rng_t;

/**********************
 * Graph construction *
 **********************/

static inline kad_node_t *kad_new_core(int n_d, int op, int n_child)
{
	kad_node_t *s;
	if (n_d >= KAD_MAX_DIM) return 0;
	s = (kad_node_t*)calloc(1, sizeof(kad_node_t));
	s->n_d = n_d, s->op = op, s->n_child = n_child;
	if (s->n_child) s->child = (kad_node_t**)calloc(s->n_child, sizeof(kad_node_t*));
	return s;
}

static inline kad_node_t *kad_vleaf(uint8_t flag, float *x, float *g, int n_d, va_list ap)
{
	int i;
	kad_node_t *p;
	if (n_d > KAD_MAX_DIM) return 0;
	p = (kad_node_t*)calloc(1, sizeof(kad_node_t));
	p->n_d = n_d;
	for (i = 0; i < n_d; ++i)
		p->d[i] = va_arg(ap, int32_t);
	p->x = x, p->g = g, p->flag = flag;
	return p;
}

kad_node_t *kad_const(float *x, int n_d, ...)
{
	kad_node_t *p;
	va_list ap;
	va_start(ap, n_d); p = kad_vleaf(KAD_CONST, x, 0, n_d, ap); va_end(ap);
	return p;
}

kad_node_t *kad_feed(int n_d, ...)
{
	kad_node_t *p;
	va_list ap;
	va_start(ap, n_d); p = kad_vleaf(0, 0, 0, n_d, ap); va_end(ap);
	return p;
}

kad_node_t *kad_var(float *x, float *g, int n_d, ...)
{
	kad_node_t *p;
	va_list ap;
	va_start(ap, n_d); p = kad_vleaf(KAD_VAR, x, g, n_d, ap); va_end(ap);
	return p;
}

static inline kad_node_t *kad_finalize_node(kad_node_t *s) /* a helper function */
{
	int i;
	if (kad_op_list[s->op](s, KAD_SYNC_DIM) < 0) { /* check dimension */
		if (s->ptr) free(s->ptr);
		free(s->child); free(s);
		return 0;
	}
	for (i = 0; i < s->n_child; ++i)
		if (kad_is_back(s->child[i]))
			break;
	if (i < s->n_child) s->flag |= KAD_VAR;
	return s;
}

/********** Simple arithmetic **********/

static inline kad_node_t *kad_op2_core(int op, kad_node_t *x, kad_node_t *y)
{
	kad_node_t *s;
	s = kad_new_core(0, op, 2);
	s->child[0] = x, s->child[1] = y;
	return kad_finalize_node(s);
}

static inline kad_node_t *kad_op1_core(int op, kad_node_t *x)
{
	kad_node_t *s;
	s = kad_new_core(0, op, 1);
	s->child[0] = x;
	return kad_finalize_node(s);
}

#define KAD_FUNC_OP2(fname, op) kad_node_t *fname(kad_node_t *x, kad_node_t *y) { return kad_op2_core((op), x, y); }

KAD_FUNC_OP2(kad_add, 1)
KAD_FUNC_OP2(kad_sub, 23)
KAD_FUNC_OP2(kad_mul, 2)
KAD_FUNC_OP2(kad_cmul, 3)
KAD_FUNC_OP2(kad_matmul, 9)
KAD_FUNC_OP2(kad_ce_multi, 13)
KAD_FUNC_OP2(kad_ce_bin, 22)
KAD_FUNC_OP2(kad_ce_bin_neg, 4)
KAD_FUNC_OP2(kad_mse, 29)

#define KAD_FUNC_OP1(fname, op) kad_node_t *fname(kad_node_t *x) { return kad_op1_core((op), x); }

KAD_FUNC_OP1(kad_log, 27)
KAD_FUNC_OP1(kad_exp, 33)
KAD_FUNC_OP1(kad_sin, 34)
KAD_FUNC_OP1(kad_square, 5)
KAD_FUNC_OP1(kad_sigm, 6)
KAD_FUNC_OP1(kad_tanh, 7)
KAD_FUNC_OP1(kad_relu, 8)
KAD_FUNC_OP1(kad_1minus, 11)
KAD_FUNC_OP1(kad_softmax, 14)
KAD_FUNC_OP1(kad_stdnorm, 32)

kad_node_t *kad_ce_multi_weighted(kad_node_t *pred, kad_node_t *truth, kad_node_t *weight)
{
	kad_node_t *s;
	s = kad_new_core(0, 13, 3);
	s->child[0] = pred, s->child[1] = truth, s->child[2] = weight;
	return kad_finalize_node(s);
}

/********** Convolution **********/

/* compute output dimension and padding sizes on both sides */
static inline int conv_find_par(int in_size, int kernel_size, int stride, int pad0, int *new_pad0, int *new_pad1)
{
	int out_size, pad_both;
	/* key equation: out_size = (in_size - kernel_size + pad_both) / stride + 1 */
	if (pad0 == KAD_PAD_SAME && stride == 1) out_size = in_size;
	else out_size = (in_size - kernel_size + (pad0 > 0? pad0 : 0) + stride - 1) / stride + 1;
	pad_both = (out_size - 1) * stride + kernel_size - in_size;
	*new_pad0 = pad_both / 2;
	*new_pad1 = pad_both - *new_pad0;
	return out_size;
}

typedef struct {
	int kernel_size, stride, pad[2];
} conv_conf_t;

static inline conv_conf_t *conv2d_gen_aux(int in_row, int in_col, int kernel_r, int kernel_c, int stride_r, int stride_c, int top_pad, int left_pad)
{
	conv_conf_t *cnn;
	cnn = (conv_conf_t*)calloc(2, sizeof(conv_conf_t));
	cnn[0].kernel_size = kernel_r, cnn[0].stride = stride_r;
	cnn[1].kernel_size = kernel_c, cnn[1].stride = stride_c;
	conv_find_par(in_row, kernel_r, stride_r, top_pad,  &cnn[0].pad[0], &cnn[0].pad[1]);
	conv_find_par(in_col, kernel_c, stride_c, left_pad, &cnn[1].pad[0], &cnn[1].pad[1]);
	return cnn;
}

kad_node_t *kad_conv2d(kad_node_t *x, kad_node_t *w, int stride_r, int stride_c, int top_pad, int left_pad)
{
	kad_node_t *s;
	if (x->n_d != 4 || w->n_d != 4) return 0;
	s = kad_new_core(0, 16, 2);
	s->child[0] = x, s->child[1] = w;
	s->ptr = conv2d_gen_aux(x->d[2], x->d[3], w->d[2], w->d[3], stride_r, stride_c, top_pad, left_pad);
	s->ptr_size = sizeof(conv_conf_t) * 2;
	return kad_finalize_node(s);
}

kad_node_t *kad_max2d(kad_node_t *x, int kernel_r, int kernel_c, int stride_r, int stride_c, int top_pad, int left_pad)
{
	kad_node_t *s;
	if (x->n_d != 4) return 0;
	s = kad_new_core(0, 17, 1);
	s->child[0] = x;
	s->ptr = conv2d_gen_aux(x->d[2], x->d[3], kernel_r, kernel_c, stride_r, stride_c, top_pad, left_pad);
	s->ptr_size = sizeof(conv_conf_t) * 2;
	return kad_finalize_node(s);
}

static inline conv_conf_t *conv1d_gen_aux(int in_col, int kernel_c, int stride_c, int left_pad)
{
	conv_conf_t *cnn;
	cnn = (conv_conf_t*)calloc(1, sizeof(conv_conf_t));
	cnn->kernel_size = kernel_c, cnn->stride = stride_c;
	conv_find_par(in_col, kernel_c, stride_c, left_pad, &cnn->pad[0], &cnn->pad[1]);
	return cnn;
}

kad_node_t *kad_conv1d(kad_node_t *x, kad_node_t *w, int stride, int left_pad)
{
	kad_node_t *s;
	if (x->n_d != 3 || w->n_d != 3) return 0;
	s = kad_new_core(0, 18, 2);
	s->child[0] = x, s->child[1] = w;
	s->ptr = conv1d_gen_aux(x->d[2], w->d[2], stride, left_pad);
	s->ptr_size = sizeof(conv_conf_t);
	return kad_finalize_node(s);
}

kad_node_t *kad_max1d(kad_node_t *x, int kernel_size, int stride, int left_pad)
{
	kad_node_t *s;
	if (x->n_d != 3) return 0;
	s = kad_new_core(0, 19, 1);
	s->child[0] = x;
	s->ptr = conv1d_gen_aux(x->d[2], kernel_size, stride, left_pad);
	s->ptr_size = sizeof(conv_conf_t);
	return kad_finalize_node(s);
}

kad_node_t *kad_avg1d(kad_node_t *x, int kernel_size, int stride, int left_pad)
{
	kad_node_t *s;
	if (x->n_d != 3) return 0;
	s = kad_new_core(0, 28, 1);
	s->child[0] = x;
	s->ptr = conv1d_gen_aux(x->d[2], kernel_size, stride, left_pad);
	s->ptr_size = sizeof(conv_conf_t);
	return kad_finalize_node(s);
}

/********** Multi-node pooling **********/

static kad_node_t *kad_pooling_general(int op, int n, kad_node_t **x)
{
	int i;
	kad_node_t *s;
	s = kad_new_core(0, op, n);
	s->flag |= KAD_POOL;
	for (i = 0; i < n; ++i)
		s->child[i] = x[i];
	return kad_finalize_node(s);
}

kad_node_t *kad_avg(int n, kad_node_t **x)   { return kad_pooling_general(10, n, x); }
kad_node_t *kad_max(int n, kad_node_t **x)   { return kad_pooling_general(21, n, x); }
kad_node_t *kad_stack(int n, kad_node_t **x) { return kad_pooling_general(35, n, x); }

kad_node_t *kad_select(int n, kad_node_t **x, int which)
{
	kad_node_t *s;
	int32_t i, *aux;
	aux = (int32_t*)calloc(1, 4);
	*aux = which;
	s = kad_new_core(0, 12, n);
	for (i = 0; i < n; ++i) s->child[i] = x[i];
	s->flag |= KAD_POOL, s->ptr = aux, s->ptr_size = 4;
	return kad_finalize_node(s);
}

/********** Dimension reduction **********/

static kad_node_t *kad_reduce_general(int op, kad_node_t *x, int axis)
{
	kad_node_t *s;
	int32_t *aux;
	aux = (int32_t*)malloc(4);
	aux[0] = axis;
	s = kad_new_core(0, op, 1);
	s->child[0] = x;
	s->ptr = aux, s->ptr_size = 4;
	return kad_finalize_node(s);
}

kad_node_t *kad_reduce_sum(kad_node_t *x, int axis)  { return kad_reduce_general(25, x, axis); }
kad_node_t *kad_reduce_mean(kad_node_t *x, int axis) { return kad_reduce_general(26, x, axis); }

/********** Sampling related **********/

kad_node_t *kad_dropout(kad_node_t *x, kad_node_t *y)
{
	kad_node_t *z;
	z = kad_op2_core(15, x, y);
	z->ptr = kad_rng(), z->ptr_size = sizeof(kad_rng_t);
	return z;
}

kad_node_t *kad_sample_normal(kad_node_t *x)
{
	kad_node_t *z;
	z = kad_op1_core(24, x);
	z->ptr = kad_rng(), z->ptr_size = sizeof(kad_rng_t);
	return z;
}

/********** Miscellaneous **********/

kad_node_t *kad_slice(kad_node_t *x, int axis, int start, int end)
{
	kad_node_t *s;
	int32_t *aux;
	if (end < start || start < 0) return 0;
	aux = (int32_t*)malloc(3 * 4);
	aux[0] = axis, aux[1] = start, aux[2] = end;
	s = kad_new_core(0, 20, 1);
	s->child[0] = x;
	s->ptr = aux, s->ptr_size = 3 * 4;
	return kad_finalize_node(s);
}

kad_node_t *kad_concat_array(int axis, int n, kad_node_t **p)
{
	kad_node_t *s;
	int32_t i, *aux;
	aux = (int32_t*)malloc(4);
	aux[0] = axis;
	s = kad_new_core(0, 31, n);
	for (i = 0; i < n; ++i)
		s->child[i] = p[i];
	s->ptr = aux, s->ptr_size = 4;
	return kad_finalize_node(s);
}

kad_node_t *kad_concat(int axis, int n, ...)
{
	int i;
	kad_node_t **p, *s;
	va_list ap;
	p = (kad_node_t**)malloc(n * sizeof(kad_node_t*));
	va_start(ap, n);
	for (i = 0; i < n; ++i) p[i] = va_arg(ap, kad_node_p);
	va_end(ap);
	s = kad_concat_array(axis, n, p);
	free(p);
	return s;
}

kad_node_t *kad_reshape(kad_node_t *x, int n_d, int *d)
{
	kad_node_t *s;
	int32_t i, *aux = 0;
	if (n_d > 0) {
		aux = (int32_t*)malloc(n_d * 4);
		for (i = 0; i < n_d; ++i) aux[i] = d? d[i] : -1;
	}
	s = kad_new_core(0, 30, 1);
	s->child[0] = x, s->ptr = aux, s->ptr_size = n_d * 4;
	return kad_finalize_node(s);
}

kad_node_t *kad_reverse(kad_node_t *x, int axis)
{
	kad_node_t *s;
	int32_t *aux;
	aux = (int32_t*)malloc(4);
	*aux = axis;
	s = kad_new_core(0, 36, 1);
	s->child[0] = x, s->ptr = aux, s->ptr_size = 4;
	return kad_finalize_node(s);
}

kad_node_t *kad_switch(int n, kad_node_t **p)
{
	kad_node_t *s;
	int32_t i, *aux;
	aux = (int32_t*)calloc(1, 4);
	s = kad_new_core(0, 12, n);
	for (i = 0; i < n; ++i)
		s->child[i] = p[i];
	s->ptr = aux, s->ptr_size = 4;
	return kad_finalize_node(s);
}

/***********************
 * Graph linearization *
 ***********************/

static void kad_mark_back(int n, kad_node_t **v)
{
	int i, j;
	for (i = 0; i < n; ++i) {
		if (v[i]->n_child == 0) continue;
		for (j = 0; j < v[i]->n_child; ++j)
			if (kad_is_back(v[i]->child[j]))
				break;
		if (j < v[i]->n_child) v[i]->flag |= KAD_VAR;
		else v[i]->flag &= ~KAD_VAR;
	}
}

static void kad_allocate_internal(int n, kad_node_t **v)
{
	int i;
	kad_mark_back(n, v);
	for (i = 0; i < n; ++i) {
		kad_node_t *p = v[i];
		if (p->n_child == 0) continue;
		p->x = (float*)realloc(p->x, kad_len(p) * sizeof(float));
		if (kad_is_back(p)) {
			p->g = (float*)realloc(p->g, kad_len(p) * sizeof(float));
			kad_op_list[p->op](p, KAD_ALLOC);
		}
	}
}

int kad_sync_dim(int n, kad_node_t **v, int batch_size)
{
	int i, req_alloc = 0, req_sync = 0, old_size = 0;
	for (i = 0; i < n; ++i) {
		if (kad_is_feed(v[i])) {
			old_size = v[i]->d[0]; /* TODO: check if all feeds have the same batch size */
			if (batch_size > 0 && v[i]->d[0] != batch_size)
				v[i]->d[0] = batch_size, req_sync = 1;
		} else if (v[i]->n_child > 0 && req_sync)
			kad_op_list[v[i]->op](v[i], KAD_SYNC_DIM);
	}
	if (old_size < batch_size) req_alloc = 1;
	for (i = 0; i < n; ++i)
		if (v[i]->n_child > 0 && v[i]->x == 0) req_alloc = 1;
	if (req_alloc) kad_allocate_internal(n, v);
	return batch_size > 0? batch_size : old_size;
}

#define kvec_t(type) struct { size_t n, m; type *a; }

#define kv_pop(v) ((v).a[--(v).n])

#define kv_push(type, v, x) do { \
		if ((v).n == (v).m) { \
			(v).m = (v).m? (v).m<<1 : 2; \
			(v).a = (type*)realloc((v).a, sizeof(type) * (v).m); \
		} \
		(v).a[(v).n++] = (x); \
	} while (0)

/* IMPORTANT: kad_node_t::tmp MUST BE set to zero before calling this function */
kad_node_t **kad_compile_array(int *n_node, int n_roots, kad_node_t **roots)
{
	int i;
	kvec_t(kad_node_p) stack = {0,0,0}, a = {0,0,0};

	/* generate kad_node_t::tmp, the count of the parent nodes; shifted by 1; lowest bit to detect fake roots */
	for (i = 0; i < n_roots; ++i) {
		roots[i]->tmp = 1; /* mark the root */
		kv_push(kad_node_p, stack, roots[i]);
	}
	while (stack.n) {
		kad_node_t *p = kv_pop(stack);
		for (i = 0; i < p->n_child; ++i) {
			kad_node_t *q = p->child[i];
			if (q->tmp == 0) kv_push(kad_node_p, stack, q);
			q->tmp += 1<<1;
		}
	}

	/* topological sorting (Kahn's algorithm) */
	for (i = 0; i < n_roots; ++i)
		if (roots[i]->tmp>>1 == 0) /* if roots[i]->tmp>>1 != 0, it is not a real root */
			kv_push(kad_node_p, stack, roots[i]);
	while (stack.n) {
		kad_node_t *p = kv_pop(stack);
		kv_push(kad_node_p, a, p);
		for (i = 0; i < p->n_child; ++i) {
			p->child[i]->tmp -= 1<<1;
			if (p->child[i]->tmp>>1 == 0)
				kv_push(kad_node_p, stack, p->child[i]);
		}
	}
	free(stack.a);
	for (i = 0; i < (int)a.n; ++i) { /* check cycles; no cycles if constructed with kad_add() etc */
		assert(a.a[i]->tmp>>1 == 0);
		a.a[i]->tmp = 0;
	}

	/* reverse */
	for (i = 0; i < (int)a.n>>1; ++i) { /* reverse a.a[] */
		kad_node_p t;
		t = a.a[i], a.a[i] = a.a[a.n-1-i], a.a[a.n-1-i] = t;
	}
	kad_allocate_internal(a.n, a.a);

	*n_node = a.n;
	return a.a;
}

kad_node_t **kad_compile(int *n_node, int n_roots, ...)
{
	int i;
	kad_node_t **roots, **ret;
	va_list ap;

	roots = (kad_node_t**)malloc(n_roots * sizeof(kad_node_t*));
	va_start(ap, n_roots);
	for (i = 0; i < n_roots; ++i) roots[i] = va_arg(ap, kad_node_p);
	va_end(ap);
	ret = kad_compile_array(n_node, n_roots, roots);
	free(roots);
	return ret;
}

/************************************
 * Miscellaneous on compiled graphs *
 ************************************/

void kad_delete(int n, kad_node_t **a)
{
	int i;
	for (i = 0; i < n; ++i) {
		kad_node_t *p = a[i];
		if (p->n_child) {
			free(p->x); free(p->g);
		}
		free(p->child); free(p->ptr); free(p->gtmp); free(p);
	}
	free(a);
}

int kad_size_var(int n, kad_node_t *const* v)
{
	int c, i;
	for (i = c = 0; i < n; ++i)
		if (kad_is_var(v[i]))
			c += kad_len(v[i]);
	return c;
}

int kad_size_const(int n, kad_node_t *const* v)
{
	int c, i;
	for (i = c = 0; i < n; ++i)
		if (kad_is_const(v[i]))
			c += kad_len(v[i]);
	return c;
}

/**********************************
 * Computate values and gradients *
 **********************************/

static void kad_propagate_marks(int n, kad_node_t **a)
{
	int i, j;
	for (i = n - 1; i >= 0; --i) {
		kad_node_t *p = a[i];
		if (p->tmp > 0) {
			if (kad_is_switch(p)) {
				int32_t *aux = (int32_t*)p->ptr;
				if (p->child[*aux]->tmp == 0)
					p->child[*aux]->tmp = 1;
			} else {
				for (j = 0; j < p->n_child; ++j)
					if (p->child[j]->tmp == 0)
						p->child[j]->tmp = 1;
			}
		}
	}
}

void kad_eval_marked(int n, kad_node_t **a)
{
	int i;
	kad_propagate_marks(n, a);
	for (i = 0; i < n; ++i)
		if (a[i]->n_child && a[i]->tmp > 0)
			kad_op_list[a[i]->op](a[i], KAD_FORWARD);
	for (i = 0; i < n; ++i) a[i]->tmp = 0;
}

const float *kad_eval_at(int n, kad_node_t **a, int from)
{
	int i;
	if (from < 0 || from >= n) from = n - 1;
	for (i = 0; i < n; ++i) a[i]->tmp = (i == from);
	kad_eval_marked(n, a);
	return a[from]->x;
}

void kad_grad(int n, kad_node_t **a, int from)
{
	int i;
	if (from < 0 || from >= n) from = n - 1;
	assert(a[from]->n_d == 0);
	for (i = 0; i < n; ++i) a[i]->tmp = (i == from);
	kad_propagate_marks(n, a);
	for (i = 0; i <= from; ++i) /* set all grandients to zero */
		if (a[i]->g && a[i]->tmp > 0)
			memset(a[i]->g, 0, kad_len(a[i]) * sizeof(float));
	for (i = from, a[i]->g[0] = 1.0f; i >= 0; --i) /* backprop */
		if (a[i]->n_child && a[i]->tmp > 0)
			kad_op_list[a[i]->op](a[i], KAD_BACKWARD);
	for (i = 0; i <= from; ++i) a[i]->tmp = 0;
}

/***********************
 * Load and save graph *
 ***********************/

static void kad_save1(FILE *fp, const kad_node_t *p)
{
	fwrite(&p->ext_label, 4, 1, fp);
	fwrite(&p->ext_flag, 4, 1, fp);
	fwrite(&p->flag, 1, 1, fp);
	fwrite(&p->n_child, 4, 1, fp);
	if (p->n_child) {
		int32_t j, pre = p->pre? p->pre->tmp : -1;
		fwrite(&p->op, 2, 1, fp);
		for (j = 0; j < p->n_child; ++j)
			fwrite(&p->child[j]->tmp, 4, 1, fp);
		fwrite(&pre, 4, 1, fp);
		fwrite(&p->ptr_size, 4, 1, fp);
		if (p->ptr_size > 0 && p->ptr)
			fwrite(p->ptr, p->ptr_size, 1, fp);
	} else {
		fwrite(&p->n_d, 1, 1, fp);
		if (p->n_d) fwrite(p->d, 4, p->n_d, fp);
	}
}

static kad_node_t *kad_load1(FILE *fp, kad_node_t **node)
{
	kad_node_t *p;
	p = (kad_node_t*)calloc(1, sizeof(kad_node_t));
	(void) !fread(&p->ext_label, 4, 1, fp);
	(void) !fread(&p->ext_flag, 4, 1, fp);
	(void) !fread(&p->flag, 1, 1, fp);
	(void) !fread(&p->n_child, 4, 1, fp);
	if (p->n_child) {
		int32_t j, k;
		p->child = (kad_node_t**)calloc(p->n_child, sizeof(kad_node_t*));
		(void) !fread(&p->op, 2, 1, fp);
		for (j = 0; j < p->n_child; ++j) {
			(void) !fread(&k, 4, 1, fp);
			p->child[j] = node? node[k] : 0;
		}
		(void) !fread(&k, 4, 1, fp);
		if (k >= 0) p->pre = node[k];
		(void) !fread(&p->ptr_size, 4, 1, fp);
		if (p->ptr_size > 0) {
			p->ptr = malloc(p->ptr_size);
			(void) !fread(p->ptr, p->ptr_size, 1, fp);
		}
	} else {
		(void) !fread(&p->n_d, 1, 1, fp);
		if (p->n_d) (void) !fread(p->d, 4, p->n_d, fp);
	}
	return p;
}

int kad_save(FILE *fp, int n_node, kad_node_t **node)
{
	int32_t i, k = n_node;
	fwrite(&k, 4, 1, fp);
	for (i = 0; i < n_node; ++i) node[i]->tmp = i;
	for (i = 0; i < n_node; ++i) kad_save1(fp, node[i]);
	for (i = 0; i < n_node; ++i) node[i]->tmp = 0;
	return 0;
}

kad_node_t **kad_load(FILE *fp, int *_n_node)
{
	int32_t i, n_node;
	kad_node_t **node;
	(void) !fread(&n_node, 4, 1, fp);
	node = (kad_node_t**)malloc(n_node * sizeof(kad_node_t*));
	for (i = 0; i < n_node; ++i) {
		kad_node_t *p;
		p = node[i] = kad_load1(fp, node);
		if (p->n_child) {
			kad_op_list[p->op](p, KAD_ALLOC);
			kad_op_list[p->op](p, KAD_SYNC_DIM);
		}
	}
	*_n_node = n_node;
	kad_mark_back(n_node, node);
	return node;
}

/***************
 * Graph clone *
 ***************/

static inline kad_node_t *kad_dup1(const kad_node_t *p)
{
	kad_node_t *q;
	q = (kad_node_t*)malloc(sizeof(kad_node_t));
	memcpy(q, p, sizeof(kad_node_t));
	q->pre = 0, q->tmp = 0, q->gtmp = 0;
	if (p->ptr && p->ptr_size > 0) {
		if (kad_use_rng(p) && !(p->flag & KAD_SHARE_RNG) && p->ptr_size == sizeof(kad_rng_t)) {
			q->ptr = kad_rng(); /* each time step uses a different RNG */
		} else {
			q->ptr = malloc(p->ptr_size);
			memcpy(q->ptr, p->ptr, p->ptr_size);
		}
	}
	if (q->n_child) {
		q->x = q->g = 0;
		q->child = (kad_node_t**)calloc(q->n_child, sizeof(kad_node_t*));
	}
	return q;
}

kad_node_t **kad_clone(int n, kad_node_t **v, int batch_size)
{
	int i, j;
	kad_node_t **u;
	u = (kad_node_t**)calloc(n, sizeof(kad_node_t*));
	for (i = 0; i < n; ++i) v[i]->tmp = i;
	for (i = 0; i < n; ++i) {
		kad_node_t *p = v[i], *q;
		q = u[i] = kad_dup1(p);
		if (p->pre) q->pre = u[p->pre->tmp];
		if (p->n_child) {
			for (j = 0; j < p->n_child; ++j)
				q->child[j] = u[p->child[j]->tmp];
		} else if (!kad_is_feed(p)) {
			q->x = (float*)malloc(kad_len(p) * sizeof(float));
			memcpy(q->x, p->x, kad_len(p) * sizeof(float));
			q->g = 0;
		}
	}
	for (i = 0; i < n; ++i) v[i]->tmp = 0;
	kad_sync_dim(n, u, batch_size); /* this will allocate x[] and g[] at internal nodes */
	return u;
}

/**************
 * Unroll RNN *
 **************/

typedef struct {
	int32_t n, m;
	kad_node_t **v;
} nodes_t;

static inline void push_nodes(nodes_t *w, kad_node_t *p)
{
	if (w->n == w->m) {
		w->m = w->m? w->m<<1 : 16;
		w->v = (kad_node_t**)realloc(w->v, w->m * sizeof(kad_node_t*));
	}
	w->v[w->n++] = p;
}

static void kad_unroll_helper(int n_v, kad_node_t **v, int i_pivot, kad_node_t **t, int len, nodes_t *w)
{
	int i, j, l;
	uint8_t *flag;
	kad_node_t **aux;

	assert(kad_is_pivot(v[i_pivot]) && t[i_pivot] == 0);
	t[i_pivot] = kad_dup1(v[i_pivot]);
	t[i_pivot]->n_child = len;
	t[i_pivot]->child = (kad_node_t**)realloc(t[i_pivot]->child, len * sizeof(kad_node_t*));

	flag = (uint8_t*)calloc(n_v, 1);
	for (i = i_pivot, flag[i] = 16; i >= 0; --i) {
		if (i < i_pivot && kad_is_pivot(v[i])) continue; /* don't trespass other pivots */
		if (flag[i]&16) /* flag 16: nodes to unroll */
			for (j = 0; j < v[i]->n_child; ++j)
				flag[v[i]->child[j]->tmp] = 16;
	}
	for (i = 0; i < i_pivot; ++i) {
		if (!(flag[i]&16)) continue;
		if (kad_is_var(v[i]) || kad_is_const(v[i]) || kad_is_pivot(v[i])) flag[i] |= 1; /* external nodes that should not be duplicated */
		if (v[i]->pre) flag[v[i]->pre->tmp] |= 2;
	}
	flag[v[i_pivot]->child[0]->tmp] |= 4;
	aux = (kad_node_t**)calloc(n_v, sizeof(kad_node_t*));
	for (l = 0; l < len; ++l) {
		for (i = 0; i < i_pivot; ++i) {
			if (!(flag[i]&16) || ((flag[i]&3) && t[i])) continue;
			t[i] = kad_dup1(v[i]);
			if (v[i]->n_child)
				for (j = 0; j < v[i]->n_child; ++j)
					t[i]->child[j] = t[v[i]->child[j]->tmp];
			if (flag[i]&4) t[i_pivot]->child[l] = t[i];
			if (l == 0 && (flag[i]&2)) aux[i] = t[i];
			if (v[i]->pre) {
				t[v[i]->pre->tmp] = t[i];
				if (l == len - 1) t[i]->pre = aux[v[i]->pre->tmp]; /* this forms a cycle! */
			}
			push_nodes(w, t[i]);
		}
	}
	push_nodes(w, t[i_pivot]);
	free(aux); free(flag);
}

int kad_n_pivots(int n_v, kad_node_t **v)
{
	int i, n_pivots = 0;
	for (i = 0; i < n_v; ++i)
		if (kad_is_pivot(v[i])) ++n_pivots;
	return n_pivots;
}

kad_node_t **kad_unroll(int n_v, kad_node_t **v, int *new_n, int *len)
{
	int i, j, n_pivots = 0;
	kad_node_t **t;
	nodes_t w = {0,0,0};

	t = (kad_node_t**)calloc(n_v, sizeof(kad_node_t*));
	n_pivots = kad_n_pivots(n_v, v);
	for (i = 0; i < n_v; ++i) v[i]->tmp = i;
	if (n_pivots) {
		int k, *i_pivots;
		i_pivots = (int*)calloc(n_pivots, sizeof(int));
		for (i = k = 0; i < n_v; ++i) /* collect pivots */
			if (kad_is_pivot(v[i])) i_pivots[k++] = i;
		for (i = 0; i < n_pivots; ++i) /* unroll each pivot, from the lowest to the highest */
			kad_unroll_helper(n_v, v, i_pivots[i], t, len[i], &w);
		free(i_pivots);
	}
	for (i = 0; i < n_v; ++i) { /* copy over the rest of nodes */
		if (t[i]) continue;
		t[i] = kad_dup1(v[i]);
		if (v[i]->n_child)
			for (j = 0; j < v[i]->n_child; ++j)
				t[i]->child[j] = t[v[i]->child[j]->tmp];
		push_nodes(&w, t[i]);
	}
	free(t);
	for (i = 0; i < n_v; ++i) v[i]->tmp = 0;
	for (i = 0; i < w.n; ++i) /* stack may change the output dimension */
		if (w.v[i]->n_child > 0)
			kad_op_list[w.v[i]->op](w.v[i], KAD_SYNC_DIM);
	kad_allocate_internal(w.n, w.v);
	*new_n = w.n;
	return w.v;
}

/********************************
 * Vector and matrix operations *
 ********************************/

#ifdef __SSE__
#include <xmmintrin.h>

static inline float kad_sdot(int n, const float *x, const float *y) /* BLAS sdot using SSE */
{
	int i, n8 = n>>3<<3;
	__m128 vs1, vs2;
	float s, t[4];
	vs1 = _mm_setzero_ps();
	vs2 = _mm_setzero_ps();
	for (i = 0; i < n8; i += 8) {
		__m128 vx1, vx2, vy1, vy2;
		vx1 = _mm_loadu_ps(&x[i]);
		vx2 = _mm_loadu_ps(&x[i+4]);
		vy1 = _mm_loadu_ps(&y[i]);
		vy2 = _mm_loadu_ps(&y[i+4]);
		vs1 = _mm_add_ps(vs1, _mm_mul_ps(vx1, vy1));
		vs2 = _mm_add_ps(vs2, _mm_mul_ps(vx2, vy2));
	}
	for (s = 0.; i < n; ++i) s += x[i] * y[i];
	_mm_storeu_ps(t, vs1);
	s += t[0] + t[1] + t[2] + t[3];
	_mm_storeu_ps(t, vs2);
	s += t[0] + t[1] + t[2] + t[3];
	return s;
}
static inline void kad_saxpy_inlined(int n, float a, const float *x, float *y) /* BLAS saxpy using SSE */
{
	int i, n8 = n>>3<<3;
	__m128 va;
	va = _mm_set1_ps(a);
	for (i = 0; i < n8; i += 8) {
		__m128 vx1, vx2, vy1, vy2, vt1, vt2;
		vx1 = _mm_loadu_ps(&x[i]);
		vx2 = _mm_loadu_ps(&x[i+4]);
		vy1 = _mm_loadu_ps(&y[i]);
		vy2 = _mm_loadu_ps(&y[i+4]);
		vt1 = _mm_add_ps(_mm_mul_ps(va, vx1), vy1);
		vt2 = _mm_add_ps(_mm_mul_ps(va, vx2), vy2);
		_mm_storeu_ps(&y[i], vt1);
		_mm_storeu_ps(&y[i+4], vt2);
	}
	for (; i < n; ++i) y[i] += a * x[i];
}
#else
static inline float kad_sdot(int n, const float *x, const float *y) /* BLAS sdot */
{
	int i;
	float s = 0.;
	for (i = 0; i < n; ++i) s += x[i] * y[i];
	return s;
}
static inline void kad_saxpy_inlined(int n, float a, const float *x, float *y) // BLAS saxpy
{
	int i;
	for (i = 0; i < n; ++i) y[i] += a * x[i];
}
#endif

void kad_vec_mul_sum(int n, float *a, const float *b, const float *c)
{
	int i;
	for (i = 0; i < n; ++i) a[i] += b[i] * c[i];
}

/* This is actually lapack not cblas, but this definition is used */
#ifdef HAVE_CBLAS
#ifndef __APPLE__
/* As gfortran mangles names */
#define ssyev ssyev_
#endif
extern void ssyev(const char* jobz, const char* uplo, int* n, float* a, int* lda, float* w, float* work, int* lwork, int* info);
#endif

#ifdef HAVE_CBLAS_SGEMM

#ifdef HAVE_CBLAS_H
#include "cblas.h"
#else
/* Poor man approach, thanks for that Apple */
enum CBLAS_ORDER {CblasRowMajor=101, CblasColMajor=102 };
enum CBLAS_TRANSPOSE {CblasNoTrans=111, CblasTrans=112 };
extern void cblas_sgemm(const enum CBLAS_ORDER Order,
                 const enum CBLAS_TRANSPOSE TA,
                 const enum CBLAS_TRANSPOSE TB,
                 const int M, const int N, const int K,
                 const float  alpha, const float *A, const int lda,
                 const float *B, const int ldb, const float  beta,
                 float *C, const int ldc);
#endif

void kad_sgemm_simple(int trans_A, int trans_B, int M, int N, int K, const float *A, const float *B, float *C)
{
	cblas_sgemm(CblasRowMajor, trans_A? CblasTrans : CblasNoTrans, trans_B? CblasTrans : CblasNoTrans, M, N, K, 1.0f, A, trans_A? M : K, B, trans_B? K : N, 1.0f, C, N);
}
#else
void kad_sgemm_simple(int trans_A, int trans_B, int M, int N, int K, const float *A, const float *B, float *C) /* simplified BLAS sgemm */
{
	static const int x = 16;
	int i, j, k;
	if (!trans_A && trans_B) {
		for (i = 0; i < M; i += x)
			for (j = 0; j < N; j += x) {
				int ii, ie = M < i + x? M : i + x;
				int jj, je = N < j + x? N : j + x;
				for (ii = i; ii < ie; ++ii) { /* loop tiling */
					const float *aii = A + ii * K, *bjj;
					float *cii = C + ii * N;
					for (jj = j, bjj = B + j * K; jj < je; ++jj, bjj += K)
						cii[jj] += kad_sdot(K, aii, bjj);
				}
			}
	} else if (!trans_A && !trans_B) {
		for (i = 0; i < M; ++i)
			for (k = 0; k < K; ++k)
				kad_saxpy_inlined(N, A[i*K+k], &B[k*N], &C[i*N]);
	} else if (trans_A && !trans_B) {
		for (k = 0; k < K; ++k)
			for (i = 0; i < M; ++i)
				kad_saxpy_inlined(N, A[k*M+i], &B[k*N], &C[i*N]);
	} else abort(); /* not implemented for (trans_A && trans_B) */
}
#endif

#ifdef HAVE_CBLAS_SAXPY
#ifndef HAVE_CBLAS_H
extern void cblas_saxpy(const int __N,
    const float __alpha, const float *__X, const int __incX, float *__Y, const int __incY);
#endif

void kad_saxpy(int n, float a, const float *x, float *y) { cblas_saxpy(n, a, x, 1, y, 1); }
#else
void kad_saxpy(int n, float a, const float *x, float *y) { kad_saxpy_inlined(n, a, x, y); }
#endif

bool kad_ssyev_simple(int N, float *A, float *eigenvals)
{
#ifndef HAVE_CBLAS
	return false;
#else
	int n = N, lda = N, info, lwork;
	float wkopt;
	float *work;

	/* Query and allocate the optimal workspace */
	lwork = -1;
	ssyev ("Vectors", "Upper", &n, A, &lda, eigenvals, &wkopt, &lwork, &info);
	lwork = wkopt;
	work = (float*) g_malloc(lwork * sizeof(double));
	ssyev ("Vectors", "Upper", &n, A, &lda, eigenvals, work, &lwork, &info);
	/* Check for convergence */
	if (info > 0) {
		g_free (work);

		return false;
	}

	g_free (work);

	return true;
#endif
}

/***************************
 * Random number generator *
 ***************************/

static kad_rng_t kad_rng_dat = { {0x50f5647d2380309dULL, 0x91ffa96fc4c62cceULL}, 0.0, 0, 0 };

static inline uint64_t kad_splitmix64(uint64_t x)
{
	uint64_t z = (x += 0x9E3779B97F4A7C15ULL);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

static inline uint64_t kad_xoroshiro128plus_next(kad_rng_t *r)
{
	const uint64_t s0 = r->s[0];
	uint64_t s1 = r->s[1];
	const uint64_t result = s0 + s1;
	s1 ^= s0;
	r->s[0] = (s0 << 55 | s0 >> 9) ^ s1 ^ (s1 << 14);
	r->s[1] = s0 << 36 | s0 >> 28;
	return result;
}

static inline void kad_xoroshiro128plus_jump(kad_rng_t *r)
{
	static const uint64_t JUMP[] = { 0xbeac0467eba5facbULL, 0xd86b048b86aa9922ULL };
	uint64_t s0 = 0, s1 = 0;
	int i, b;
	for (i = 0; i < 2; ++i)
		for (b = 0; b < 64; b++) {
			if (JUMP[i] & 1ULL << b)
				s0 ^= r->s[0], s1 ^= r->s[1];
			kad_xoroshiro128plus_next(r);
		}
	r->s[0] = s0, r->s[1] = s1;
}

void kad_srand(void *d, uint64_t seed)
{
	kad_rng_t *r = d? (kad_rng_t*)d : &kad_rng_dat;
	r->n_gset = 0.0, r->n_iset = 0;
	r->s[0] = kad_splitmix64(seed);
	r->s[1] = kad_splitmix64(r->s[0]);
}

void *kad_rng(void)
{
	kad_rng_t *r;
	r = (kad_rng_t*)calloc(1, sizeof(kad_rng_t));
	kad_xoroshiro128plus_jump(&kad_rng_dat);
	r->s[0] = kad_rng_dat.s[0], r->s[1] = kad_rng_dat.s[1];
	return r;
}

uint64_t kad_rand(void *d) { return kad_xoroshiro128plus_next(d? (kad_rng_t*)d : &kad_rng_dat); }

double kad_drand(void *d)
{
	union { uint64_t i; double d; } u;
	u.i = 0x3FFULL << 52 | kad_xoroshiro128plus_next(d? (kad_rng_t*)d : &kad_rng_dat) >> 12;
	return u.d - 1.0;
}

double kad_drand_normal(void *d)
{
	kad_rng_t *r = d? (kad_rng_t*)d : &kad_rng_dat;
	if (r->n_iset == 0) {
		double fac, rsq, v1, v2;
		do {
			v1 = 2.0 * kad_drand(d) - 1.0;
			v2 = 2.0 * kad_drand(d) - 1.0;
			rsq = v1 * v1 + v2 * v2;
		} while (rsq >= 1.0 || rsq == 0.0);
		fac = sqrt(-2.0 * log(rsq) / rsq);
		r->n_gset = v1 * fac;
		r->n_iset = 1;
		return v2 * fac;
	} else {
		r->n_iset = 0;
		return r->n_gset;
	}
}

/*************
 * Operators *
 *************/

static inline void kad_copy_dim1(kad_node_t *dst, const kad_node_t *src) /* set the dimension/shape of dst to src */
{
	dst->n_d = src->n_d;
	if (src->n_d) memcpy(dst->d, src->d, src->n_d * sizeof(int));
}

/********** Arithmetic operations **********/

int kad_op_add(kad_node_t *p, int action)
{
	int i, n0, n1;
	kad_node_t *q[2];

	q[0] = p->child[0], n0 = kad_len(q[0]);
	q[1] = p->child[1], n1 = kad_len(q[1]);
	if (action == KAD_SYNC_DIM) {
		if (n0 % n1 != 0) return -1;
		kad_copy_dim1(p, q[0]);
	} else if (action == KAD_FORWARD) {
		assert(n0 >= n1);
		memcpy(p->x, q[0]->x, n0 * sizeof(float));
		for (i = 0; i < n0; i += n1)
			kad_saxpy(n1, 1.0f, q[1]->x, p->x + i);
	} else if (action == KAD_BACKWARD) {
		if (kad_is_back(q[0])) kad_saxpy(n0, 1.0f, p->g, q[0]->g);
		if (kad_is_back(q[1]))
			for (i = 0; i < n0; i += n1)
				kad_saxpy(n1, 1.0f, p->g + i, q[1]->g);
	}
	return 0;
}

int kad_op_sub(kad_node_t *p, int action)
{
	int i, n0, n1;
	kad_node_t *q[2];

	q[0] = p->child[0], n0 = kad_len(q[0]);
	q[1] = p->child[1], n1 = kad_len(q[1]);
	if (action == KAD_SYNC_DIM) {
		if (n0 % n1 != 0) return -1;
		kad_copy_dim1(p, q[0]);
	} else if (action == KAD_FORWARD) {
		assert(n0 >= n1);
		memcpy(p->x, q[0]->x, n0 * sizeof(float));
		for (i = 0; i < n0; i += n1)
			kad_saxpy(n1, -1.0f, q[1]->x, p->x + i);
	} else if (action == KAD_BACKWARD) {
		if (kad_is_back(q[0])) kad_saxpy(n0, 1.0f, p->g, q[0]->g);
		if (kad_is_back(q[1]))
			for (i = 0; i < n0; i += n1)
				kad_saxpy(n1, -1.0f, p->g + i, q[1]->g);
	}
	return 0;
}

int kad_op_mul(kad_node_t *p, int action)
{
	int i, n0, n1;
	kad_node_t *q[2];

	q[0] = p->child[0], n0 = kad_len(q[0]);
	q[1] = p->child[1], n1 = kad_len(q[1]);
	if (action == KAD_SYNC_DIM) {
		if (n0 % n1 != 0) return -1;
		kad_copy_dim1(p, q[0]);
	} else if (action == KAD_FORWARD) {
		assert(n0 >= n1);
		memset(p->x, 0, n0 * sizeof(float));
		if (q[0]->x != 0 && q[1]->x != 0)
			for (i = 0; i < n0; i += n1) /* TODO: optimize when n1==1 */
				kad_vec_mul_sum(n1, p->x + i, q[0]->x + i, q[1]->x);
	} else if (action == KAD_BACKWARD) {
		if (kad_is_back(q[0]) && q[1]->x)
			for (i = 0; i < n0; i += n1)
				kad_vec_mul_sum(n1, q[0]->g + i, p->g + i, q[1]->x);
		if (kad_is_back(q[1]) && q[0]->x)
			for (i = 0; i < n0; i += n1)
				kad_vec_mul_sum(n1, q[1]->g, p->g + i, q[0]->x + i);
	}
	return 0;
}

int kad_op_cmul(kad_node_t *p, int action)
{
	int i, n_a_row, n_b_row, n_col, n_a_col = 1, n_b_col = 1;
	kad_node_t *q[2];

	q[0] = p->child[0], q[1] = p->child[1];
	n_col = q[0]->d[q[0]->n_d - 1] > q[1]->d[q[1]->n_d - 1]? q[0]->d[q[0]->n_d - 1] : q[1]->d[q[1]->n_d - 1];
	for (i = q[0]->n_d - 1; i >= 0; --i) if (n_a_col < n_col) n_a_col *= q[0]->d[i];
	for (i = q[1]->n_d - 1; i >= 0; --i) if (n_b_col < n_col) n_b_col *= q[1]->d[i];
	n_a_row = kad_len(q[0]) / n_a_col, n_b_row = kad_len(q[1]) / n_b_col;
	if (action == KAD_SYNC_DIM) {
		if (n_a_col != n_b_col) return -1;
		p->n_d = 2, p->d[0] = n_a_row, p->d[1] = n_b_row;
	} else if (action == KAD_FORWARD) {
		memset(p->x, 0, n_a_row * n_b_row * sizeof(float));
		if (q[0]->x && q[1]->x)
			kad_sgemm_simple(0, 1, n_a_row, n_b_row, n_col, q[0]->x, q[1]->x, p->x); /* Y = X * trans(W) */
	} else if (action == KAD_BACKWARD) {
		if (kad_is_back(q[0]) && q[1]->x)
			kad_sgemm_simple(0, 0, n_a_row, n_col, n_b_row, p->g, q[1]->x, q[0]->g); /* G_x <- G_y * W */
		if (kad_is_back(q[1]) && q[0]->x)
			kad_sgemm_simple(1, 0, n_b_row, n_col, n_a_row, p->g, q[0]->x, q[1]->g); /* G_w <- trans(G_y) * X */
	}
	return 0;
}

int kad_op_matmul(kad_node_t *p, int action) /* TODO: matmul and cmul have different broadcasting rules */
{
	int n_a_row, n_b_row, n_a_col, n_b_col;
	kad_node_t *q[2];

	q[0] = p->child[0];
	q[1] = p->child[1];
	n_a_row = q[0]->n_d == 1? 1 : q[0]->d[0];
	n_b_row = q[1]->n_d == 1? 1 : q[1]->d[0];
	n_a_col = kad_len(q[0]) / n_a_row;
	n_b_col = kad_len(q[1]) / n_b_row;
	if (action == KAD_SYNC_DIM) {
		if (n_a_col != n_b_row) return -1;
		p->n_d = 2, p->d[0] = n_a_row, p->d[1] = n_b_col;
	} else if (action == KAD_FORWARD) {
		memset(p->x, 0, n_a_row * n_b_col * sizeof(float));
		if (q[0]->x && q[1]->x)
			kad_sgemm_simple(0, 0, n_a_row, n_b_col, n_a_col, q[0]->x, q[1]->x, p->x); /* Y = X * W */
	} else if (action == KAD_BACKWARD) {
		if (kad_is_back(q[0]) && q[1]->x)
			kad_sgemm_simple(0, 1, n_a_row, n_a_col, n_b_col, p->g, q[1]->x, q[0]->g); /* G_x <- G_y * trans(W) */
		if (kad_is_back(q[1]) && q[0]->x)
			kad_sgemm_simple(1, 0, n_b_row, n_b_col, n_a_row, q[0]->x, p->g, q[1]->g); /* G_y <- trans(A) * G_y */
	}
	return 0;
}

int kad_op_square(kad_node_t *p, int action)
{
	int i, n;
	kad_node_t *q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < n; ++i)
			p->x[i] = q->x[i] * q->x[i];
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (i = 0; i < n; ++i)
			q->g[i] += p->g[i] * (q->x[i] + q->x[i]);
	}
	return 0;
}

int kad_op_1minus(kad_node_t *p, int action)
{
	int i, n;
	kad_node_t *q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < n; ++i) p->x[i] = 1.0f - q->x[i];
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		kad_saxpy(n, -1.0f, p->g, q->g);
	}
	return 0;
}

int kad_op_exp(kad_node_t *p, int action)
{
	int i, n;
	kad_node_t *q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < n; ++i) p->x[i] = expf(q->x[i]);
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (i = 0; i < n; ++i)
			q->g[i] += p->g[i] * p->x[i];
	}
	return 0;
}

int kad_op_log(kad_node_t *p, int action)
{
	int i, n;
	kad_node_t *q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < n; ++i) p->x[i] = logf(q->x[i]);
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (i = 0; i < n; ++i)
			q->g[i] += p->g[i] / q->x[i];
	}
	return 0;
}

int kad_op_reduce_sum(kad_node_t *p, int action)
{
	kad_node_t *q = p->child[0];
	int i, j, k, axis, d0, d1;

	assert(p->ptr);
	axis = *(int32_t*)p->ptr;
	if (axis < 0 || axis >= q->n_d) return -1;
	for (i = 0, d0 = 1; i < axis; ++i) d0 *= q->d[i];
	for (i = axis + 1, d1 = 1; i < q->n_d; ++i) d1 *= q->d[i];
	if (action == KAD_SYNC_DIM) {
		p->n_d = q->n_d - 1;
		for (i = j = 0; i < q->n_d; ++i)
			if (i != axis) p->d[j++] = q->d[i];
	} else if (action == KAD_FORWARD) {
		memset(p->x, 0, kad_len(p) * sizeof(float));
		for (i = 0; i < d0; ++i)
			for (j = 0; j < q->d[axis]; ++j)
				for (k = 0; k < d1; ++k)
					p->x[i * d1 + k] += q->x[(i * q->d[axis] + j) * d1 + k];
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (i = 0; i < d0; ++i)
			for (j = 0; j < q->d[axis]; ++j)
				for (k = 0; k < d1; ++k)
					q->g[(i * q->d[axis] + j) * d1 + k] += p->g[i * d1 + k];
	}
	return 0;
}

int kad_op_reduce_mean(kad_node_t *p, int action)
{
	kad_node_t *q = p->child[0];
	int i, j, k, axis, d0, d1;

	assert(p->ptr);
	axis = *(int32_t*)p->ptr;
	if (axis < 0 || axis >= q->n_d) return -1;
	for (i = 0, d0 = 1; i < axis; ++i) d0 *= q->d[i];
	for (i = axis + 1, d1 = 1; i < q->n_d; ++i) d1 *= q->d[i];
	if (action == KAD_SYNC_DIM) {
		p->n_d = q->n_d - 1;
		for (i = j = 0; i < q->n_d; ++i)
			if (i != axis) p->d[j++] = q->d[i];
	} else if (action == KAD_FORWARD) {
		float t = 1.0f / q->d[axis];
		memset(p->x, 0, kad_len(p) * sizeof(float));
		for (i = 0; i < d0; ++i)
			for (j = 0; j < q->d[axis]; ++j)
				for (k = 0; k < d1; ++k)
					p->x[i * d1 + k] += t * q->x[(i * q->d[axis] + j) * d1 + k];
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		float t = 1.0f / q->d[axis];
		for (i = 0; i < d0; ++i)
			for (j = 0; j < q->d[axis]; ++j)
				for (k = 0; k < d1; ++k)
					q->g[(i * q->d[axis] + j) * d1 + k] += t * p->g[i * d1 + k];
	}
	return 0;
}

/********** Miscellaneous **********/

int kad_op_dropout(kad_node_t *p, int action)
{
	int i, n;
	kad_node_t *q = p->child[0];
	assert(p->child[1]->n_d == 0);
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_ALLOC) {
		if (kad_is_back(p->child[0]))
			p->gtmp = realloc(p->gtmp, n);
	} else if (action == KAD_FORWARD) {
		float r = kad_is_const(q) || kad_is_var(q)? 0.0f : *p->child[1]->x, z = 1.0f / (1.0f - r);
		uint8_t *flag = (uint8_t*)p->gtmp;
		for (i = 0; i < n; ++i) {
			int kept = (kad_drand(p->ptr) >= r);
			p->x[i] = kept? q->x[i] * z : 0.0f;
			if (flag) flag[i] = kept;
		}
	} else if (action == KAD_BACKWARD && kad_is_back(p->child[0])) {
		float r = kad_is_const(q) || kad_is_var(q)? 0.0f : *p->child[1]->x, z = 1.0f / (1.0f - r);
		uint8_t *flag = (uint8_t*)p->gtmp;
		for (i = 0; i < n; ++i)
			if (flag[i]) q->g[i] += z * p->g[i];
	}
	return 0;
}

int kad_op_sample_normal(kad_node_t *p, int action) /* not tested */
{
	int i, n;
	kad_node_t *q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_ALLOC) {
		if (kad_is_back(p->child[0]))
			p->gtmp = realloc(p->gtmp, n * sizeof(float));
	} else if (action == KAD_FORWARD) {
		float *r = (float*)p->gtmp;
		for (i = 0; i < n; ++i) {
			float z;
			z = (float)kad_drand_normal(p->ptr);
			p->x[i] = q->x[i] * z;
			if (r) r[i] = z;
		}
	} else if (action == KAD_BACKWARD && kad_is_back(p->child[0])) {
		float *r = (float*)p->gtmp;
		for (i = 0; i < n; ++i)
			q->g[i] += p->g[i] * r[i];
	}
	return 0;
}

int kad_op_slice(kad_node_t *p, int action)
{
	kad_node_t *q = p->child[0];
	int32_t *aux, *range;
	int i, axis, d0, d1;

	assert(p->ptr);
	aux = (int32_t*)p->ptr, axis = aux[0], range = aux + 1;
	if (axis < 0 || axis >= q->n_d) return -1;
	for (i = 0, d0 = 1; i < axis; ++i) d0 *= q->d[i];
	for (i = axis + 1, d1 = 1; i < q->n_d; ++i) d1 *= q->d[i];
	if (action == KAD_SYNC_DIM) {
		if (range[0] >= range[1] || range[0] < 0 || range[1] > q->d[axis]) return -1;
		kad_copy_dim1(p, q);
		p->d[axis] = range[1] - range[0];
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < d0; ++i)
			memcpy(&p->x[i * p->d[axis] * d1], &q->x[(i * q->d[axis] + range[0]) * d1], (range[1] - range[0]) * d1 * sizeof(float));
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (i = 0; i < d0; ++i)
			kad_saxpy((range[1] - range[0]) * d1, 1.0f, &p->g[i * p->d[axis] * d1], &q->g[(i * q->d[axis] + range[0]) * d1]);
	}
	return 0;
}

int kad_op_concat(kad_node_t *p, int action)
{
	kad_node_t *q = p->child[0];
	int32_t *aux;
	int i, j, k, axis, d0, d1;

	assert(p->ptr);
	aux = (int32_t*)p->ptr, axis = aux[0];
	for (i = 0, d0 = 1; i < axis; ++i) d0 *= q->d[i];
	for (i = axis + 1, d1 = 1; i < q->n_d; ++i) d1 *= q->d[i];
	if (action == KAD_SYNC_DIM) {
		for (i = 1; i < p->n_child; ++i) {
			if (p->child[i]->n_d != q->n_d) return -1;
			for (j = 0; j < q->n_d; ++j)
				if (j != axis && q->d[j] != p->child[i]->d[j]) return -1;
		}
		kad_copy_dim1(p, q);
		for (i = 1; i < p->n_child; ++i)
			p->d[axis] += p->child[i]->d[axis];
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < d0; ++i)
			for (j = k = 0; j < p->n_child; ++j) {
				q = p->child[j];
				memcpy(&p->x[(i * p->d[axis] + k) * d1], &q->x[i * q->d[axis] * d1], q->d[axis] * d1 * sizeof(float));
				k += q->d[axis];
			}
	} else if (action == KAD_BACKWARD) {
		for (i = 0; i < d0; ++i)
			for (j = k = 0; j < p->n_child; ++j) {
				q = p->child[j];
				if (!kad_is_back(q)) continue;
				kad_saxpy(q->d[axis] * d1, 1.0f, &p->g[(i * p->d[axis] + k) * d1], &q->g[i * q->d[axis] * d1]);
				k += q->d[axis];
			}
	}
	return 0;
}

int kad_op_reshape(kad_node_t *p, int action)
{
	kad_node_t *q = p->child[0];

	if (action == KAD_SYNC_DIM) {
		if (p->ptr) {
			int32_t *aux = (int32_t*)p->ptr;
			int i, len = 1, n_missing = 0;
			p->n_d = p->ptr_size / 4;
			for (i = 0; i < p->n_d; ++i) p->d[i] = aux[i];
			for (i = 0; i < p->n_d; ++i)
				if (p->d[i] <= 0) ++n_missing;
				else len *= p->d[i];
			if (n_missing == 0 && len != kad_len(q)) return -1;
			if (n_missing > 1) { /* attempt to infer missing dimensions except the last one */
				for (i = 0; i < p->n_d; ++i)
					if (p->d[i] <= 0 && i < q->n_d) {
						p->d[i] = q->d[i], len *= p->d[i];
						if (--n_missing == 1) break;
					}
				if (n_missing > 1) return -1;
			}
			if (n_missing == 1) { /* infer the last missing dimension */
				if (kad_len(q) % len != 0) return -1;
				for (i = 0; i < p->n_d; ++i)
					if (p->d[i] <= 0) p->d[i] = kad_len(q) / len;
			}
		} else kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		memcpy(p->x, q->x, kad_len(p) * sizeof(float));
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		kad_saxpy(kad_len(p), 1.0f, p->g, q->g);
	}
	return 0;
}

int kad_op_reverse(kad_node_t *p, int action)
{
	kad_node_t *q = p->child[0];
	int axis, i, j, n, d0, d1;

	axis = p->ptr? *(int32_t*)p->ptr : 0;
	if (axis < 0) axis += q->n_d;
	assert(axis >= 0 && axis < q->n_d);
	for (i = 0, d0 = 1; i < axis; ++i) d0 *= q->d[i];
	n = q->d[axis];
	for (i = axis + 1, d1 = 1; i < q->n_d; ++i) d1 *= q->d[i];
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < d0; ++i)
			for (j = 0; j < n; ++j)
				memcpy(&p->x[(i * n + n - 1 - j) * d1], &q->x[(i * n + j) * d1], d1 * sizeof(float));
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (i = 0; i < d0; ++i)
			for (j = 0; j < n; ++j)
				kad_saxpy(d1, 1.0f, &p->g[(i * n + n - 1 - j) * d1], &q->g[(i * n + j) * d1]);
	}
	return 0;
}

/********** Cost functions **********/

int kad_op_mse(kad_node_t *p, int action)
{
	kad_node_t *y1 = p->child[0]; /* test */
	kad_node_t *y0 = p->child[1]; /* truth */
	int i, n;

	n = kad_len(y0);
	if (action == KAD_SYNC_DIM) {
		if (n != kad_len(y1)) return -1;
		p->n_d = 0;
	} else if (action == KAD_FORWARD) {
		double cost = 0.0;
		for (i = 0; i < n; ++i)
			cost += (y1->x[i] - y0->x[i]) * (y1->x[i] - y0->x[i]);
		p->x[0] = (float)(cost / n);
	} else if (action == KAD_BACKWARD && kad_is_back(y1)) {
		float t = 2.0f * p->g[0] / n;
		for (i = 0; i < n; ++i)
			y1->g[i] += t * (y1->x[i] - y0->x[i]);
	}
	return 0;
}

int kad_op_ce_bin(kad_node_t *p, int action)
{
	static const float tiny = 1e-9f;
	kad_node_t *y1 = p->child[0]; /* test */
	kad_node_t *y0 = p->child[1]; /* truth */
	int i, n;

	n = kad_len(y0);
	if (action == KAD_SYNC_DIM) {
		if (n != kad_len(y1)) return -1;
		p->n_d = 0;
	} else if (action == KAD_FORWARD) {
		double cost = 0.0;
		for (i = 0; i < n; ++i) {
			if (y0->x[i] > 0.0f)
				cost += y0->x[i] * log(y0->x[i] / (y1->x[i] > tiny? y1->x[i] : tiny));
			if (1.0f - y0->x[i] > 0.0f)
				cost += (1.0f - y0->x[i]) * log((1.0f - y0->x[i]) / (1.0f - y1->x[i] > tiny? 1.0f - y1->x[i] : tiny));
		}
		p->x[0] = (float)(cost / n);
	} else if (action == KAD_BACKWARD && kad_is_back(y1)) {
		float t = p->g[0] / n;
		for (i = 0; i < n; ++i) {
			if (y0->x[i] > 0.0f)
				y1->g[i] -= t * y0->x[i] / (y1->x[i] > tiny? y1->x[i] : tiny);
			if (1.0f - y0->x[i] > 0.0f)
				y1->g[i] += t * (1.0f - y0->x[i]) / (1.0f - y1->x[i] > tiny? 1.0f - y1->x[i] : tiny);
		}
	}
	return 0;
}

int kad_op_ce_bin_neg(kad_node_t *p, int action)
{
	static const float tiny = 1e-9f;
	kad_node_t *y1 = p->child[0]; /* test */
	kad_node_t *y0 = p->child[1]; /* truth */
	int i, n;

	n = kad_len(y0);
	if (action == KAD_SYNC_DIM) {
		if (n != kad_len(y1)) return -1;
		p->n_d = 0;
	} else if (action == KAD_FORWARD) {
		double cost = 0.0;
		for (i = 0; i < n; ++i) {
			if (1.0f + y0->x[i] > 0.0f)
				cost += .5f * (1.0f + y0->x[i]) * log((1.0f + y0->x[i]) / (1.0f + y1->x[i] > tiny? 1.0f + y1->x[i] : tiny));
			if (1.0f - y0->x[i] > 0.0f)
				cost += .5f * (1.0f - y0->x[i]) * log((1.0f - y0->x[i]) / (1.0f - y1->x[i] > tiny? 1.0f - y1->x[i] : tiny));
		}
		p->x[0] = (float)(cost / n);
	} else if (action == KAD_BACKWARD && kad_is_back(y1)) {
		float t = p->g[0] / n;
		for (i = 0; i < n; ++i) {
			if (1.0f + y0->x[i] > 0.0f)
				y1->g[i] -= .5f * t * (1.0f + y0->x[i]) / (1.0f + y1->x[i] > tiny? 1.0f + y1->x[i] : tiny);
			if (1.0f - y0->x[i] > 0.0f)
				y1->g[i] += .5f * t * (1.0f - y0->x[i]) / (1.0f - y1->x[i] > tiny? 1.0f - y1->x[i] : tiny);
		}
	}
	return 0;
}

int kad_op_ce_multi(kad_node_t *p, int action)
{
	static const float tiny = 1e-9f;
	kad_node_t *y1 = p->child[0]; /* test */
	kad_node_t *y0 = p->child[1]; /* truth */
	kad_node_t *c = 0;
	int i, j, n1, d0;

	n1 = y0->d[y0->n_d - 1];
	d0 = kad_len(y0) / n1;
	if (p->n_child == 3) {
		c = p->child[2];
		assert(c->n_d == 1 && c->d[0] == n1);
	}
	if (action == KAD_SYNC_DIM) {
		if (kad_len(y0) != kad_len(y1) || y0->d[y0->n_d - 1] != y1->d[y1->n_d - 1]) return -1;
		p->n_d = 0;
	} else if (action == KAD_FORWARD) {
		double cost = 0.0;
		if (c == 0) {
			for (j = 0; j < d0; ++j) {
				float *x1 = &y1->x[j * n1], *x0 = &y0->x[j * n1];
				for (i = 0; i < n1; ++i)
					if (x0[i] > 0.0f)
						cost += x0[i] * log(x0[i] / (x1[i] > tiny? x1[i] : tiny));
			}
		} else {
			for (j = 0; j < d0; ++j) {
				float *x1 = &y1->x[j * n1], *x0 = &y0->x[j * n1];
				for (i = 0; i < n1; ++i)
					if (x0[i] > 0.0f)
						cost += c->x[i] * x0[i] * log(x0[i] / (x1[i] > tiny? x1[i] : tiny));
			}
		}
		p->x[0] = (float)(cost / d0);
	} else if (action == KAD_BACKWARD && kad_is_back(y1)) {
		float t = p->g[0] / d0;
		if (c == 0) {
			for (j = 0; j < d0; ++j) {
				float *g = &y1->g[j * n1], *x1 = &y1->x[j * n1], *x0 = &y0->x[j * n1];
				for (i = 0; i < n1; ++i)
					g[i] -= t * x0[i] / (x1[i] > tiny? x1[i] : tiny);
			}
		} else {
			for (j = 0; j < d0; ++j) {
				float *g = &y1->g[j * n1], *x1 = &y1->x[j * n1], *x0 = &y0->x[j * n1];
				for (i = 0; i < n1; ++i)
					g[i] -= t * c->x[i] * x0[i] / (x1[i] > tiny? x1[i] : tiny);
			}
		}
	}
	return 0;
}

/********** Normalization **********/

int kad_op_stdnorm(kad_node_t *p, int action)
{
	int i, j, n, m;
	kad_node_t *q = p->child[0];
	assert(q->n_d > 0);
	n = q->d[q->n_d - 1];
	m = kad_len(q) / n;
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_ALLOC) {
		p->gtmp = realloc(p->gtmp, m * sizeof(float));
	} else if (action == KAD_FORWARD) {
		float *si = (float*)p->gtmp;
		for (j = 0; j < m; ++j) {
			float *px = &p->x[j * n], *qx = &q->x[j * n];
			float avg, std_inv;
			double s;
			for (i = 0, s = 0.0; i < n; ++i) s += qx[i];
			avg = (float)(s / n);
			for (i = 0; i < n; ++i) px[i] = qx[i] - avg;
			for (i = 0, s = 0.0; i < n; ++i) s += px[i] * px[i];
			std_inv = s == 0.0? 1.0f : (float)(1.0 / sqrt(s / n));
			for (i = 0; i < n; ++i) px[i] *= std_inv;
			si[j] = std_inv;
		}
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		float *si = (float*)p->gtmp;
		for (j = 0; j < m; ++j) {
			float *pg = &p->g[j * n], *qg = &q->g[j * n], *px = &p->x[j * n], std_inv = si[j];
			double s, t;
			for (i = 0, s = t = 0.0; i < n; ++i)
				s += pg[i], t += px[i] * pg[i];
			s /= n, t /= n;
			for (i = 0; i < n; ++i)
				qg[i] += std_inv * (pg[i] - s - px[i] * t);
		}
	}
	return 0;
}

/********** Activation functions **********/

int kad_op_sigm(kad_node_t *p, int action)
{
	int i, n;
	kad_node_t *q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < n; ++i)
			p->x[i] = 1.0f / (1.0f + expf(-q->x[i]));
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (i = 0; i < n; ++i)
			q->g[i] += p->g[i] * (p->x[i] * (1.0f - p->x[i]));
	}
	return 0;
}

int kad_op_tanh(kad_node_t *p, int action)
{
	int i, n;
	kad_node_t *q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < n; ++i) {
			if (q->x[i] < -20.0f) p->x[i] = -1.0f;
			else {
				float y;
				y = expf(-2.0f * q->x[i]);
				p->x[i] = (1.0f - y) / (1.0f + y);
			}
		}
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (i = 0; i < n; ++i)
			q->g[i] += p->g[i] * (1.0f - p->x[i] * p->x[i]);
	}
	return 0;
}

int kad_op_relu(kad_node_t *p, int action)
{
	int i, n;
	kad_node_t *q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < n; ++i)
			p->x[i] = q->x[i] > 0.0f? q->x[i] : 0.0f;
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (i = 0; i < n; ++i)
			if (q->x[i] > 0.0f)
				q->g[i] += p->g[i];
	}
	return 0;
}

int kad_op_sin(kad_node_t *p, int action)
{
	int i, n;
	kad_node_t *q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		for (i = 0; i < n; ++i) p->x[i] = sinf(q->x[i]);
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (i = 0; i < n; ++i)
			q->g[i] += p->g[i] * cosf(q->x[i]);
	}
	return 0;
}

int kad_op_softmax(kad_node_t *p, int action)
{
	int i, j, n1, d0;
	kad_node_t *q = p->child[0];

	n1 = q->d[q->n_d - 1];
	d0 = kad_len(q) / n1;
	if (action == KAD_SYNC_DIM) {
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		for (j = 0; j < d0; ++j) {
			float s, max, *x = &q->x[j * n1], *y = &p->x[j * n1];
			for (i = 0, max = -FLT_MAX; i < n1; ++i)
				max = max > x[i]? max : x[i];
			for (i = 0, s = 0.0f; i < n1; ++i) {
				y[i] = expf(x[i] - max);
				s += y[i];
			}
			for (i = 0, s = 1.0f / s; i < n1; ++i) y[i] *= s;
		}
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		for (j = 0; j < d0; ++j) {
			float s, *g = &p->g[j * n1], *y = &p->x[j * n1], *h = &q->g[j * n1];
			for (i = 0, s = 0.0f; i < n1; ++i)
				s += g[i] * y[i];
			for (i = 0; i < n1; ++i)
				h[i] += y[i] * (g[i] - s);
		}
	}
	return 0;
}

/********** Multi-node pooling **********/

int kad_op_avg(kad_node_t *p, int action)
{
	int i, n;
	float tmp;
	kad_node_t *q;

	assert(p->n_child > 0);
	tmp = 1.0f / p->n_child;
	q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		for (i = 1; i < p->n_child; ++i)
			if (kad_len(p->child[i]) != n) return -1;
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		memcpy(p->x, q->x, n * sizeof(float));
		for (i = 1; i < p->n_child; ++i)
			kad_saxpy(n, 1.0f, p->child[i]->x, p->x);
		for (i = 0; i < n; ++i) p->x[i] *= tmp;
	} else if (action == KAD_BACKWARD) {
		for (i = 0; i < p->n_child; ++i)
			if (kad_is_back(p->child[i]))
				kad_saxpy(n, tmp, p->g, p->child[i]->g);
	}
	return 0;
}

int kad_op_max(kad_node_t *p, int action)
{
	int i, n;
	kad_node_t *q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		int *max_j;
		for (i = 1; i < p->n_child; ++i)
			if (kad_len(p->child[i]) != n) return -1;
		kad_copy_dim1(p, q);
		max_j = (int*)calloc(n, sizeof(int));
		p->gtmp = max_j;
	} else if (action == KAD_FORWARD) {
		int j, *max_j = (int*)p->gtmp;
		memset(max_j, 0, n * sizeof(int));
		memcpy(p->x, q->x, n * sizeof(float));
		for (j = 1; j < p->n_child; ++j)
			for (i = 0, q = p->child[j]; i < n; ++i)
				if (q->x[i] > p->x[i]) p->x[i] = q->x[i], max_j[i] = j;
	} else if (action == KAD_BACKWARD) {
		int *max_j = (int*)p->gtmp;
		for (i = 0; i < n; ++i)
			p->child[max_j[i]]->g[i] += p->g[i];
	}
	return 0;
}

int kad_op_stack(kad_node_t *p, int action) /* TODO: allow axis, as in TensorFlow */
{
	int i, n, axis = 0;
	kad_node_t *q;

	assert(p->n_child > 0);
	q = p->child[0];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		for (i = 1; i < p->n_child; ++i)
			if (kad_len(p->child[i]) != n) return -1;
		p->n_d = q->n_d + 1;
		for (i = 0; i < axis; ++i) p->d[i] = q->d[i];
		p->d[axis] = p->n_child;
		for (; i < q->n_d; ++i) p->d[i+1] = q->d[i];
	} else if (action == KAD_FORWARD) { /* TODO: doesn't work when axis != 0 */
		for (i = 0; i < p->n_child; ++i)
			memcpy(&p->x[i * n], p->child[i]->x, n * sizeof(float));
	} else if (action == KAD_BACKWARD) {
		for (i = 0; i < p->n_child; ++i)
			if (kad_is_back(p->child[i]))
				kad_saxpy(n, 1.0f, &p->g[i * n], p->child[i]->g);
	}
	return 0;
}

int kad_op_select(kad_node_t *p, int action)
{
	kad_node_t *q;
	int i, n, which;

	which = *(int32_t*)p->ptr;
	if (which < 0) which += p->n_child;
	assert(which >= 0 && which < p->n_child);
	q = p->child[which];
	n = kad_len(q);
	if (action == KAD_SYNC_DIM) {
		for (i = 0; i < p->n_child; ++i)
			if (p->child[i]->n_d != q->n_d || kad_len(p->child[i]) != n)
				break;
		if (i < p->n_child) return -1;
		kad_copy_dim1(p, q);
	} else if (action == KAD_FORWARD) {
		memcpy(p->x, q->x, n * sizeof(float));
	} else if (action == KAD_BACKWARD && kad_is_back(q)) {
		kad_saxpy(n, 1.0f, p->g, q->g);
	}
	return 0;
}

/********** 2D convolution **********/

static void conv_rot180(int d0, int d1, float *x) /* rotate/reverse a weight martix */
{
	int i, j;
	for (i = 0; i < d0; ++i) {
		float tmp, *xi = &x[i * d1];
		for (j = 0; j < d1>>1; ++j)
			tmp = xi[j], xi[j] = xi[d1-1-j], xi[d1-1-j] = tmp;
	}
}

static void conv2d_move_1to3(int d[4], const float *x, float *y) /* convert the NCHW shape to the NHWC shape */
{
	int i, j, k, l;
	for (i = 0; i < d[0]; ++i)
		for (j = 0; j < d[1]; ++j)
			for (k = 0; k < d[2]; ++k) {
				int ik = (i * d[2] + k) * d[3], ijk = ((i * d[1] + j) * d[2] + k) * d[3];
				for (l = 0; l < d[3]; ++l)
					y[(ik + l) * d[1] + j] = x[ijk + l];
			}
}

static void conv2d_add_3to1(int d[4], const float *y, float *x) /* convert the NHWC shape back to NCHW and add to another NCHW-shaped array */
{
	int i, j, k, l;
	for (i = 0; i < d[0]; ++i)
		for (j = 0; j < d[1]; ++j)
			for (k = 0; k < d[2]; ++k) {
				int ik = (i * d[2] + k) * d[3], ijk = ((i * d[1] + j) * d[2] + k) * d[3];
				for (l = 0; l < d[3]; ++l)
					x[ijk + l] += y[(ik + l) * d[1] + j];
			}
}

#define conv_out_size(in_size, aux) (((in_size) - (aux)->kernel_size + (aux)->pad[0] + (aux)->pad[1]) / (aux)->stride + 1)

#define process_row_for(_xx, _ww, _yy, _wn, _pn, _stride, _pad, _t) do { \
	int j, l; \
	if (_stride > 1) { \
		for (l = 0; l < _wn; ++l) { \
			const float *xl = &_xx[l - _pad]; \
			for (j = 0; j < _pn; ++j, xl += _stride) _t[j] = *xl; \
			kad_saxpy(_pn, _ww[l], _t, _yy); \
		} \
	} else for (l = 0; l < _wn; ++l) kad_saxpy(_pn, _ww[l], &_xx[l - _pad], _yy); \
} while (0)

#define process_row_back_x(_xx, _ww, _yy, _wn, _pn, _stride, _pad, _t) do { \
	int j, l; \
	if (_stride > 1) { \
		for (l = 0; l < _wn; ++l) { \
			float *xl = &_xx[l - _pad]; \
			memset(_t, 0, _pn * sizeof(float)); \
			kad_saxpy(_pn, _ww[l], _yy, _t); \
			for (j = 0; j < _pn; ++j, xl += _stride) *xl += _t[j]; \
		} \
	} else for (l = 0; l < _wn; ++l) kad_saxpy(_pn, _ww[l], _yy, &_xx[l - _pad]); \
} while (0)

#define process_row_back_w(_xx, _ww, _yy, _wn, _pn, _stride, _pad, _t) do { \
	int j, l; \
	if (_stride > 1) { \
		for (l = 0; l < _wn; ++l) { \
			const float *xl = &_xx[l - _pad]; \
			for (j = 0; j < _pn; ++j, xl += _stride) _t[j] = *xl; \
			_ww[l] += kad_sdot(_pn, _yy, _t); \
		} \
	} else for (l = 0; l < _wn; ++l) _ww[l] += kad_sdot(_pn, _yy, &_xx[l - _pad]); \
} while (0)

/* Forward and backward passes are implemented with two different algorithms.
 * The first is faster for small kernels with few input channels; otherwise the
 * second algorithm is faster. Both algorithms should produce identical
 * results, up to the precision of "float".
 */
int kad_op_conv2d(kad_node_t *p, int action) /* in the number-channel-height-width (NCHW) shape */
{
#define conv2d_loop1(_x, _w, _y, _tmp, _row_func) do { /* for the NCHW shape */ \
		int n, c1, c0, i, k, ii; \
		for (n = 0; n < q->d[0]; ++n) /* mini-batch */ \
			for (c1 = 0; c1 < w->d[0]; ++c1) /* output channel */ \
				for (c0 = 0; c0 < w->d[1]; ++c0) /* input channel */ \
					for (k = 0; k < w->d[2]; ++k) { /* kernel row */ \
						float *_ww = &(_w)[((c1 * w->d[1] + c0) * w->d[2] + k) * w->d[3]]; \
						for (i = 0, ii = k - aux[0].pad[0]; i < p->d[2] && ii >= 0 && ii < q->d[2]; ++i, ii += aux[0].stride) { /* output row */ \
							float *_xx = &(_x)[((n * q->d[1] + c0) * q->d[2] + ii) * q->d[3]]; \
							float *_yy = &(_y)[((n * p->d[1] + c1) * p->d[2] + i)  * p->d[3]]; \
							if (x_padded) { \
								memcpy(x_padded + aux[1].pad[0], _xx, q->d[3] * sizeof(float)); \
								_xx = x_padded + aux[1].pad[0]; \
							} \
							_row_func(_xx, _ww, _yy, w->d[3], p->d[3], aux[1].stride, aux[1].pad[0], (_tmp)); \
						} /* ~i */ \
					} /* ~k, c0, c1, n */ \
	} while (0)

#define conv2d_loop2(_x, _w, _y, _code) do { /* for the NHWC shape */ \
		int n, c1, i, j, k, ii, j_skip = aux[1].stride * q->d[1], m = w->d[3] * w->d[1]; \
		for (n = 0; n < q->d[0]; ++n) /* mini-batch */ \
			for (c1 = 0; c1 < w->d[0]; ++c1) /* output channel */ \
				for (k = 0; k < w->d[2]; ++k) { /* kernel row */ \
					float *_ww = &(_w)[(c1 * w->d[2] + k) * m]; \
					for (i = 0, ii = k - aux[0].pad[0]; i < p->d[2] && ii >= 0 && ii < q->d[2]; ++i, ii += aux[0].stride) { /* output and input row */ \
						float *_xx = &(_x)[(n * q->d[2] + ii) * q->d[3] * q->d[1]]; \
						float *_yy = &(_y)[((n * p->d[1] + c1) * p->d[2] + i) * p->d[3]]; \
						if (x_padded) { \
							memcpy(x_padded + aux[1].pad[0] * q->d[1], _xx, q->d[3] * q->d[1] * sizeof(float)); \
							_xx = x_padded; \
						} \
						for (j = 0; j < p->d[3]; ++j, _xx += j_skip, ++_yy) _code; /* output and input column */ \
					} /* ~i */ \
				} /* ~k, c1, n */ \
	} while (0)

	conv_conf_t *aux = (conv_conf_t*)p->ptr;
	kad_node_t *q = p->child[0], *w = p->child[1];
	float *t = 0, *q1 = 0, *w1 = 0, *x_padded = 0;
	int algo_switch = 0;

	if (action == KAD_FORWARD || action == KAD_BACKWARD) { /* allocate working space */
		if (w->d[3] * w->d[1] < 16) {
			t = (float*)malloc(p->d[3] * sizeof(float));
			x_padded = aux[1].pad[0] + aux[1].pad[1] > 0? (float*)calloc(q->d[3] + aux[1].pad[0] + aux[1].pad[1], sizeof(float)) : 0;
		} else {
			q1 = (float*)malloc(kad_len(q) * sizeof(float));
			w1 = (float*)malloc(kad_len(w) * sizeof(float));
			x_padded = aux[1].pad[0] + aux[1].pad[1] > 0? (float*)calloc((q->d[3] + aux[1].pad[0] + aux[1].pad[1]) * q->d[1], sizeof(float)) : 0;
			algo_switch = 1;
		}
	}
	if (action == KAD_SYNC_DIM) {
		if (q->n_d != 4 || w->n_d != 4) return -1;
		if (q->d[1] != w->d[1]) return -1; /* unmatched input channels */
		p->n_d = 4;
		p->d[0] = q->d[0], p->d[1] = w->d[0], p->d[2] = conv_out_size(q->d[2], &aux[0]), p->d[3] = conv_out_size(q->d[3], &aux[1]);
	} else if (action == KAD_FORWARD) {
		conv_rot180(w->d[0] * w->d[1], w->d[2] * w->d[3], w->x);
		memset(p->x, 0, kad_len(p) * sizeof(float));
		if (!algo_switch) { /* this is the first algorithm */
			conv2d_loop1(q->x, w->x, p->x, t, process_row_for);
		} else { /* this is the second algorithm */
			conv2d_move_1to3(q->d, q->x, q1);
			conv2d_move_1to3(w->d, w->x, w1);
			conv2d_loop2(q1, w1, p->x, (*_yy += kad_sdot(m, _ww, _xx)));
		}
		conv_rot180(w->d[0] * w->d[1], w->d[2] * w->d[3], w->x);
	} else if (action == KAD_BACKWARD) {
		if (kad_is_back(p->child[0])) { /* backprop to the input array */
			conv_rot180(w->d[0] * w->d[1], w->d[2] * w->d[3], w->x);
			if (!algo_switch) {
				conv2d_loop1(q->g, w->x, p->g, t, process_row_back_x);
			} else {
				memset(q1, 0, kad_len(q) * sizeof(float));
				conv2d_move_1to3(w->d, w->x, w1);
				conv2d_loop2(q1, w1, p->g, kad_saxpy(m, *_yy, _ww, _xx));
				conv2d_add_3to1(q->d, q1, q->g);
			}
			conv_rot180(w->d[0] * w->d[1], w->d[2] * w->d[3], w->x);
		}
		if (kad_is_back(p->child[1])) { /* backprop to the weight matrix */
			conv_rot180(w->d[0] * w->d[1], w->d[2] * w->d[3], w->g);
			if (!algo_switch) {
				conv2d_loop1(q->x, w->g, p->g, t, process_row_back_w);
			} else {
				conv2d_move_1to3(q->d, q->x, q1);
				memset(w1, 0, kad_len(w) * sizeof(float));
				conv2d_loop2(q1, w1, p->g, kad_saxpy(m, *_yy, _xx, _ww));
				conv2d_add_3to1(w->d, w1, w->g);
			}
			conv_rot180(w->d[0] * w->d[1], w->d[2] * w->d[3], w->g);
		}
	}
	free(t); free(q1); free(w1); free(x_padded);
	return 0;
}

int kad_op_max2d(kad_node_t *p, int action)
{
	conv_conf_t *aux = (conv_conf_t*)p->ptr;
	kad_node_t *q = p->child[0];
	if (action == KAD_SYNC_DIM) {
		if (q->n_d != 4) return -1;
		p->n_d = 4;
		p->d[0] = q->d[0], p->d[1] = q->d[1], p->d[2] = conv_out_size(q->d[2], &aux[0]), p->d[3] = conv_out_size(q->d[3], &aux[1]);
	} else if (action == KAD_ALLOC) {
		p->gtmp = realloc(p->gtmp, kad_len(p) * sizeof(int));
	} else if (action == KAD_FORWARD) {
		int rest = 1, len, t, i;
		int *f = (int*)p->gtmp;
		len = kad_len(p);
		for (i = 0; i < len; ++i) p->x[i] = -FLT_MAX;
		for (i = 0; i < p->n_d - 2; ++i) rest *= p->d[i];
		for (t = 0; t < rest; ++t) {
			int i, j, k, l, p_row = p->d[p->n_d - 2], p_col = p->d[p->n_d - 1];
			for (i = 0; i < p_row; ++i) {
				int u = (t * p_row + i) * p_col;
				for (k = 0; k < aux[0].kernel_size; ++k) {
					int v, v0, v_end, ii = i * aux[0].stride + k - aux[0].pad[0];
					if (ii < 0 || ii >= q->d[p->n_d - 2]) continue;
					v0 = (t * q->d[p->n_d - 2] + ii) * q->d[p->n_d - 1];
					v_end = v0 + q->d[p->n_d - 1];
					for (l = 0; l < aux[1].kernel_size; ++l)
						for (j = 0, v = v0 + (l > aux[1].pad[0]? l - aux[1].pad[0] : 0); j < p_col && v < v_end; ++j, v += aux[1].stride)
							if (p->x[u + j] < q->x[v])
								p->x[u + j] = q->x[v], f[u + j] = v;
				} /* ~k */
			} /* ~i */
		}
	} else if (action == KAD_BACKWARD) {
		int i, len, *f = (int*)p->gtmp;
		len = kad_len(p);
		for (i = 0; i < len; ++i) q->g[f[i]] += p->g[i];
	}
	return 0;
}

/********** 1D convolution **********/

static void conv1d_move_1to2(int d[3], const float *x, float *y)
{
	int i, j, k;
	for (k = 0; k < d[0]; ++k)
		for (j = 0; j < d[1]; ++j)
			for (i = 0; i < d[2]; ++i)
				y[(k * d[2] + i) * d[1] + j] = x[(k * d[1] + j) * d[2] + i];
}

static void conv1d_add_2to1(int d[3], const float *y, float *x)
{
	int i, j, k;
	for (k = 0; k < d[0]; ++k)
		for (j = 0; j < d[1]; ++j)
			for (i = 0; i < d[2]; ++i)
				x[(k * d[1] + j) * d[2] + i] += y[(k * d[2] + i) * d[1] + j];
}

int kad_op_conv1d(kad_node_t *p, int action) /* in the number-channel-width (NCW) shape */
{
#define conv1d_loop1(_x, _w, _y, _tmp, _row_func) do { /* for the NCW shape */ \
		int n, c1, c0; \
		for (n = 0; n < q->d[0]; ++n) /* mini-batch */ \
			for (c1 = 0; c1 < w->d[0]; ++c1) /* output channel */ \
				for (c0 = 0; c0 < w->d[1]; ++c0) { /* input channel */ \
					float *_ww = &(_w)[(c1 * w->d[1] + c0) * w->d[2]]; \
					float *_xx = &(_x)[(n  * q->d[1] + c0) * q->d[2]]; \
					float *_yy = &(_y)[(n  * p->d[1] + c1) * p->d[2]]; \
					if (x_padded) { \
						memcpy(x_padded + aux->pad[0], _xx, q->d[2] * sizeof(float)); \
						_xx = x_padded + aux->pad[0]; \
					} \
					_row_func(_xx, _ww, _yy, w->d[2], p->d[2], aux->stride, aux->pad[0], (_tmp)); \
				} /* ~c0, c1, n */ \
	} while (0)

#define conv1d_loop2(_x, _w, _y, _code) do { /* for the NWC shape */ \
		int n, c1, j, j_skip = aux->stride * q->d[1], m = w->d[2] * w->d[1]; \
		for (n = 0; n < q->d[0]; ++n) /* mini-batch */ \
			for (c1 = 0; c1 < w->d[0]; ++c1) { /* output channel */ \
				float *_ww = &(_w)[c1 * m]; \
				float *_xx = &(_x)[n * q->d[1] * q->d[2]]; \
				float *_yy = &(_y)[(n * p->d[1] + c1) * p->d[2]]; \
				if (x_padded) { \
					memcpy(x_padded + aux->pad[0] * q->d[1], _xx, q->d[2] * q->d[1] * sizeof(float)); \
					_xx = x_padded; \
				} \
				for (j = 0; j < p->d[2]; ++j, _xx += j_skip, ++_yy) _code; \
			} /* ~c1, n */ \
	} while (0)

	conv_conf_t *aux = (conv_conf_t*)p->ptr;
	kad_node_t *q = p->child[0], *w = p->child[1];
	float *t = 0, *q1 = 0, *w1 = 0, *x_padded = 0;
	int algo_switch = 0;

	if (action == KAD_FORWARD || action == KAD_BACKWARD) { /* allocate working space */
		if (w->d[2] * w->d[1] < 32) {
			t = (float*)malloc(p->d[2] * sizeof(float));
			x_padded = aux->pad[0] + aux->pad[1] > 0? (float*)calloc(q->d[2] + aux->pad[0] + aux->pad[1], sizeof(float)) : 0;
		} else {
			q1 = (float*)malloc(kad_len(q) * sizeof(float));
			w1 = (float*)malloc(kad_len(w) * sizeof(float));
			x_padded = aux->pad[0] + aux->pad[1] > 0? (float*)calloc((q->d[2] + aux->pad[0] + aux->pad[1]) * q->d[1], sizeof(float)) : 0;
			algo_switch = 1;
		}
	}
	if (action == KAD_SYNC_DIM) {
		if (q->n_d != 3 || w->n_d != 3) return -1;
		if (q->d[1] != w->d[1]) return -1; /* unmatched input channels */
		p->n_d = 3;
		p->d[0] = q->d[0], p->d[1] = w->d[0], p->d[2] = conv_out_size(q->d[2], aux);
	} else if (action == KAD_FORWARD) {
		conv_rot180(w->d[0] * w->d[1], w->d[2], w->x);
		memset(p->x, 0, kad_len(p) * sizeof(float));
		if (!algo_switch) { /* this is the first algorithm */
			conv1d_loop1(q->x, w->x, p->x, t, process_row_for);
		} else { /* this is the second algorithm */
			conv1d_move_1to2(q->d, q->x, q1);
			conv1d_move_1to2(w->d, w->x, w1);
			conv1d_loop2(q1, w1, p->x, (*_yy += kad_sdot(m, _ww, _xx)));
		}
		conv_rot180(w->d[0] * w->d[1], w->d[2], w->x);
	} else if (action == KAD_BACKWARD) {
		if (kad_is_back(p->child[0])) { /* backprop to the input array */
			conv_rot180(w->d[0] * w->d[1], w->d[2], w->x);
			if (!algo_switch) {
				conv1d_loop1(q->g, w->x, p->g, t, process_row_back_x);
			} else {
				memset(q1, 0, kad_len(q) * sizeof(float));
				conv1d_move_1to2(w->d, w->x, w1);
				conv1d_loop2(q1, w1, p->g, kad_saxpy(m, *_yy, _ww, _xx));
				conv1d_add_2to1(q->d, q1, q->g);
			}
			conv_rot180(w->d[0] * w->d[1], w->d[2], w->x);
		}
		if (kad_is_back(p->child[1])) { /* backprop to the weight matrix */
			conv_rot180(w->d[0] * w->d[1], w->d[2], w->g);
			if (!algo_switch) {
				conv1d_loop1(q->x, w->g, p->g, t, process_row_back_w);
			} else {
				conv1d_move_1to2(q->d, q->x, q1);
				memset(w1, 0, kad_len(w) * sizeof(float));
				conv1d_loop2(q1, w1, p->g, kad_saxpy(m, *_yy, _xx, _ww));
				conv1d_add_2to1(w->d, w1, w->g);
			}
			conv_rot180(w->d[0] * w->d[1], w->d[2], w->g);
		}
	}
	free(t); free(q1); free(w1); free(x_padded);
	return 0;
}

int kad_op_max1d(kad_node_t *p, int action)
{
	conv_conf_t *aux = (conv_conf_t*)p->ptr;
	kad_node_t *q = p->child[0];
	if (action == KAD_SYNC_DIM) {
		if (q->n_d != 3) return -1;
		p->n_d = 3;
		p->d[0] = q->d[0], p->d[1] = q->d[1], p->d[2] = conv_out_size(q->d[2], aux);
	} else if (action == KAD_ALLOC) {
		p->gtmp = realloc(p->gtmp, kad_len(p) * sizeof(int));
	} else if (action == KAD_FORWARD) {
		int rest = 1, len, t, i;
		int *f = (int*)p->gtmp;
		len = kad_len(p);
		for (i = 0; i < len; ++i) p->x[i] = -FLT_MAX;
		for (i = 0; i < p->n_d - 1; ++i) rest *= p->d[i];
		for (t = 0; t < rest; ++t) {
			int j, l, p_width = p->d[p->n_d - 1];
			int u = t * p_width, v, v0 = t * q->d[p->n_d - 1], v_end = v0 + q->d[p->n_d - 1];
			for (l = 0; l < aux->kernel_size; ++l)
				for (j = 0, v = v0 + (l > aux->pad[0]? l - aux->pad[0] : 0); j < p_width && v < v_end; ++j, v += aux->stride)
					if (p->x[u + j] < q->x[v])
						p->x[u + j] = q->x[v], f[u + j] = v;
		}
	} else if (action == KAD_BACKWARD) {
		int i, len, *f = (int*)p->gtmp;
		len = kad_len(p);
		for (i = 0; i < len; ++i) q->g[f[i]] += p->g[i];
	}
	return 0;
}

int kad_op_avg1d(kad_node_t *p, int action)
{
	conv_conf_t *aux = (conv_conf_t*)p->ptr;
	kad_node_t *q = p->child[0];
	if (action == KAD_SYNC_DIM) {
		if (q->n_d != 3) return -1;
		p->n_d = 3;
		p->d[0] = q->d[0], p->d[1] = q->d[1], p->d[2] = conv_out_size(q->d[2], aux);
	} else if (action == KAD_ALLOC) {
		p->gtmp = realloc(p->gtmp, kad_len(p) * sizeof(int));
	} else if (action == KAD_FORWARD) {
		int rest = 1, len, t, i;
		int *f = (int*)p->gtmp;
		len = kad_len(p);
		for (i = 0; i < len; ++i) p->x[i] = 0.0f, f[i] = 0;
		for (i = 0; i < p->n_d - 1; ++i) rest *= p->d[i];
		for (t = 0; t < rest; ++t) {
			int j, l, p_width = p->d[p->n_d - 1];
			int u = t * p_width, v, v0 = t * q->d[p->n_d - 1], v_end = v0 + q->d[p->n_d - 1];
			for (l = 0; l < aux->kernel_size; ++l)
				for (j = 0, v = v0 + (l > aux->pad[0]? l - aux->pad[0] : 0); j < p_width && v < v_end; ++j, v += aux->stride)
					p->x[u + j] += q->x[v], ++f[u + j];
		}
		for (i = 0; i < len; ++i) p->x[i] /= f[i];
	} else if (action == KAD_BACKWARD) {
		int rest = 1, t, i;
		int *f = (int*)p->gtmp;
		for (i = 0; i < p->n_d - 1; ++i) rest *= p->d[i];
		for (t = 0; t < rest; ++t) {
			int j, l, p_width = p->d[p->n_d - 1];
			int u = t * p_width, v, v0 = t * q->d[p->n_d - 1], v_end = v0 + q->d[p->n_d - 1];
			for (l = 0; l < aux->kernel_size; ++l)
				for (j = 0, v = v0 + (l > aux->pad[0]? l - aux->pad[0] : 0); j < p_width && v < v_end; ++j, v += aux->stride)
					q->g[v] += p->g[u + j] / f[u + j];
		}
	}
	return 0;
}

/********** List of operators **********/

kad_op_f kad_op_list[KAD_MAX_OP] = {
	0,
	kad_op_add,        /* 1:  element-wise addition */
	kad_op_mul,        /* 2:  element-wise multiplication */
	kad_op_cmul,       /* 3:  column multiplication */
	kad_op_ce_bin_neg, /* 4:  binary cross-entropy for (-1,1) */
	kad_op_square,     /* 5:  square */
	kad_op_sigm,       /* 6:  sigmoid */
	kad_op_tanh,       /* 7:  tanh */
	kad_op_relu,       /* 8:  ReLU */
	kad_op_matmul,     /* 9:  matrix multiplication */
	kad_op_avg,        /* 10: general average pooling (not for ConvNet) */
	kad_op_1minus,     /* 11: 1-x */
	kad_op_select,     /* 12: choose between one of the children */
	kad_op_ce_multi,   /* 13: multi-class cross-entropy */
	kad_op_softmax,    /* 14: softmax */
	kad_op_dropout,    /* 15: dropout */
	kad_op_conv2d,     /* 16: 2D convolution */
	kad_op_max2d,      /* 17: 2D max pooling (for 2D ConvNet) */
	kad_op_conv1d,     /* 18: 1D convolution */
	kad_op_max1d,      /* 19: 1D max pooling (for 1D ConvNet) */
	kad_op_slice,      /* 20: slice data at a dimension */
	kad_op_max,        /* 21: general max pooling */
	kad_op_ce_bin,     /* 22: binary cross-entropy for (0,1) */
	kad_op_sub,        /* 23: element-wise subtraction */
	kad_op_sample_normal,  /* 24: sample from a normal distribution */
	kad_op_reduce_sum,     /* 25 */
	kad_op_reduce_mean,    /* 26 */
	kad_op_log,        /* 27: log() */
	kad_op_avg1d,      /* 28: 1D average pooling (for 1D ConvNet) */
	kad_op_mse,        /* 29: mean square error */
	kad_op_reshape,    /* 30 */
	kad_op_concat,     /* 31 */
	kad_op_stdnorm,    /* 32: layer normalization */
	kad_op_exp,        /* 33: exp() */
	kad_op_sin,        /* 34: sin() */
	kad_op_stack,      /* 35: tf.stack, but on the first axis only */
	kad_op_reverse     /* 36: tf.reverse, but on one axis only */
};

char *kad_op_name[KAD_MAX_OP] = {
	0, "add", "mul", "cmul", "ce_bin_neg", "square", "sigm", "tanh", "relu", "matmul", "avg", "1minus", "select", "ce_multi", "softmax",
	"dropout", "conv2d", "max2d", "conv1d", "max1d", "slice", "max", "ce_bin", "sub", "sample_normal", "reduce_sum", "reduce_mean", "log",
	"avg1d", "mse", "reshape", "concat", "stdnorm", "exp", "sin", "stack", "reverse"
};

/**************************
 *** Debugging routines ***
 **************************/

void kad_trap_fe(void)
{
#ifdef __SSE__
	_MM_SET_EXCEPTION_MASK(_MM_GET_EXCEPTION_MASK() & ~(_MM_MASK_INVALID | _MM_MASK_DIV_ZERO));
#endif
}

void kad_print_graph(FILE *fp, int n, kad_node_t **v)
{
	int i, j;
	for (i = 0; i < n; ++i) v[i]->tmp = i;
	for (i = 0; i < n; ++i) {
		kad_node_t *p = v[i];
		fprintf(fp, "%d\t%x:%x\t%d\t", i, p->flag, p->ext_flag, p->ext_label);
		if (p->pre) fprintf(fp, "%d\t", p->pre->tmp);
		else fprintf(fp, ".\t");
		fputs("[", fp);
		for (j = 0; j < p->n_d; ++j) {
			if (j) fputc(',', fp);
			fprintf(fp, "%d", p->d[j]);
		}
		fprintf(fp, "]\t");
		if (p->n_child) {
			fprintf(fp, "%s(", kad_op_name[p->op]);
			for (j = 0; j < p->n_child; ++j) {
				if (j) fputc(',', fp);
				fprintf(fp, "$%d", p->child[j]->tmp);
			}
			fprintf(fp, ")");
		} else fprintf(fp, "%s", kad_is_feed(p)? "feed" : kad_is_var(p)? "var" : kad_is_const(p)? "const" : "N/A");
		fputc('\n', fp);
	}
	for (i = 0; i < n; ++i) v[i]->tmp = 0;
}

static void kad_add_delta(int n, kad_node_t **a, float c, float *delta)
{
	int i, k;
	for (i = k = 0; i < n; ++i)
		if (kad_is_var(a[i])) {
			kad_saxpy(kad_len(a[i]), c, &delta[k], a[i]->x);
			k += kad_len(a[i]);
		}
}

void kad_check_grad(int n, kad_node_t **a, int from)
{
	const float eps = 1e-5f, rel = 1e-7f / eps;
	int i, k, n_var;
	float *g0, *delta, f0, f_minus, f_plus, s0, s1, rel_err, p_m_err;
	n_var = kad_size_var(n, a);
	g0 = (float*)calloc(n_var, sizeof(float));
	f0 = *kad_eval_at(n, a, from);
	kad_grad(n, a, from);
	for (i = k = 0; i < n; ++i)
		if (kad_is_var(a[i])) {
			memcpy(&g0[k], a[i]->g, kad_len(a[i]) * sizeof(float));
			k += kad_len(a[i]);
		}
	delta = (float*)calloc(n_var, sizeof(float));
	for (k = 0; k < n_var; ++k) delta[k] = (float)kad_drand(0) * eps;
	kad_add_delta(n, a, 1.0f, delta);
	f_plus = *kad_eval_at(n, a, from);
	kad_add_delta(n, a, -2.0f, delta);
	f_minus = *kad_eval_at(n, a, from);
	kad_add_delta(n, a, 1.0f, delta);
	s0 = kad_sdot(n_var, g0, delta);
	s1 = .5f * (f_plus - f_minus);
	fprintf(stderr, "Gradient check -- %g <=> %g @ %g -- ", s0/eps, s1/eps, f0);
	if (fabs(s1) >= rel * eps) {
		rel_err = fabsf(fabsf(s0) - fabsf(s1)) / (fabsf(s0) + fabsf(s1));
		p_m_err = fabsf(f_plus + f_minus - 2.0f * f0) / fabsf(f_plus - f_minus);
		fprintf(stderr, "rel_err:%g p_m_err:%g -- ", rel_err, p_m_err);
		if (rel_err >= rel && rel_err > p_m_err) fprintf(stderr, "failed\n");
		else fprintf(stderr, "passed\n");
	} else fprintf(stderr, "skipped\n");
	free(delta); free(g0);
}
