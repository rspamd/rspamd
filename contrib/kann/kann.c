#include "config.h"

#include <math.h>
#include <float.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include "kann.h"

int kann_verbose = 3;

/******************************************
 *** @@BASIC: fundamental KANN routines ***
 ******************************************/

static void kad_ext_collate(int n, kad_node_t **a, float **_x, float **_g, float **_c)
{
	int i, j, k, l, n_var;
	float *x, *g, *c;
	n_var = kad_size_var(n, a);
	x = *_x = (float*)realloc(*_x, n_var * sizeof(float));
	g = *_g = (float*)realloc(*_g, n_var * sizeof(float));
	c = *_c = (float*)realloc(*_c, kad_size_const(n, a) * sizeof(float));
	memset(g, 0, n_var * sizeof(float));
	for (i = j = k = 0; i < n; ++i) {
		kad_node_t *v = a[i];
		if (kad_is_var(v)) {
			l = kad_len(v);
			memcpy(&x[j], v->x, l * sizeof(float));
			free(v->x);
			v->x = &x[j];
			v->g = &g[j];
			j += l;
		} else if (kad_is_const(v)) {
			l = kad_len(v);
			memcpy(&c[k], v->x, l * sizeof(float));
			free(v->x);
			v->x = &c[k];
			k += l;
		}
	}
}

static void kad_ext_sync(int n, kad_node_t **a, float *x, float *g, float *c)
{
	int i, j, k;
	for (i = j = k = 0; i < n; ++i) {
		kad_node_t *v = a[i];
		if (kad_is_var(v)) {
			v->x = &x[j];
			v->g = &g[j];
			j += kad_len(v);
		} else if (kad_is_const(v)) {
			v->x = &c[k];
			k += kad_len(v);
		}
	}
}

kann_t *kann_new(kad_node_t *cost, int n_rest, ...)
{
	kann_t *a;
	int i, n_roots = 1 + n_rest, has_pivot = 0, has_recur = 0;
	kad_node_t **roots;
	va_list ap;

	if (cost->n_d != 0) return 0;

	va_start(ap, n_rest);
	roots = (kad_node_t**)malloc((n_roots + 1) * sizeof(kad_node_t*));
	for (i = 0; i < n_rest; ++i)
		roots[i] = va_arg(ap, kad_node_t*);
	roots[i++] = cost;
	va_end(ap);

	cost->ext_flag |= KANN_F_COST;
	a = (kann_t*)calloc(1, sizeof(kann_t));
	a->v = kad_compile_array(&a->n, n_roots, roots);

	for (i = 0; i < a->n; ++i) {
		if (a->v[i]->pre) has_recur = 1;
		if (kad_is_pivot(a->v[i])) has_pivot = 1;
	}
	if (has_recur && !has_pivot) { /* an RNN that doesn't have a pivot; then add a pivot on top of cost and recompile */
		cost->ext_flag &= ~KANN_F_COST;
		roots[n_roots-1] = cost = kad_avg(1, &cost), cost->ext_flag |= KANN_F_COST;
		free(a->v);
		a->v = kad_compile_array(&a->n, n_roots, roots);
	}
	kad_ext_collate(a->n, a->v, &a->x, &a->g, &a->c);
	free(roots);
	return a;
}

kann_t *kann_clone(kann_t *a, int batch_size)
{
	kann_t *b;
	b = (kann_t*)calloc(1, sizeof(kann_t));
	b->n = a->n;
	b->v = kad_clone(a->n, a->v, batch_size);
	kad_ext_collate(b->n, b->v, &b->x, &b->g, &b->c);
	return b;
}

kann_t *kann_unroll_array(kann_t *a, int *len)
{
	kann_t *b;
	b = (kann_t*)calloc(1, sizeof(kann_t));
	b->x = a->x, b->g = a->g, b->c = a->c; /* these arrays are shared */
	b->v = kad_unroll(a->n, a->v, &b->n, len);
	return b;
}

kann_t *kann_unroll(kann_t *a, ...)
{
	kann_t *b;
	va_list ap;
	int i, n_pivots, *len;
	n_pivots = kad_n_pivots(a->n, a->v);
	len = (int*)calloc(n_pivots, sizeof(int));
	va_start(ap, a);
	for (i = 0; i < n_pivots; ++i) len[i] = va_arg(ap, int);
	va_end(ap);
	b = kann_unroll_array(a, len);
	free(len);
	return b;
}

void kann_delete_unrolled(kann_t *a)
{
	if (a && a->mt) kann_mt(a, 0, 0);
	if (a && a->v) kad_delete(a->n, a->v);
	free(a);
}

void kann_delete(kann_t *a)
{
	if (a == 0) return;
	free(a->x); free(a->g); free(a->c);
	kann_delete_unrolled(a);
}

static void kann_switch_core(kann_t *a, int is_train)
{
	int i;
	for (i = 0; i < a->n; ++i)
		if (a->v[i]->op == 12 && a->v[i]->n_child == 2)
			*(int32_t*)a->v[i]->ptr = !!is_train;
}

#define chk_flg(flag, mask) ((mask) == 0 || ((flag) & (mask)))
#define chk_lbl(label, query) ((query) == 0 || (label) == (query))

int kann_find(const kann_t *a, uint32_t ext_flag, int32_t ext_label)
{
	int i, k, r = -1;
	for (i = k = 0; i < a->n; ++i)
		if (chk_flg(a->v[i]->ext_flag, ext_flag) && chk_lbl(a->v[i]->ext_label, ext_label))
			++k, r = i;
	return k == 1? r : k == 0? -1 : -2;
}

int kann_feed_bind(kann_t *a, uint32_t ext_flag, int32_t ext_label, float **x)
{
	int i, k;
	if (x == 0) return 0;
	for (i = k = 0; i < a->n; ++i)
		if (kad_is_feed(a->v[i]) && chk_flg(a->v[i]->ext_flag, ext_flag) && chk_lbl(a->v[i]->ext_label, ext_label))
			a->v[i]->x = x[k++];
	return k;
}

int kann_feed_dim(const kann_t *a, uint32_t ext_flag, int32_t ext_label)
{
	int i, k, n = 0;
	for (i = k = 0; i < a->n; ++i)
		if (kad_is_feed(a->v[i]) && chk_flg(a->v[i]->ext_flag, ext_flag) && chk_lbl(a->v[i]->ext_label, ext_label))
			++k, n = a->v[i]->n_d > 1? kad_len(a->v[i]) / a->v[i]->d[0] : a->v[i]->n_d == 1? a->v[i]->d[0] : 1;
	return k == 1? n : k == 0? -1 : -2;
}

static float kann_cost_core(kann_t *a, int cost_label, int cal_grad)
{
	int i_cost;
	float cost;
	i_cost = kann_find(a, KANN_F_COST, cost_label);
	assert(i_cost >= 0);
	cost = *kad_eval_at(a->n, a->v, i_cost);
	if (cal_grad) kad_grad(a->n, a->v, i_cost);
	return cost;
}

int kann_eval(kann_t *a, uint32_t ext_flag, int ext_label)
{
	int i, k;
	for (i = k = 0; i < a->n; ++i)
		if (chk_flg(a->v[i]->ext_flag, ext_flag) && chk_lbl(a->v[i]->ext_label, ext_label))
			++k, a->v[i]->tmp = 1;
	kad_eval_marked(a->n, a->v);
	return k;
}

void kann_rnn_start(kann_t *a)
{
	int i;
	kann_set_batch_size(a, 1);
	for (i = 0; i < a->n; ++i) {
		kad_node_t *p = a->v[i];
		if (p->pre) { /* NB: BE CAREFUL of the interaction between kann_rnn_start() and kann_set_batch_size() */
			kad_node_t *q = p->pre;
			if (q->x) memcpy(p->x, q->x, kad_len(p) * sizeof(float));
			else memset(p->x, 0, kad_len(p) * sizeof(float));
			if (q->n_child > 0) free(q->x);
			q->x = p->x;
		}
	}
}

void kann_rnn_end(kann_t *a)
{
	int i;
	kad_ext_sync(a->n, a->v, a->x, a->g, a->c);
	for (i = 0; i < a->n; ++i)
		if (a->v[i]->pre && a->v[i]->pre->n_child > 0)
			a->v[i]->pre->x = (float*)calloc(kad_len(a->v[i]->pre), sizeof(float));
}

static int kann_class_error_core(const kann_t *ann, int *base)
{
	int i, j, k, m, n, off, n_err = 0;
	for (i = 0, *base = 0; i < ann->n; ++i) {
		kad_node_t *p = ann->v[i];
		if (((p->op == 13 && (p->n_child == 2 || p->n_child == 3)) || (p->op == 22 && p->n_child == 2)) && p->n_d == 0) { /* ce_bin or ce_multi */
			kad_node_t *x = p->child[0], *t = p->child[1];
			n = t->d[t->n_d - 1], m = kad_len(t) / n;
			for (j = off = 0; j < m; ++j, off += n) {
				float t_sum = 0.0f, t_min = 1.0f, t_max = 0.0f, x_max = 0.0f, x_min = 1.0f;
				int x_max_k = -1, t_max_k = -1;
				for (k = 0; k < n; ++k) {
					float xk = x->x[off+k], tk = t->x[off+k];
					t_sum += tk;
					t_min = t_min < tk? t_min : tk;
					x_min = x_min < xk? x_min : xk;
					if (t_max < tk) t_max = tk, t_max_k = k;
					if (x_max < xk) x_max = xk, x_max_k = k;
				}
				if (t_sum - 1.0f == 0 && t_min >= 0.0f && x_min >= 0.0f && x_max <= 1.0f) {
					++(*base);
					n_err += (x_max_k != t_max_k);
				}
			}
		}
	}
	return n_err;
}

/*************************
 * @@MT: multi-threading *
 *************************/

#ifdef HAVE_PTHREAD
#include <pthread.h>

struct mtaux_t;

typedef struct { /* per-worker data */
	kann_t *a;
	float cost;
	int action;
	pthread_t tid;
	struct mtaux_t *g;
} mtaux1_t;

typedef struct mtaux_t { /* cross-worker data */
	int n_threads, max_batch_size;
	int cal_grad, cost_label, eval_out;
	volatile int n_idle; /* we will be busy waiting on this, so volatile necessary */
	pthread_mutex_t mtx;
	pthread_cond_t cv;
	mtaux1_t *mt;
} mtaux_t;

static void *mt_worker(void *data) /* pthread worker */
{
	mtaux1_t *mt1 = (mtaux1_t*)data;
	mtaux_t *mt = mt1->g;
	for (;;) {
		int action;
		pthread_mutex_lock(&mt->mtx);
		mt1->action = 0;
		++mt->n_idle;
		while (mt1->action == 0)
			pthread_cond_wait(&mt->cv, &mt->mtx);
		action = mt1->action;
		pthread_mutex_unlock(&mt->mtx);
		if (action == -1) break;

		if (mt->eval_out) kann_eval(mt1->a, KANN_F_OUT, 0);
		else mt1->cost = kann_cost_core(mt1->a, mt->cost_label, mt->cal_grad);
	}
	pthread_exit(0);
}

static void mt_destroy(mtaux_t *mt) /* de-allocate an entire mtaux_t struct */
{
	int i;
	pthread_mutex_lock(&mt->mtx);
	mt->n_idle = 0;
	for (i = 1; i < mt->n_threads; ++i) mt->mt[i].action = -1;
	pthread_cond_broadcast(&mt->cv);
	pthread_mutex_unlock(&mt->mtx);
	for (i = 1; i < mt->n_threads; ++i) pthread_join(mt->mt[i].tid, 0);
	for (i = 0; i < mt->n_threads; ++i) kann_delete(mt->mt[i].a);
	free(mt->mt);
	pthread_cond_destroy(&mt->cv);
	pthread_mutex_destroy(&mt->mtx);
	free(mt);
}

void kann_mt(kann_t *ann, int n_threads, int max_batch_size)
{
	mtaux_t *mt;
	int i, k;

	if (n_threads <= 1) {
		if (ann->mt) mt_destroy((mtaux_t*)ann->mt);
		ann->mt = 0;
		return;
	}
	if (n_threads > max_batch_size) n_threads = max_batch_size;
	if (n_threads <= 1) return;

	mt = (mtaux_t*)calloc(1, sizeof(mtaux_t));
	mt->n_threads = n_threads, mt->max_batch_size = max_batch_size;
	pthread_mutex_init(&mt->mtx, 0);
	pthread_cond_init(&mt->cv, 0);
	mt->mt = (mtaux1_t*)calloc(n_threads, sizeof(mtaux1_t));
	for (i = k = 0; i < n_threads; ++i) {
		int size = (max_batch_size - k) / (n_threads - i);
		mt->mt[i].a = kann_clone(ann, size);
		mt->mt[i].g = mt;
		k += size;
	}
	for (i = 1; i < n_threads; ++i)
		pthread_create(&mt->mt[i].tid, 0, mt_worker, &mt->mt[i]);
	while (mt->n_idle < n_threads - 1); /* busy waiting until all threads in sync */
	ann->mt = mt;
}

static void mt_kickoff(kann_t *a, int cost_label, int cal_grad, int eval_out)
{
	mtaux_t *mt = (mtaux_t*)a->mt;
	int i, j, k, B, n_var;

	B = kad_sync_dim(a->n, a->v, -1); /* get the current batch size */
	assert(B <= mt->max_batch_size); /* TODO: can be relaxed */
	n_var = kann_size_var(a);

	pthread_mutex_lock(&mt->mtx);
	mt->cost_label = cost_label, mt->cal_grad = cal_grad, mt->eval_out = eval_out;
	for (i = k = 0; i < mt->n_threads; ++i) {
		int size = (B - k) / (mt->n_threads - i);
		for (j = 0; j < a->n; ++j)
			if (kad_is_feed(a->v[j]))
				mt->mt[i].a->v[j]->x = &a->v[j]->x[k * kad_len(a->v[j]) / a->v[j]->d[0]];
		kad_sync_dim(mt->mt[i].a->n, mt->mt[i].a->v, size); /* TODO: we can point ->x to internal nodes, too */
		k += size;
		memcpy(mt->mt[i].a->x, a->x, n_var * sizeof(float));
		mt->mt[i].action = 1;
	}
	mt->n_idle = 0;
	pthread_cond_broadcast(&mt->cv);
	pthread_mutex_unlock(&mt->mtx);
}

float kann_cost(kann_t *a, int cost_label, int cal_grad)
{
	mtaux_t *mt = (mtaux_t*)a->mt;
	int i, j, B, k, n_var;
	float cost;

	if (mt == 0) return kann_cost_core(a, cost_label, cal_grad);
	B = kad_sync_dim(a->n, a->v, -1); /* get the current batch size */
	n_var = kann_size_var(a);

	mt_kickoff(a, cost_label, cal_grad, 0);
	mt->mt[0].cost = kann_cost_core(mt->mt[0].a, cost_label, cal_grad);
	while (mt->n_idle < mt->n_threads - 1); /* busy waiting until all threads in sync */

	memset(a->g, 0, n_var * sizeof(float)); /* TODO: check if this is necessary when cal_grad is false */
	for (i = k = 0, cost = 0.0f; i < mt->n_threads; ++i) {
		int size = (B - k) / (mt->n_threads - i);
		cost += mt->mt[i].cost * size / B;
		kad_saxpy(n_var, (float)size / B, mt->mt[i].a->g, a->g);
		k += size;
	}
	for (j = 0; j < a->n; ++j) { /* copy values back at recurrent nodes (needed by textgen; TODO: temporary solution) */
		kad_node_t *p = a->v[j];
		if (p->pre && p->n_d >= 2 && p->d[0] == B) {
			for (i = k = 0; i < mt->n_threads; ++i) {
				kad_node_t *q = mt->mt[i].a->v[j];
				memcpy(&p->x[k], q->x, kad_len(q) * sizeof(float));
				k += kad_len(q);
			}
		}
	}
	return cost;
}

int kann_eval_out(kann_t *a)
{
	mtaux_t *mt = (mtaux_t*)a->mt;
	int j, B, n_eval;
	if (mt == 0) return kann_eval(a, KANN_F_OUT, 0);
	B = kad_sync_dim(a->n, a->v, -1); /* get the current batch size */
	mt_kickoff(a, 0, 0, 1);
	n_eval = kann_eval(mt->mt[0].a, KANN_F_OUT, 0);
	while (mt->n_idle < mt->n_threads - 1); /* busy waiting until all threads in sync */
	for (j = 0; j < a->n; ++j) { /* copy output values back */
		kad_node_t *p = a->v[j];
		if (p->ext_flag & KANN_F_OUT) {
			int i, t, k, d0 = p->d[0] / B, d1 = 1; /* for RNN, p->d[0] may equal unroll_len * batch_size */
			assert(p->d[0] % B == 0);
			for (i = 1; i < p->n_d; ++i) d1 *= p->d[i];
			for (i = 0; i < d0; ++i) {
				for (t = k = 0; t < mt->n_threads; ++t) { /* similar to the forward pass of kad_op_concat() */
					kad_node_t *q = mt->mt[t].a->v[j];
					int size = q->d[0] / d0;
					memcpy(&p->x[(i * B + k) * d1], &q->x[i * size * d1], size * d1 * sizeof(float));
					k += size;
				}
			}
		}
	}
	return n_eval;
}

int kann_class_error(const kann_t *ann, int *base)
{
	mtaux_t *mt = (mtaux_t*)ann->mt;
	int i, n_err = 0, b = 0;
	if (mt == 0) return kann_class_error_core(ann, base);
	for (i = 0; i < mt->n_threads; ++i) {
		n_err += kann_class_error_core(mt->mt[i].a, &b);
		*base += b;
	}
	return n_err;
}

void kann_switch(kann_t *ann, int is_train)
{
	mtaux_t *mt = (mtaux_t*)ann->mt;
	int i;
	if (mt == 0) {
		kann_switch_core(ann, is_train);
		return;
	}
	for (i = 0; i < mt->n_threads; ++i)
		kann_switch_core(mt->mt[i].a, is_train);
}
#else
void kann_mt(kann_t *ann, int n_threads, int max_batch_size) {}
float kann_cost(kann_t *a, int cost_label, int cal_grad) { return kann_cost_core(a, cost_label, cal_grad); }
int kann_eval_out(kann_t *a) { return kann_eval(a, KANN_F_OUT, 0); }
int kann_class_error(const kann_t *a, int *base) { return kann_class_error_core(a, base); }
void kann_switch(kann_t *ann, int is_train) { return kann_switch_core(ann, is_train); }
#endif

/***********************
 *** @@IO: model I/O ***
 ***********************/

#define KANN_MAGIC "KAN\1"

void kann_save_fp(FILE *fp, kann_t *ann)
{
	kann_set_batch_size(ann, 1);
	fwrite(KANN_MAGIC, 1, 4, fp);
	kad_save(fp, ann->n, ann->v);
	fwrite(ann->x, sizeof(float), kann_size_var(ann), fp);
	fwrite(ann->c, sizeof(float), kann_size_const(ann), fp);
}

void kann_save(const char *fn, kann_t *ann)
{
	FILE *fp;
	fp = fn && strcmp(fn, "-")? fopen(fn, "wb") : stdout;
	kann_save_fp(fp, ann);
	fclose(fp);
}

kann_t *kann_load_fp(FILE *fp)
{
	char magic[4];
	kann_t *ann;
	int n_var, n_const;

	(void) !fread(magic, 1, 4, fp);
	if (strncmp(magic, KANN_MAGIC, 4) != 0) {
		return 0;
	}
	ann = (kann_t*)calloc(1, sizeof(kann_t));
	ann->v = kad_load(fp, &ann->n);
	n_var = kad_size_var(ann->n, ann->v);
	n_const = kad_size_const(ann->n, ann->v);
	ann->x = (float*)malloc(n_var * sizeof(float));
	ann->g = (float*)calloc(n_var, sizeof(float));
	ann->c = (float*)malloc(n_const * sizeof(float));
	(void) !fread(ann->x, sizeof(float), n_var, fp);
	(void) !fread(ann->c, sizeof(float), n_const, fp);
	kad_ext_sync(ann->n, ann->v, ann->x, ann->g, ann->c);
	return ann;
}

kann_t *kann_load(const char *fn)
{
	FILE *fp;
	kann_t *ann;
	fp = fn && strcmp(fn, "-")? fopen(fn, "rb") : stdin;
	ann = kann_load_fp(fp);
	fclose(fp);
	return ann;
}

/**********************************************
 *** @@LAYER: layers and model generation ***
 **********************************************/

/********** General but more complex APIs **********/

kad_node_t *kann_new_leaf_array(int *offset, kad_node_p *par, uint8_t flag, float x0_01, int n_d, int32_t d[KAD_MAX_DIM])
{
	int i, len, off = offset && par? *offset : -1;
	kad_node_t *p;

	if (off >= 0 && par[off]) return par[(*offset)++];
	p = (kad_node_t*)calloc(1, sizeof(kad_node_t));
	p->n_d = n_d, p->flag = flag;
	memcpy(p->d, d, n_d * sizeof(int32_t));
	len = kad_len(p);
	p->x = (float*)calloc(len, sizeof(float));
	if (p->n_d <= 1) {
		for (i = 0; i < len; ++i)
			p->x[i] = x0_01;
	} else {
		double sdev_inv;
		sdev_inv = 1.0 / sqrt((double)len / p->d[0]);
		for (i = 0; i < len; ++i)
			p->x[i] = (float)(kad_drand_normal(0) * sdev_inv);
	}
	if (off >= 0) par[off] = p, ++(*offset);
	return p;
}

kad_node_t *kann_new_leaf2(int *offset, kad_node_p *par, uint8_t flag, float x0_01, int n_d, ...)
{
	int32_t i, d[KAD_MAX_DIM];
	va_list ap;
	va_start(ap, n_d); for (i = 0; i < n_d; ++i) d[i] = va_arg(ap, int); va_end(ap);
	return kann_new_leaf_array(offset, par, flag, x0_01, n_d, d);
}

kad_node_t *kann_layer_dense2(int *offset, kad_node_p *par, kad_node_t *in, int n1)
{
	int n0;
	kad_node_t *w, *b;
	n0 = in->n_d >= 2? kad_len(in) / in->d[0] : kad_len(in);
	w = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 2, n1, n0);
	b = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 1, n1);
	return kad_add(kad_cmul(in, w), b);
}

kad_node_t *kann_layer_dropout2(int *offset, kad_node_p *par, kad_node_t *t, float r)
{
	kad_node_t *x[2], *cr;
	cr = kann_new_leaf2(offset, par, KAD_CONST, r, 0);
	x[0] = t, x[1] = kad_dropout(t, cr);
	return kad_switch(2, x);
}

kad_node_t *kann_layer_layernorm2(int *offset, kad_node_t **par, kad_node_t *in)
{
	int n0;
	kad_node_t *alpha, *beta;
	n0 = in->n_d >= 2? kad_len(in) / in->d[0] : kad_len(in);
	alpha = kann_new_leaf2(offset, par, KAD_VAR, 1.0f, 1, n0);
	beta  = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 1, n0);
	return kad_add(kad_mul(kad_stdnorm(in), alpha), beta);
}

static inline kad_node_t *cmul_norm2(int *offset, kad_node_t **par, kad_node_t *x, kad_node_t *w, int use_norm)
{
	return use_norm? kann_layer_layernorm2(offset, par, kad_cmul(x, w)) : kad_cmul(x, w);
}

kad_node_t *kann_layer_rnn2(int *offset, kad_node_t **par, kad_node_t *in, kad_node_t *h0, int rnn_flag)
{
	int n0, n1 = h0->d[h0->n_d-1], use_norm = !!(rnn_flag & KANN_RNN_NORM);
	kad_node_t *t, *w, *u, *b, *out;

	u = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 2, n1, n1);
	b = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 1, n1);
	t = cmul_norm2(offset, par, h0, u, use_norm);
	if (in) {
		n0 = in->n_d >= 2? kad_len(in) / in->d[0] : kad_len(in);
		w = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 2, n1, n0);
		t = kad_add(cmul_norm2(offset, par, in, w, use_norm), t);
	}
	out = kad_tanh(kad_add(t, b));
	out->pre = h0;
	return out;
}

kad_node_t *kann_layer_gru2(int *offset, kad_node_t **par, kad_node_t *in, kad_node_t *h0, int rnn_flag)
{
	int n0 = 0, n1 = h0->d[h0->n_d-1], use_norm = !!(rnn_flag & KANN_RNN_NORM);
	kad_node_t *t, *r, *z, *w, *u, *b, *s, *out;

	if (in) n0 = in->n_d >= 2? kad_len(in) / in->d[0] : kad_len(in);
	/* z = sigm(x_t * W_z + h_{t-1} * U_z + b_z) */
	u = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 2, n1, n1);
	b = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 1, n1);
	t = cmul_norm2(offset, par, h0, u, use_norm);
	if (in) {
		w = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 2, n1, n0);
		t = kad_add(cmul_norm2(offset, par, in, w, use_norm), t);
	}
	z = kad_sigm(kad_add(t, b));
	/* r = sigm(x_t * W_r + h_{t-1} * U_r + b_r) */
	u = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 2, n1, n1);
	b = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 1, n1);
	t = cmul_norm2(offset, par, h0, u, use_norm);
	if (in) {
		w = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 2, n1, n0);
		t = kad_add(cmul_norm2(offset, par, in, w, use_norm), t);
	}
	r = kad_sigm(kad_add(t, b));
	/* s = tanh(x_t * W_s + (h_{t-1} # r) * U_s + b_s) */
	u = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 2, n1, n1);
	b = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 1, n1);
	t = cmul_norm2(offset, par, kad_mul(r, h0), u, use_norm);
	if (in) {
		w = kann_new_leaf2(offset, par, KAD_VAR, 0.0f, 2, n1, n0);
		t = kad_add(cmul_norm2(offset, par, in, w, use_norm), t);
	}
	s = kad_tanh(kad_add(t, b));
	/* h_t = z # h_{t-1} + (1 - z) # s */
	out = kad_add(kad_mul(kad_1minus(z), s), kad_mul(z, h0));
	out->pre = h0;
	return out;
}

/********** APIs without offset & par **********/

kad_node_t *kann_new_leaf(uint8_t flag, float x0_01, int n_d, ...)
{
	int32_t i, d[KAD_MAX_DIM];
	va_list ap;
	va_start(ap, n_d); for (i = 0; i < n_d; ++i) d[i] = va_arg(ap, int); va_end(ap);
	return kann_new_leaf_array(0, 0, flag, x0_01, n_d, d);
}

kad_node_t *kann_new_scalar(uint8_t flag, float x) { return kann_new_leaf(flag, x, 0); }
kad_node_t *kann_new_weight(int n_row, int n_col) { return kann_new_leaf(KAD_VAR, 0.0f, 2, n_row, n_col); }
kad_node_t *kann_new_vec(int n, float x) { return kann_new_leaf(KAD_VAR, x, 1, n); }
kad_node_t *kann_new_bias(int n) { return kann_new_vec(n, 0.0f); }
kad_node_t *kann_new_weight_conv2d(int n_out, int n_in, int k_row, int k_col) { return kann_new_leaf(KAD_VAR, 0.0f, 4, n_out, n_in, k_row, k_col); }
kad_node_t *kann_new_weight_conv1d(int n_out, int n_in, int kernel_len) { return kann_new_leaf(KAD_VAR, 0.0f, 3, n_out, n_in, kernel_len); }

kad_node_t *kann_layer_input(int n1)
{
	kad_node_t *t;
	t = kad_feed(2, 1, n1);
	t->ext_flag |= KANN_F_IN;
	return t;
}

kad_node_t *kann_layer_dense(kad_node_t *in, int n1) { return kann_layer_dense2(0, 0, in, n1); }
kad_node_t *kann_layer_dropout(kad_node_t *t, float r) { return kann_layer_dropout2(0, 0, t, r); }
kad_node_t *kann_layer_layernorm(kad_node_t *in) { return kann_layer_layernorm2(0, 0, in); }

kad_node_t *kann_layer_rnn(kad_node_t *in, int n1, int rnn_flag)
{
	kad_node_t *h0;
	h0 = (rnn_flag & KANN_RNN_VAR_H0)? kad_var(0, 0, 2, 1, n1) : kad_const(0, 2, 1, n1);
	h0->x = (float*)calloc(n1, sizeof(float));
	return kann_layer_rnn2(0, 0, in, h0, rnn_flag);
}

kad_node_t *kann_layer_gru(kad_node_t *in, int n1, int rnn_flag)
{
	kad_node_t *h0;
	h0 = (rnn_flag & KANN_RNN_VAR_H0)? kad_var(0, 0, 2, 1, n1) : kad_const(0, 2, 1, n1);
	h0->x = (float*)calloc(n1, sizeof(float));
	return kann_layer_gru2(0, 0, in, h0, rnn_flag);
}

static kad_node_t *kann_cmul_norm(kad_node_t *x, kad_node_t *w)
{
	return kann_layer_layernorm(kad_cmul(x, w));
}

kad_node_t *kann_layer_lstm(kad_node_t *in, int n1, int rnn_flag)
{
	int n0;
	kad_node_t *i, *f, *o, *g, *w, *u, *b, *h0, *c0, *c, *out;
	kad_node_t *(*cmul)(kad_node_t*, kad_node_t*) = (rnn_flag & KANN_RNN_NORM)? kann_cmul_norm : kad_cmul;

	n0 = in->n_d >= 2? kad_len(in) / in->d[0] : kad_len(in);
	h0 = (rnn_flag & KANN_RNN_VAR_H0)? kad_var(0, 0, 2, 1, n1) : kad_const(0, 2, 1, n1);
	h0->x = (float*)calloc(n1, sizeof(float));
	c0 = (rnn_flag & KANN_RNN_VAR_H0)? kad_var(0, 0, 2, 1, n1) : kad_const(0, 2, 1, n1);
	c0->x = (float*)calloc(n1, sizeof(float));

	/* i = sigm(x_t * W_i + h_{t-1} * U_i + b_i) */
	w = kann_new_weight(n1, n0);
	u = kann_new_weight(n1, n1);
	b = kann_new_bias(n1);
	i = kad_sigm(kad_add(kad_add(cmul(in, w), cmul(h0, u)), b));
	/* f = sigm(x_t * W_f + h_{t-1} * U_f + b_f) */
	w = kann_new_weight(n1, n0);
	u = kann_new_weight(n1, n1);
	b = kann_new_vec(n1, 1.0f); /* see Jozefowicz et al on using a large bias */
	f = kad_sigm(kad_add(kad_add(cmul(in, w), cmul(h0, u)), b));
	/* o = sigm(x_t * W_o + h_{t-1} * U_o + b_o) */
	w = kann_new_weight(n1, n0);
	u = kann_new_weight(n1, n1);
	b = kann_new_bias(n1);
	o = kad_sigm(kad_add(kad_add(cmul(in, w), cmul(h0, u)), b));
	/* g = tanh(x_t * W_g + h_{t-1} * U_g + b_g) */
	w = kann_new_weight(n1, n0);
	u = kann_new_weight(n1, n1);
	b = kann_new_bias(n1);
	g = kad_tanh(kad_add(kad_add(cmul(in, w), cmul(h0, u)), b));
	/* c_t = c_{t-1} # f + g # i */
	c = kad_add(kad_mul(f, c0), kad_mul(g, i)); /* can't be kad_mul(c0, f)!!! */
	c->pre = c0;
	/* h_t = tanh(c_t) # o */
	if (rnn_flag & KANN_RNN_NORM) c = kann_layer_layernorm(c); /* see Ba et al (2016) about how to apply layer normalization to LSTM */
	out = kad_mul(kad_tanh(c), o);
	out->pre = h0;
	return out;
}

kad_node_t *kann_layer_conv2d(kad_node_t *in, int n_flt, int k_rows, int k_cols, int stride_r, int stride_c, int pad_r, int pad_c)
{
	kad_node_t *w;
	w = kann_new_weight_conv2d(n_flt, in->d[1], k_rows, k_cols);
	return kad_conv2d(in, w, stride_r, stride_c, pad_r, pad_c);
}

kad_node_t *kann_layer_conv1d(kad_node_t *in, int n_flt, int k_size, int stride, int pad)
{
	kad_node_t *w;
	w = kann_new_weight_conv1d(n_flt, in->d[1], k_size);
	return kad_conv1d(in, w, stride, pad);
}

kad_node_t *kann_layer_cost(kad_node_t *t, int n_out, int cost_type)
{
	kad_node_t *cost = 0, *truth = 0;
	assert(cost_type == KANN_C_CEB || cost_type == KANN_C_CEM || cost_type == KANN_C_CEB_NEG || cost_type == KANN_C_MSE);
	t = kann_layer_dense(t, n_out);
	truth = kad_feed(2, 1, n_out), truth->ext_flag |= KANN_F_TRUTH;

	if (cost_type == KANN_C_MSE) {
		cost = kad_mse(t, truth);
	} else if (cost_type == KANN_C_CEB) {
		t = kad_sigm(t);
		cost = kad_ce_bin(t, truth);
	} else if (cost_type == KANN_C_CEB_NEG) {
		t = kad_tanh(t);
		cost = kad_ce_bin_neg(t, truth);
	} else if (cost_type == KANN_C_CEM) {
		t = kad_softmax(t);
		cost = kad_ce_multi(t, truth);
	}
	else {
		assert (0);
	}

	t->ext_flag |= KANN_F_OUT;
	cost->ext_flag |= KANN_F_COST;

	return cost;
}

void kann_shuffle(int n, int *s)
{
	int i, j, t;
	for (i = 0; i < n; ++i) s[i] = i;
	for (i = n; i > 0; --i) {
		j = (int)(i * kad_drand(0));
		t = s[j], s[j] = s[i-1], s[i-1] = t;
	}
}

/***************************
 *** @@MIN: minimization ***
 ***************************/

#ifdef __SSE__
#include <xmmintrin.h>

void kann_RMSprop(int n, float h0, const float *h, float decay, const float *g, float *t, float *r)
{
	int i, n4 = n>>2<<2;
	__m128 vh, vg, vr, vt, vd, vd1, tmp, vtiny;
	vh = _mm_set1_ps(h0);
	vd = _mm_set1_ps(decay);
	vd1 = _mm_set1_ps(1.0f - decay);
	vtiny = _mm_set1_ps(1e-6f);
	for (i = 0; i < n4; i += 4) {
		vt = _mm_loadu_ps(&t[i]);
		vr = _mm_loadu_ps(&r[i]);
		vg = _mm_loadu_ps(&g[i]);
		if (h) vh = _mm_loadu_ps(&h[i]);
		vr = _mm_add_ps(_mm_mul_ps(vd1, _mm_mul_ps(vg, vg)), _mm_mul_ps(vd, vr));
		_mm_storeu_ps(&r[i], vr);
		tmp = _mm_sub_ps(vt, _mm_mul_ps(_mm_mul_ps(vh, _mm_rsqrt_ps(_mm_add_ps(vtiny, vr))), vg));
		_mm_storeu_ps(&t[i], tmp);
	}
	for (; i < n; ++i) {
		r[i] = (1. - decay) * g[i] * g[i] + decay * r[i];
		t[i] -= (h? h[i] : h0) / sqrtf(1e-6f + r[i]) * g[i];
	}
}
#else
void kann_RMSprop(int n, float h0, const float *h, float decay, const float *g, float *t, float *r)
{
	int i;
	for (i = 0; i < n; ++i) {
		float lr = h? h[i] : h0;
		r[i] = (1.0f - decay) * g[i] * g[i] + decay * r[i];
		t[i] -= lr / sqrtf(1e-6f + r[i]) * g[i];
	}
}
#endif

float kann_grad_clip(float thres, int n, float *g)
{
	int i;
	double s2 = 0.0;
	for (i = 0; i < n; ++i)
		s2 += g[i] * g[i];
	s2 = sqrt(s2);
	if (s2 > thres)
		for (i = 0, s2 = 1.0 / s2; i < n; ++i)
			g[i] *= (float)s2;
	return (float)s2 / thres;
}

/****************************************************************
 *** @@XY: simpler API for network with a single input/output ***
 ****************************************************************/

int kann_train_fnn1(kann_t *ann, float lr, int mini_size, int max_epoch,
					int max_drop_streak, float frac_val, int n,
					float **_x, float **_y,
					kann_train_cb cb, void *ud)
{
	int i, j, *shuf, n_train, n_val, n_in, n_out, n_var, n_const, drop_streak = 0, min_set = 0;
	float **x, **y, *x1, *y1, *r, min_val_cost = FLT_MAX, *min_x, *min_c;

	n_in = kann_dim_in(ann);
	n_out = kann_dim_out(ann);
	if (n_in < 0 || n_out < 0) return -1;
	n_var = kann_size_var(ann);
	n_const = kann_size_const(ann);
	r = (float*)calloc(n_var, sizeof(float));
	shuf = (int*)malloc(n * sizeof(int));
	x = (float**)malloc(n * sizeof(float*));
	y = (float**)malloc(n * sizeof(float*));
	kann_shuffle(n, shuf);
	for (j = 0; j < n; ++j)
		x[j] = _x[shuf[j]], y[j] = _y[shuf[j]];
	n_val = (int)(n * frac_val);
	n_train = n - n_val;
	min_x = (float*)malloc(n_var * sizeof(float));
	min_c = (float*)malloc(n_const * sizeof(float));

	x1 = (float*)malloc(n_in  * mini_size * sizeof(float));
	y1 = (float*)malloc(n_out * mini_size * sizeof(float));
	kann_feed_bind(ann, KANN_F_IN,    0, &x1);
	kann_feed_bind(ann, KANN_F_TRUTH, 0, &y1);

	for (i = 0; i < max_epoch; ++i) {
		int n_proc = 0, n_train_err = 0, n_val_err = 0, n_train_base = 0, n_val_base = 0;
		double train_cost = 0.0, val_cost = 0.0;
		kann_shuffle(n_train, shuf);
		kann_switch(ann, 1);
		while (n_proc < n_train) {
			int b, c, ms = n_train - n_proc < mini_size? n_train - n_proc : mini_size;
			for (b = 0; b < ms; ++b) {
				memcpy(&x1[b*n_in],  x[shuf[n_proc+b]], n_in  * sizeof(float));
				memcpy(&y1[b*n_out], y[shuf[n_proc+b]], n_out * sizeof(float));
			}
			kann_set_batch_size(ann, ms);
			train_cost += kann_cost(ann, 0, 1) * ms;
			c = kann_class_error(ann, &b);
			n_train_err += c, n_train_base += b;
			kann_RMSprop(n_var, lr, 0, 0.9f, ann->g, ann->x, r);
			n_proc += ms;
		}
		train_cost /= n_train;
		kann_switch(ann, 0);
		n_proc = 0;
		while (n_proc < n_val) {
			int b, c, ms = n_val - n_proc < mini_size? n_val - n_proc : mini_size;
			for (b = 0; b < ms; ++b) {
				memcpy(&x1[b*n_in],  x[n_train+n_proc+b], n_in  * sizeof(float));
				memcpy(&y1[b*n_out], y[n_train+n_proc+b], n_out * sizeof(float));
			}
			kann_set_batch_size(ann, ms);
			val_cost += kann_cost(ann, 0, 0) * ms;
			c = kann_class_error(ann, &b);
			n_val_err += c, n_val_base += b;
			n_proc += ms;
		}
		if (n_val > 0) val_cost /= n_val;
		if (cb) {
			cb(i + 1, train_cost, val_cost, ud);
#if 0
			fprintf(stderr, "epoch: %d; training cost: %g", i+1, train_cost);
			if (n_train_base) fprintf(stderr, " (class error: %.2f%%)", 100.0f * n_train_err / n_train);
			if (n_val > 0) {
				fprintf(stderr, "; validation cost: %g", val_cost);
				if (n_val_base) fprintf(stderr, " (class error: %.2f%%)", 100.0f * n_val_err / n_val);
			}
			fputc('\n', stderr);
#endif
		}
		if (i >= max_drop_streak && n_val > 0) {
			if (val_cost < min_val_cost) {
				min_set = 1;
				memcpy(min_x, ann->x, n_var * sizeof(float));
				memcpy(min_c, ann->c, n_const * sizeof(float));
				drop_streak = 0;
				min_val_cost = (float)val_cost;
			} else if (++drop_streak >= max_drop_streak)
				break;
		}
	}
	if (min_set) {
		memcpy(ann->x, min_x, n_var * sizeof(float));
		memcpy(ann->c, min_c, n_const * sizeof(float));
	}

	free(min_c); free(min_x); free(y1); free(x1); free(y); free(x); free(shuf); free(r);
	return i;
}

float kann_cost_fnn1(kann_t *ann, int n, float **x, float **y)
{
	int n_in, n_out, n_proc = 0, mini_size = 64 < n? 64 : n;
	float *x1, *y1;
	double cost = 0.0;

	n_in = kann_dim_in(ann);
	n_out = kann_dim_out(ann);
	if (n <= 0 || n_in < 0 || n_out < 0) return 0.0;

	x1 = (float*)malloc(n_in  * mini_size * sizeof(float));
	y1 = (float*)malloc(n_out * mini_size * sizeof(float));
	kann_feed_bind(ann, KANN_F_IN,    0, &x1);
	kann_feed_bind(ann, KANN_F_TRUTH, 0, &y1);
	kann_switch(ann, 0);
	while (n_proc < n) {
		int b, ms = n - n_proc < mini_size? n - n_proc : mini_size;
		for (b = 0; b < ms; ++b) {
			memcpy(&x1[b*n_in],  x[n_proc+b], n_in  * sizeof(float));
			memcpy(&y1[b*n_out], y[n_proc+b], n_out * sizeof(float));
		}
		kann_set_batch_size(ann, ms);
		cost += kann_cost(ann, 0, 0) * ms;
		n_proc += ms;
	}
	free(y1); free(x1);
	return (float)(cost / n);
}

const float *kann_apply1(kann_t *a, float *x)
{
	int i_out;
	i_out = kann_find(a, KANN_F_OUT, 0);
	if (i_out < 0) return 0;
	kann_set_batch_size(a, 1);
	kann_feed_bind(a, KANN_F_IN, 0, &x);
	kad_eval_at(a->n, a->v, i_out);
	return a->v[i_out]->x;
}
