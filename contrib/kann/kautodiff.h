/*
  The MIT License

  Copyright (c) 2018-2019 Dana-Farber Cancer Institute
                2016-2018 Broad Institute

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

#ifndef KANN_AUTODIFF_H
#define KANN_AUTODIFF_H

#define KAD_VERSION "r544"

#include <stdio.h>
#include <stdint.h>

#ifdef __STRICT_ANSI__
#define inline
#endif

#define KAD_MAX_DIM 4     /* max dimension */
#define KAD_MAX_OP  64    /* max number of operators */

/* A computational graph is a directed acyclic graph. In the graph, an external
 * node represents a variable, a constant or a feed; an internal node
 * represents an operator; an edge from node v to w indicates v is an operand
 * of w.
 */

#define KAD_VAR        0x1
#define KAD_CONST      0x2
#define KAD_POOL       0x4
#define KAD_SHARE_RNG  0x10 /* with this flag on, different time step shares the same RNG status after unroll */

#define kad_is_back(p)  ((p)->flag & KAD_VAR)
#define kad_is_ext(p)   ((p)->n_child == 0)
#define kad_is_var(p)   (kad_is_ext(p) && kad_is_back(p))
#define kad_is_const(p) (kad_is_ext(p) && ((p)->flag & KAD_CONST))
#define kad_is_feed(p)  (kad_is_ext(p) && !kad_is_back(p) && !((p)->flag & KAD_CONST))
#define kad_is_pivot(p) ((p)->n_child == 1 && ((p)->flag & KAD_POOL))
#define kad_is_switch(p) ((p)->op == 12 && !((p)->flag & KAD_POOL))
#define kad_use_rng(p)  ((p)->op == 15 || (p)->op == 24)

#define kad_eval_enable(p) ((p)->tmp = 1)
#define kad_eval_disable(p) ((p)->tmp = -1)

/* a node in the computational graph */
typedef struct kad_node_t {
	uint8_t     n_d;            /* number of dimensions; no larger than KAD_MAX_DIM */
	uint8_t     flag;           /* type of the node; see KAD_F_* for valid flags */
	uint16_t    op;             /* operator; kad_op_list[op] is the actual function */
	int32_t     n_child;        /* number of operands/child nodes */
	int32_t     tmp;            /* temporary field; MUST BE zero before calling kad_compile() */
	int32_t     ptr_size;       /* size of ptr below */
	int32_t     d[KAD_MAX_DIM]; /* dimensions */
	int32_t     ext_label;      /* labels for external uses (not modified by the kad_* APIs) */
	uint32_t    ext_flag;       /* flags for external uses (not modified by the kad_* APIs) */
	float      *x;              /* value; allocated for internal nodes */
	float      *g;              /* gradient; allocated for internal nodes */
	void       *ptr;            /* for special operators that need additional parameters (e.g. conv2d) */
	void       *gtmp;           /* temporary data generated at the forward pass but used at the backward pass */
	struct kad_node_t **child;  /* operands/child nodes */
	struct kad_node_t  *pre;    /* usually NULL; only used for RNN */
} kad_node_t, *kad_node_p;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compile/linearize a computational graph
 *
 * @param n_node   number of nodes (out)
 * @param n_roots  number of nodes without predecessors
 * @param roots    list of nodes without predecessors
 *
 * @return list of nodes, of size *n_node
 */
kad_node_t **kad_compile_array(int *n_node, int n_roots, kad_node_t **roots);

kad_node_t **kad_compile(int *n_node, int n_roots, ...); /* an alternative API to above */
void kad_delete(int n, kad_node_t **a); /* deallocate a compiled/linearized graph */

/**
 * Compute the value at a node
 * 
 * @param n       number of nodes
 * @param a       list of nodes
 * @param from    compute the value at this node, 0<=from<n
 *
 * @return a pointer to the value (pointing to kad_node_t::x, so don't call
 *         free() on it!)
 */
const float *kad_eval_at(int n, kad_node_t **a, int from);

void kad_eval_marked(int n, kad_node_t **a);
int kad_sync_dim(int n, kad_node_t **v, int batch_size);

/**
 * Compute gradient
 *
 * @param n       number of nodes
 * @param a       list of nodes
 * @param from    the function node; must be a scalar (compute \nabla a[from])
 */
void kad_grad(int n, kad_node_t **a, int from);

/**
 * Unroll a recurrent computation graph
 *
 * @param n_v     number of nodes
 * @param v       list of nodes
 * @param new_n   number of nodes in the unrolled graph (out)
 * @param len     how many times to unroll, one for each pivot
 *
 * @return list of nodes in the unrolled graph
 */
kad_node_t **kad_unroll(int n_v, kad_node_t **v, int *new_n, int *len);
int kad_n_pivots(int n_v, kad_node_t **v);

kad_node_t **kad_clone(int n, kad_node_t **v, int batch_size);

/* define a variable, a constant or a feed (placeholder in TensorFlow) */
kad_node_t *kad_var(float *x, float *g, int n_d, ...); /* a variable; gradients to be computed; not unrolled */
kad_node_t *kad_const(float *x, int n_d, ...);         /* a constant; no gradients computed; not unrolled */
kad_node_t *kad_feed(int n_d, ...);                    /* an input/output; no gradients computed; unrolled */

/* operators taking two operands */
kad_node_t *kad_add(kad_node_t *x, kad_node_t *y); /* f(x,y) = x + y (generalized element-wise addition; f[i*n+j]=x[i*n+j]+y[j], n=kad_len(y), 0<j<n, 0<i<kad_len(x)/n) */
kad_node_t *kad_sub(kad_node_t *x, kad_node_t *y); /* f(x,y) = x - y (generalized element-wise subtraction) */
kad_node_t *kad_mul(kad_node_t *x, kad_node_t *y); /* f(x,y) = x * y (generalized element-wise product) */

kad_node_t *kad_matmul(kad_node_t *x, kad_node_t *y);     /* f(x,y) = x * y   (general matrix product) */
kad_node_t *kad_cmul(kad_node_t *x, kad_node_t *y);       /* f(x,y) = x * y^T (column-wise matrix product; i.e. y is transposed) */

/* loss functions; output scalar */
kad_node_t *kad_mse(kad_node_t *x, kad_node_t *y);        /* mean square error */
kad_node_t *kad_ce_multi(kad_node_t *x, kad_node_t *y);   /* multi-class cross-entropy; x is the preidction and y is the truth */
kad_node_t *kad_ce_bin(kad_node_t *x, kad_node_t *y);     /* binary cross-entropy for (0,1) */
kad_node_t *kad_ce_bin_neg(kad_node_t *x, kad_node_t *y); /* binary cross-entropy for (-1,1) */
kad_node_t *kad_ce_multi_weighted(kad_node_t *pred, kad_node_t *truth, kad_node_t *weight);

#define KAD_PAD_NONE  0      /* use the smallest zero-padding */
#define KAD_PAD_SAME  (-2)   /* output to have the same dimension as input */

kad_node_t *kad_conv2d(kad_node_t *x, kad_node_t *w, int r_stride, int c_stride, int r_pad, int c_pad);             /* 2D convolution with weight matrix flipped */
kad_node_t *kad_max2d(kad_node_t *x, int kernel_h, int kernel_w, int r_stride, int c_stride, int r_pad, int c_pad); /* 2D max pooling */
kad_node_t *kad_conv1d(kad_node_t *x, kad_node_t *w, int stride, int pad);  /* 1D convolution with weight flipped */
kad_node_t *kad_max1d(kad_node_t *x, int kernel_size, int stride, int pad); /* 1D max pooling */
kad_node_t *kad_avg1d(kad_node_t *x, int kernel_size, int stride, int pad); /* 1D average pooling */

kad_node_t *kad_dropout(kad_node_t *x, kad_node_t *r);                      /* dropout at rate r */
kad_node_t *kad_sample_normal(kad_node_t *x);                               /* f(x) = x * r, where r is drawn from a standard normal distribution */

/* operators taking one operand */
kad_node_t *kad_square(kad_node_t *x); /* f(x) = x^2                         (element-wise square) */
kad_node_t *kad_sigm(kad_node_t *x);   /* f(x) = 1/(1+exp(-x))               (element-wise sigmoid) */
kad_node_t *kad_tanh(kad_node_t *x);   /* f(x) = (1-exp(-2x)) / (1+exp(-2x)) (element-wise tanh) */
kad_node_t *kad_relu(kad_node_t *x);   /* f(x) = max{0,x}                    (element-wise rectifier, aka ReLU) */
kad_node_t *kad_softmax(kad_node_t *x);/* f_i(x_1,...,x_n) = exp(x_i) / \sum_j exp(x_j) (softmax: tf.nn.softmax(x,dim=-1)) */
kad_node_t *kad_1minus(kad_node_t *x); /* f(x) = 1 - x */
kad_node_t *kad_exp(kad_node_t *x);    /* f(x) = exp(x) */
kad_node_t *kad_log(kad_node_t *x);    /* f(x) = log(x) */
kad_node_t *kad_sin(kad_node_t *x);    /* f(x) = sin(x) */

kad_node_t *kad_stdnorm(kad_node_t *x); /* layer normalization; applied to the last dimension */

/* operators taking an indefinite number of operands (e.g. pooling) */
kad_node_t *kad_avg(int n, kad_node_t **x);   /* f(x_1,...,x_n) = \sum_i x_i/n      (mean pooling) */
kad_node_t *kad_max(int n, kad_node_t **x);   /* f(x_1,...,x_n) = max{x_1,...,x_n}  (max pooling) */
kad_node_t *kad_stack(int n, kad_node_t **x); /* f(x_1,...,x_n) = [x_1,...,x_n]     (stack pooling) */
kad_node_t *kad_select(int n, kad_node_t **x, int which); /* f(x_1,...,x_n;i) = x_i (select pooling; -1 for the last) */

/* dimension reduction */
kad_node_t *kad_reduce_sum(kad_node_t *x, int axis);  /* tf.reduce_sum(x, axis) */
kad_node_t *kad_reduce_mean(kad_node_t *x, int axis); /* tf.reduce_mean(x, axis) */

/* special operators */
kad_node_t *kad_slice(kad_node_t *x, int axis, int start, int end); /* take a slice on the axis-th dimension */
kad_node_t *kad_concat(int axis, int n, ...);                       /* concatenate on the axis-th dimension */
kad_node_t *kad_concat_array(int axis, int n, kad_node_t **p);      /* the array version of concat */
kad_node_t *kad_reshape(kad_node_t *x, int n_d, int *d);            /* reshape; similar behavior to TensorFlow's reshape() */
kad_node_t *kad_reverse(kad_node_t *x, int axis);
kad_node_t *kad_switch(int n, kad_node_t **p);                      /* manually (as a hyperparameter) choose one input, default to 0 */

/* miscellaneous operations on a compiled graph */
int kad_size_var(int n, kad_node_t *const* v);   /* total size of all variables */
int kad_size_const(int n, kad_node_t *const* v); /* total size of all constants */

/* graph I/O */
int kad_save(FILE *fp, int n_node, kad_node_t **node);
kad_node_t **kad_load(FILE *fp, int *_n_node);

/* random number generator */
void *kad_rng(void);
void kad_srand(void *d, uint64_t seed);
uint64_t kad_rand(void *d);
double kad_drand(void *d);
double kad_drand_normal(void *d);
void kad_saxpy(int n, float a, const float *x, float *y);

/* debugging routines */
void kad_trap_fe(void); /* abort on divide-by-zero and NaN */
void kad_print_graph(FILE *fp, int n, kad_node_t **v);
void kad_check_grad(int n, kad_node_t **a, int from);

#ifdef __cplusplus
}
#endif

#define KAD_ALLOC      1
#define KAD_FORWARD    2
#define KAD_BACKWARD   3
#define KAD_SYNC_DIM   4

typedef int (*kad_op_f)(kad_node_t*, int);
extern kad_op_f kad_op_list[KAD_MAX_OP];
extern char *kad_op_name[KAD_MAX_OP];

static inline int kad_len(const kad_node_t *p) /* calculate the size of p->x */
{
	int n = 1, i;
	for (i = 0; i < p->n_d; ++i) n *= p->d[i];
	return n;
}

#endif
