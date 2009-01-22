#ifndef CLASSIFIERS_H
#define CLASSIFIERS_H

#include <sys/types.h>
#include "../config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include "../mem_pool.h"
#include "../statfile.h"
#include "../tokenizers/tokenizers.h"

/* Common classifier structure */
struct classifier {
	char *name;
	double (*classify_func)(statfile_pool_t *pool, char *statfile, GTree *input);
	void (*learn_func)(statfile_pool_t *pool, char *statfile, GTree *input, int in_class);
	double (*add_result_func)(double result, double new);
};

/* Get classifier structure by name or return NULL if this name is not found */
struct classifier* get_classifier (char *name);
/* Winnow algorithm */
double winnow_classify (statfile_pool_t *pool, char *statfile, GTree *input);
void winnow_learn (statfile_pool_t *pool, char *statfile, GTree *input, int in_class);
double winnow_add_result (double result, double new);

/* Array of all defined classifiers */
extern struct classifier classifiers[];

#endif
/*
 * vi:ts=4
 */
