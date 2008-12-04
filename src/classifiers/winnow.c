/*
 * Winnow classifier
 */

#include <sys/types.h>
#include "classifiers.h"

#define WINNOW_PROMOTION 1.23
#define WINNOW_DEMOTION 0.83

struct winnow_callback_data {
	statfile_pool_t *pool;
	char *filename;
	double sum;
	int count;
	int in_class;
	time_t now;
};

static gboolean
classify_callback (gpointer key, gpointer value, gpointer data) 
{
	token_node_t *node = key;
	struct winnow_callback_data *cd = data;
	float v;
	
	/* Consider that not found blocks have value 1 */
	if ((v = statfile_pool_get_block (cd->pool, cd->filename, node->h1, node->h2, cd->now)) < 0.00001) {
		cd->sum += 1;
	}
	else {
		cd->sum += v;
	}

	cd->count ++;

	return FALSE;
}

static gboolean
learn_callback (gpointer key, gpointer value, gpointer data) 
{
	token_node_t *node = key;
	struct winnow_callback_data *cd = data;
	float v, c;

	c = (cd->in_class) ? WINNOW_PROMOTION : WINNOW_DEMOTION;

	/* Consider that not found blocks have value 1 */
	if ((v = statfile_pool_get_block (cd->pool, cd->filename, node->h1, node->h2, cd->now)) < 0.00001) {
		statfile_pool_set_block (cd->pool, cd->filename, node->h1, node->h2, cd->now, c);
	}
	else {
		statfile_pool_set_block (cd->pool, cd->filename, node->h1, node->h2, cd->now, v * c);
	}

	cd->count ++;
	
	return FALSE;
}


double 
winnow_classify (statfile_pool_t *pool, char *statfile, GTree *input)
{
	struct winnow_callback_data data;

	data.pool = pool;
	data.filename = statfile;
	data.sum = 0;
	data.count = 0;
	data.now = time (NULL);

	if (!statfile_pool_is_open (pool, statfile)) {
		if (statfile_pool_open (pool, statfile) == -1) {
			return 0;
		}
	}

	g_tree_foreach (input, classify_callback, &data);
	
	return data.sum / data.count;
}

void
winnow_learn (statfile_pool_t *pool, char *statfile, GTree *input, int in_class)
{
	struct winnow_callback_data data;

	data.pool = pool;
	data.filename = statfile;
	data.sum = 0;
	data.count = 0;
	data.in_class = in_class;
	data.now = time (NULL);

	if (!statfile_pool_is_open (pool, statfile)) {
		if (statfile_pool_open (pool, statfile) == -1) {
			return;
		}
	}

	statfile_pool_lock_file (pool, statfile);
	g_tree_foreach (input, learn_callback, &data);
	statfile_pool_unlock_file (pool, statfile);
	
}
