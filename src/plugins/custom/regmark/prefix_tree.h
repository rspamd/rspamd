#ifndef RSPAMD_PREFIX_TREE_H
#define RSPAMD_PREFIX_TREE_H

#include "../../../config.h"

#define LETTERS_NUMBER 26

typedef struct prefix_tree_leaf_s {
	uintptr_t data;
} prefix_tree_leaf_t;

typedef struct prefix_tree_level_s {
	struct prefix_tree_leaf_s leafs[LETTERS_NUMBER];
} prefix_tree_level_t;

typedef struct prefix_tree_s {
	prefix_tree_level_t *nodes;
	int levels;
} prefix_tree_t;

prefix_tree_t* prefix_tree_new (int levels);

uintptr_t add_string (prefix_tree_t *tree, const char *input, int skip_levels);

uintptr_t check_string (prefix_tree_t *tree, const char *input, int skip_levels);

uintptr_t add_string_longest (prefix_tree_t *tree, const char *input, int skip_levels);
uintptr_t check_string_longest (prefix_tree_t *tree, const char *input, int skip_levels);

void prefix_tree_free (prefix_tree_t *tree);

gboolean save_prefix_tree (prefix_tree_t *tree, const char *filename);
prefix_tree_t* load_prefix_tree (const char *filename);

#endif
