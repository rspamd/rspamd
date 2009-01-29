/*
 * Common classifier functions
 */

#include <sys/types.h>
#include "classifiers.h"

struct classifier classifiers[] = {
	{
	.name             = "winnow", 
	.init_func        = winnow_init, 
	.classify_func    = winnow_classify, 
	.learn_func       = winnow_learn, 
	.result_file_func = winnow_result_file 
	},
};

struct classifier*
get_classifier (char *name)
{
	int i;

	for (i = 0; i < sizeof (classifiers) / sizeof (classifiers[0]); i ++) {
		if (strcmp (classifiers[i].name, name) == 0) {
			return &classifiers[i];
		}
	}

	return NULL;
}

/*
 * vi:ts=4
 */
