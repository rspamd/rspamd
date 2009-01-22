/*
 * Common classifier functions
 */

#include <sys/types.h>
#include "classifiers.h"

struct classifier classifiers[] = {
	{"winnow", winnow_classify, winnow_learn, winnow_add_result },
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
