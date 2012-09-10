/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Common classifier functions
 */

#include "classifiers.h"

struct classifier               classifiers[] = {
		{
			.name = "winnow",
			.init_func = winnow_init,
			.classify_func = winnow_classify,
			.learn_func = winnow_learn,
			.learn_spam_func = winnow_learn_spam,
			.weights_func = winnow_weights
		},
		{
			.name = "bayes",
			.init_func = bayes_init,
			.classify_func = bayes_classify,
			.learn_func = bayes_learn,
			.learn_spam_func = bayes_learn_spam,
			.weights_func = bayes_weights
		}
};

struct classifier              *
get_classifier (char *name)
{
	guint                             i;

	for (i = 0; i < sizeof (classifiers) / sizeof (classifiers[0]); i++) {
		if (strcmp (classifiers[i].name, name) == 0) {
			return &classifiers[i];
		}
	}

	return NULL;
}

/*
 * vi:ts=4
 */
