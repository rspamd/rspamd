/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0.
 */
#ifndef RSPAMD_UCL_UTIL_HXX
#define RSPAMD_UCL_UTIL_HXX

#include "contrib/libucl/ucl.h"
#include <memory>

namespace rspamd::ucl {

struct object_deleter {
	void operator()(ucl_object_t *obj) const
	{
		ucl_object_unref(obj);
	}
};

/* Own one UCL reference, including objects returned by parsers and builders. */
using owning_object = std::unique_ptr<ucl_object_t, object_deleter>;

}// namespace rspamd::ucl

#endif
