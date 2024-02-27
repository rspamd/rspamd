#include "rspamd.h"
extern worker_t normal_worker;
extern worker_t controller_worker;
extern worker_t fuzzy_worker;
extern worker_t rspamd_proxy_worker;


worker_t *workers[] = {
&normal_worker,
&controller_worker,
&fuzzy_worker,
&rspamd_proxy_worker,
NULL
};
