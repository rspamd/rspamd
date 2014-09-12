#ifndef RSPAMD_TESTS_H
#define RSPAMD_TESTS_H

/* 
 * Here are described test functions for rspamd test suite 
 */

/* URL parser test */
void rspamd_url_test_func (void);

/* Memory pools */
void rspamd_mem_pool_test_func (void);

/* Expressions */
void rspamd_expression_test_func (void);

/* Fuzzy hashes */
void rspamd_fuzzy_test_func (void);

/* Stat file */
void rspamd_statfile_test_func (void);

/* Radix test */
void rspamd_radix_test_func (void);

/* DNS resolving */
void rspamd_dns_test_func (void);

/* Async IO */
void rspamd_async_test_func (void);

/* DKIM test */
void rspamd_dkim_test_func (void);

/* RRD test */
void rspamd_rrd_test_func (void);

#endif
