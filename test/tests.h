#ifndef RSPAMD_TESTS_H
#define RSPAMD_TESTS_H

/* 
 * Here are described test functions for rspamd test suite 
 */

/* URL parser test */
void rspamd_url_test_func ();

/* Memcached library test */
void rspamd_memcached_test_func ();

/* Memory pools */
void rspamd_mem_pool_test_func ();

/* Expressions */
void rspamd_expression_test_func ();

/* Fuzzy hashes */
void rspamd_fuzzy_test_func ();

/* Stat file */
void rspamd_statfile_test_func ();

/* DNS resolving */
void rspamd_dns_test_func ();

#endif
