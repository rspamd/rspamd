#ifndef RSPAMD_TESTS_H
#define RSPAMD_TESTS_H

/*
 * Here are described test functions for rspamd test suite
 */

#ifdef  __cplusplus
extern "C" {
#endif

/* URL parser test */
void rspamd_url_test_func (void);

/* Memory pools */
void rspamd_mem_pool_test_func (void);

/* Stat file */
void rspamd_statfile_test_func (void);

/* Radix test */
void rspamd_radix_test_func (void);

/* DNS resolving */
void rspamd_dns_test_func (void);

/* DKIM test */
void rspamd_dkim_test_func (void);

/* RRD test */
void rspamd_rrd_test_func (void);

void rspamd_upstream_test_func (void);

void rspamd_shingles_test_func (void);

void rspamd_http_test_func (void);

void rspamd_lua_test_func (void);

void rspamd_cryptobox_test_func (void);

void rspamd_heap_test_func (void);

void rspamd_lua_lua_pcall_vs_resume_test_func (void);

#ifdef  __cplusplus
}
#endif

#endif
