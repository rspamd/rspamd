#pragma once

#ifndef RSPAMD_SMTPUTF8_SYNTAX_H
#define RSPAMD_SMTPUTF8_SYNTAX_H

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The rules of draft-ietf-mailmaint-smtputf8-syntax, which restricts the
 * addresses RFC6532 permits. Each value names the first rule an address
 * breaks.
 */
enum rspamd_smtputf8_syntax_result {
	RSPAMD_SMTPUTF8_VALID = 0,
	RSPAMD_SMTPUTF8_BAD_UTF8,
	RSPAMD_SMTPUTF8_A_LABEL,
	RSPAMD_SMTPUTF8_CODE_POINT,
	RSPAMD_SMTPUTF8_SCRIPTS,
	RSPAMD_SMTPUTF8_NOT_NFC,
};

/*
 * Rule 1 bans a-labels in the domain too, but Exchange writes the domain
 * of an EAI address as a-labels, as in grå@xn--gr-zia.org. Set this to 0
 * once that mail is rare. The exemption covers only all-ASCII domains, and
 * a-labels in the local part are always invalid.
 */
#define RSPAMD_SMTPUTF8_ACCEPT_A_LABEL_DOMAINS 1

/**
 * Checks an address against draft-ietf-mailmaint-smtputf8-syntax
 * @param user the local part, without the quotes if it was quoted
 * @param domain the domain, as written in the address
 * @param user_quoted whether the local part was a quoted string
 * @return RSPAMD_SMTPUTF8_VALID or the rule the address breaks
 */
enum rspamd_smtputf8_syntax_result
rspamd_smtputf8_check_address(const char *user, gsize user_len,
							  const char *domain, gsize domain_len,
							  gboolean user_quoted);

/**
 * A short name for a result, such as "a-label", for use in logs and
 * symbol options
 */
const char *rspamd_smtputf8_result_name(enum rspamd_smtputf8_syntax_result r);

#ifdef __cplusplus
}
#endif

#endif
