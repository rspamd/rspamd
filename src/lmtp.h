#ifndef RSPAMD_LMTP_H
#define RSPAMD_LMTP_H

#include "config.h"
#include "main.h"

#define LMTP_GREETING       220
#define LMTP_QUIT       221
#define LMTP_OK         250
#define LMTP_DATA       354
#define LMTP_ERROR_PROCESS  500
#define LMTP_FAILURE        530
#define LMTP_AUTH_ERROR     503
#define LMTP_BAD_CMD        503
#define LMTP_NO_RCPT        554
#define LMTP_TEMP_FAIL      421

#endif
