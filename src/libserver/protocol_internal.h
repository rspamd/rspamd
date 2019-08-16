/*-
 * Copyright 2017 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RSPAMD_PROTOCOL_INTERNAL_H
#define RSPAMD_PROTOCOL_INTERNAL_H

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Just check if the passed message is spam or not and reply as
 * described below
 */
#define MSG_CMD_CHECK "check"

/*
 * Modern check version
 */
#define MSG_CMD_CHECK_V2 "checkv2"
#define MSG_CMD_SCAN "scan"

/*
 * Check if message is spam or not, and return score plus list
 * of symbols hit
 */
#define MSG_CMD_SYMBOLS "symbols"
/*
 * Check if message is spam or not, and return score plus report
 */
#define MSG_CMD_REPORT "report"
/*
 * Check if message is spam or not, and return score plus report
 * if the message is spam
 */
#define MSG_CMD_REPORT_IFSPAM "report_ifspam"
/*
 * Ignore this message -- client opened connection then changed
 */
#define MSG_CMD_SKIP "skip"
/*
 * Return a confirmation that spamd is alive
 */
#define MSG_CMD_PING "ping"
/*
 * Process this message as described above and return modified message
 */
#define MSG_CMD_PROCESS "process"
/*
 * Headers
 */
#define HELO_HEADER "Helo"
#define FROM_HEADER "From"
#define IP_ADDR_HEADER "IP"
#define RCPT_HEADER "Rcpt"
#define SUBJECT_HEADER "Subject"
#define SETTINGS_ID_HEADER "Settings-ID"
#define SETTINGS_HEADER "Settings"
#define QUEUE_ID_HEADER "Queue-ID"
#define USER_HEADER "User"
#define URLS_HEADER "URL-Format"
#define PASS_HEADER "Pass"
#define HOSTNAME_HEADER "Hostname"
#define DELIVER_TO_HEADER "Deliver-To"
#define NO_LOG_HEADER "Log"
#define MLEN_HEADER "Message-Length"
#define USER_AGENT_HEADER "User-Agent"
#define MTA_TAG_HEADER "MTA-Tag"
#define PROFILE_HEADER "Profile"
#define TLS_CIPHER_HEADER "TLS-Cipher"
#define TLS_VERSION_HEADER "TLS-Version"
#define MTA_NAME_HEADER "MTA-Name"
#define MILTER_HEADER "Milter"
#define FILENAME_HEADER "Filename"
#define FLAGS_HEADER "Flags"
#define CERT_ISSUER_HEADER "TLS-Cert-Issuer"
#define MAILER_HEADER "Mailer"
#define RAW_DATA_HEADER "Raw"
#define COMPRESSION_HEADER "Compression"
#define MESSAGE_OFFSET_HEADER "Message-Offset"

#ifdef  __cplusplus
}
#endif

#endif //RSPAMD_PROTOCOL_INTERNAL_H
