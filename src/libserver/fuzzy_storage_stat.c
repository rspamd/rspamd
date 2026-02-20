/*
 * Copyright 2026 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"
#include "rspamd.h"
#include "util.h"
#include "rspamd_control.h"
#include "libserver/worker_util.h"
#include "fuzzy_backend/fuzzy_backend.h"
#include "fuzzy_storage_internal.h"
#include "fuzzy_wire.h"
#include "libcryptobox/keypair.h"
#include "unix-std.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

ucl_object_t *
rspamd_fuzzy_storage_stat_key(const struct fuzzy_key_stat *key_stat)
{
	ucl_object_t *res;

	res = ucl_object_typed_new(UCL_OBJECT);

	ucl_object_insert_key(res, ucl_object_fromint(key_stat->checked),
						  "checked", 0, false);
	ucl_object_insert_key(res, ucl_object_fromdouble(key_stat->checked_ctr.mean),
						  "checked_per_hour", 0, false);
	ucl_object_insert_key(res, ucl_object_fromint(key_stat->matched),
						  "matched", 0, false);
	ucl_object_insert_key(res, ucl_object_fromdouble(key_stat->matched_ctr.mean),
						  "matched_per_hour", 0, false);
	ucl_object_insert_key(res, ucl_object_fromint(key_stat->added),
						  "added", 0, false);
	ucl_object_insert_key(res, ucl_object_fromint(key_stat->deleted),
						  "deleted", 0, false);
	ucl_object_insert_key(res, ucl_object_fromint(key_stat->errors),
						  "errors", 0, false);

	return res;
}

void rspamd_fuzzy_key_stat_iter(const unsigned char *pk_iter,
								struct fuzzy_key *fuzzy_key,
								ucl_object_t *keys_obj,
								gboolean ip_stat)
{
	struct fuzzy_key_stat *key_stat = fuzzy_key->stat;
	char keyname[17];

	if (key_stat) {
		rspamd_snprintf(keyname, sizeof(keyname), "%8bs", pk_iter);

		ucl_object_t *elt = rspamd_fuzzy_storage_stat_key(key_stat);

		if (key_stat->last_ips && ip_stat) {
			int i = 0;
			ucl_object_t *ip_elt = ucl_object_typed_new(UCL_OBJECT);
			gpointer k, v;

			while ((i = rspamd_lru_hash_foreach(key_stat->last_ips,
												i, &k, &v)) != -1) {
				ucl_object_t *ip_cur = rspamd_fuzzy_storage_stat_key(v);
				ucl_object_insert_key(ip_elt, ip_cur,
									  rspamd_inet_address_to_string(k), 0, true);
			}
			ucl_object_insert_key(elt, ip_elt, "ips", 0, false);
		}

		int flag;
		struct fuzzy_key_stat *flag_stat;
		ucl_object_t *flags_ucl = ucl_object_typed_new(UCL_OBJECT);

		kh_foreach_key_value_ptr(fuzzy_key->flags_stat, flag, flag_stat, {
			char intbuf[16];
			rspamd_snprintf(intbuf, sizeof(intbuf), "%d", flag);
			ucl_object_insert_key(flags_ucl, rspamd_fuzzy_storage_stat_key(flag_stat),
								  intbuf, 0, true);
		});

		ucl_object_insert_key(elt, flags_ucl, "flags", 0, false);

		ucl_object_insert_key(elt,
							  rspamd_keypair_to_ucl(fuzzy_key->key, RSPAMD_KEYPAIR_ENCODING_DEFAULT,
													RSPAMD_KEYPAIR_DUMP_NO_SECRET | RSPAMD_KEYPAIR_DUMP_FLATTENED),
							  "keypair", 0, false);

		if (fuzzy_key->rl_bucket) {
			ucl_object_insert_key(elt,
								  rspamd_leaky_bucket_to_ucl(fuzzy_key->rl_bucket),
								  "ratelimit", 0, false);
		}

		ucl_object_insert_key(keys_obj, elt, keyname, 0, true);
	}
}

ucl_object_t *
rspamd_fuzzy_stat_to_ucl(struct rspamd_fuzzy_storage_ctx *ctx, gboolean ip_stat)
{
	struct fuzzy_key *fuzzy_key;
	ucl_object_t *obj, *keys_obj, *elt, *ip_elt;
	const unsigned char *pk_iter;

	obj = ucl_object_typed_new(UCL_OBJECT);

	keys_obj = ucl_object_typed_new(UCL_OBJECT);

	kh_foreach(ctx->keys, pk_iter, fuzzy_key, {
		rspamd_fuzzy_key_stat_iter(pk_iter, fuzzy_key, keys_obj, ip_stat);
	});

	if (ctx->dynamic_keys) {
		kh_foreach(ctx->dynamic_keys, pk_iter, fuzzy_key, {
			rspamd_fuzzy_key_stat_iter(pk_iter, fuzzy_key, keys_obj, ip_stat);
		});
	}

	ucl_object_insert_key(obj, keys_obj, "keys", 0, false);

	/* Now generic stats */
	ucl_object_insert_key(obj,
						  ucl_object_fromint(ctx->stat.fuzzy_hashes),
						  "fuzzy_stored",
						  0,
						  false);
	ucl_object_insert_key(obj,
						  ucl_object_fromint(ctx->stat.fuzzy_hashes_expired),
						  "fuzzy_expired",
						  0,
						  false);
	ucl_object_insert_key(obj,
						  ucl_object_fromint(ctx->stat.invalid_requests),
						  "invalid_requests",
						  0,
						  false);
	ucl_object_insert_key(obj,
						  ucl_object_fromint(ctx->stat.delayed_hashes),
						  "delayed_hashes",
						  0,
						  false);

	if (ctx->errors_ips && ip_stat) {
		gpointer k, v;
		int i = 0;
		ip_elt = ucl_object_typed_new(UCL_OBJECT);

		while ((i = rspamd_lru_hash_foreach(ctx->errors_ips, i, &k, &v)) != -1) {
			ucl_object_insert_key(ip_elt,
								  ucl_object_fromint(*(uint64_t *) v),
								  rspamd_inet_address_to_string(k), 0, true);
		}

		ucl_object_insert_key(obj,
							  ip_elt,
							  "errors_ips",
							  0,
							  false);
	}

	/* Checked by epoch */
	elt = ucl_object_typed_new(UCL_ARRAY);

	for (int i = RSPAMD_FUZZY_EPOCH10; i < RSPAMD_FUZZY_EPOCH_MAX; i++) {
		ucl_array_append(elt,
						 ucl_object_fromint(ctx->stat.fuzzy_hashes_checked[i]));
	}

	ucl_object_insert_key(obj, elt, "fuzzy_checked", 0, false);

	/* Shingles by epoch */
	elt = ucl_object_typed_new(UCL_ARRAY);

	for (int i = RSPAMD_FUZZY_EPOCH10; i < RSPAMD_FUZZY_EPOCH_MAX; i++) {
		ucl_array_append(elt,
						 ucl_object_fromint(ctx->stat.fuzzy_shingles_checked[i]));
	}

	ucl_object_insert_key(obj, elt, "fuzzy_shingles", 0, false);

	/* Matched by epoch */
	elt = ucl_object_typed_new(UCL_ARRAY);

	for (int i = RSPAMD_FUZZY_EPOCH10; i < RSPAMD_FUZZY_EPOCH_MAX; i++) {
		ucl_array_append(elt,
						 ucl_object_fromint(ctx->stat.fuzzy_hashes_found[i]));
	}

	ucl_object_insert_key(obj, elt, "fuzzy_found", 0, false);


	return obj;
}

gboolean
rspamd_fuzzy_storage_stat(struct rspamd_main *rspamd_main,
						  struct rspamd_worker *worker, int fd,
						  int attached_fd,
						  struct rspamd_control_command *cmd,
						  gpointer ud)
{
	struct rspamd_fuzzy_storage_ctx *ctx = ud;
	struct rspamd_control_reply rep;
	ucl_object_t *obj;
	struct ucl_emitter_functions *emit_subr;
	unsigned char fdspace[CMSG_SPACE(sizeof(int))];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;

	int outfd = -1;
	char tmppath[PATH_MAX];

	memset(&rep, 0, sizeof(rep));
	rep.type = RSPAMD_CONTROL_FUZZY_STAT;
	rep.id = cmd->id;

	rspamd_snprintf(tmppath, sizeof(tmppath), "%s%c%s-XXXXXXXXXX",
					rspamd_main->cfg->temp_dir, G_DIR_SEPARATOR, "fuzzy-stat");

	if ((outfd = mkstemp(tmppath)) == -1) {
		rep.reply.fuzzy_stat.status = errno;
		msg_info_main("cannot make temporary stat file for fuzzy stat: %s",
					  strerror(errno));
	}
	else {
		const char *backend_id;

		rep.reply.fuzzy_stat.status = 0;

		backend_id = rspamd_fuzzy_backend_id(ctx->backend);
		if (backend_id) {
			memcpy(rep.reply.fuzzy_stat.storage_id,
				   backend_id,
				   sizeof(rep.reply.fuzzy_stat.storage_id));
		}

		obj = rspamd_fuzzy_stat_to_ucl(ctx, TRUE);
		emit_subr = ucl_object_emit_fd_funcs(outfd);
		ucl_object_emit_full(obj, UCL_EMIT_JSON_COMPACT, emit_subr, NULL);
		ucl_object_emit_funcs_free(emit_subr);
		ucl_object_unref(obj);
		/* Rewind output file */
		close(outfd);
		outfd = open(tmppath, O_RDONLY);
		unlink(tmppath);
	}

	/* Now we can send outfd and status message */
	memset(&msg, 0, sizeof(msg));

	/* Attach fd to the message */
	if (outfd != -1) {
		memset(fdspace, 0, sizeof(fdspace));
		msg.msg_control = fdspace;
		msg.msg_controllen = sizeof(fdspace);
		cmsg = CMSG_FIRSTHDR(&msg);

		if (cmsg) {
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			cmsg->cmsg_len = CMSG_LEN(sizeof(int));
			memcpy(CMSG_DATA(cmsg), &outfd, sizeof(int));
		}
	}

	iov.iov_base = &rep;
	iov.iov_len = sizeof(rep);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(fd, &msg, 0) == -1) {
		msg_err_main("cannot send fuzzy stat: %s", strerror(errno));
	}

	if (outfd != -1) {
		close(outfd);
	}

	return TRUE;
}
