
MODULE = Mail::Rspamd   PACKAGE = Mail::Rspamd::Task PREFIX = rspamd_task_
PROTOTYPES: DISABLE

Mail::Rspamd::Message
rspamd_task_get_message (task)
		Mail::Rspamd::Task task
	CODE:
		RETVAL = task->message;
	OUTPUT:
		RETVAL

void
rspamd_task_set_message (message)
		Mail::Rspamd::Message message
	CODE:
		g_object_unref (G_OBJECT(task->message));
		task->message = message;

SV*
rspamd_task_ip (task)
		Mail::Rspamd::Task task
	CODE:	
		RETVAL = newSVpv (inet_ntoa (task->from_addr), 0);
	OUTPUT:
		RETVAL

SV*
rspamd_task_from (task)
		Mail::Rspamd::Task task
	CODE:
		if (task->from == NULL) {
			XSRETURN_UNDEF;
		}
		RETVAL = newSVpv (task->from, 0);
	OUTPUT:
		RETVAL

void
rspamd_task_save_point (task)
		Mail::Rspamd::Task task
    CODE:
    	task->save.saved = 1;

void
rspamd_task_recall_filter (task)
		Mail::Rspamd::Task task
    CODE:
    	process_filters (task);

void
rspamd_task_insert_result (task, metric, symbol, flag)
		Mail::Rspamd::Task task
		const char *metric
		const char *symbol
		double flag
	CODE:
		insert_result (task, metric, symbol, flag, NULL);

Mail::Rspamd::Conf
rspamd_task_get_conf (task)
		Mail::Rspamd::Task task
	CODE:
		RETVAL = task->cfg;
	OUTPUT:
		RETVAL

AV*
rspamd_task_get_urls (task)
		Mail::Rspamd::Task task
	PREINIT:
		AV* retav;
		struct uri *url;
	CODE:
		retav = newAV ();
		TAILQ_FOREACH (url, &task.urls, next) {
			av_push (retav, newSVpv ((char *)g_strdup (struri (url)), 0));
		}

		RETVAL = retav;
	OUTPUT:
		RETVAL

AV*
rspamd_task_get_text_parts (task)
		Mail::Rspamd::Task task
	PREINIT:
		AV* retav;
		GList *cur;
		SV* ps;
	CODE:
		retav = newAV ();
		cur = g_list_first (task->text_parts);
		while (cur) {
			ps = newSViv (0);
			sv_setref_pv (ps, "Mail::Rspamd::TextPart", (Mail__Rspamd__TextPart)(cur->data));
			av_push(retav, ps);
			cur = g_list_next (task->text_parts);
		}

		RETVAL = retav;
	OUTPUT:
		RETVAL

