MODULE = Mail::Rspamd PACKAGE = Mail::Rspamd::Hash::Header PREFIX=hash_

Mail::Rspamd::Hash::Header
hash_TIEHASH (Class, objptr)
		char *			Class
		Mail::Rspamd::Message		objptr
	PREINIT:
		hash_header *		hash;
	CODE:
		hash = g_malloc (sizeof (hash_header));
		hash->keyindex = 0;
		hash->objptr = objptr;
		hash->fetchvalue = NULL;
		RETVAL = hash;
	OUTPUT:
		RETVAL

void
hash_DESTROY (obj)
		Mail::Rspamd::Hash::Header	obj
	CODE:
		obj->objptr = NULL;
		g_free (obj);

void
hash_FETCH (obj, key)
		Mail::Rspamd::Hash::Header	obj
		const char *		key
	PREINIT:
		Mail__Rspamd__Message		msg;
		GList			*gret = NULL, *item;
		AV *			retav;
		I32			gimme = GIMME_V;
	PPCODE:
		msg = obj->objptr;

		/* THE HACK - FETCH method would get value indirectly from NEXTKEY */
		if (obj->keyindex != -1 && obj->fetchvalue != NULL) {
			XPUSHs (sv_2mortal (newSVpv (obj->fetchvalue, 0)));
			obj->fetchvalue == NULL;
		  	XSRETURN(1);
		}

		obj->fetchvalue = NULL;
		
		gret = message_get_header (msg, key);

		if (!gret || gret->data == NULL) {
			if (gret) {
				g_list_free(gret);
			}
		  
			XSRETURN(0);
		} else {
			if (gret->next == NULL) { // one value
				XPUSHs (sv_2mortal (newSVpv ((char *)(gret->data), 0)));
		  	} else {
				if (gimme == G_ARRAY) {
			  		item = gret;
			  		while (item && item->data) {
						XPUSHs (sv_2mortal (newSVpv ((char *)(item->data), 0)));
						item = item->next;
			  		}
				} else if (gimme == G_SCALAR) {
			  		retav = newAV();
			  		item = gret;
			  		while (item && item->data) {
						av_push (retav, newSVpv ((char *)g_strdup ((item->data)), 0));
						item = item->next;
			  		}
			  		XPUSHs (newRV_noinc ((SV *)retav));
				}
			}
		}
		if (gret) {
			item = gret;
		  	while (item) {
				if (item->data) {
			  		g_free((char *)(item->data));
				}
				item = item->next;
			}
			g_list_free(gret);
		}

void
hash_STORE (obj, key, svmixed)
		Mail::Rspamd::Hash::Header	obj
		const char *		key
		SV *			svmixed
	PREINIT:
		Mail__Rspamd__Message		msg;
		char *			value;
		SV *			svvalue;
		svtype			svvaltype;
		STRLEN			vallen;
	CODE:
		/* only one value can be stored - no arrays allowed by perl */
		msg = obj->objptr;

		svvalue = svmixed;
		if (SvROK (svmixed)) {
			svvalue = SvRV(svmixed);
		}
		svvaltype = SvTYPE (svvalue);

		if (SvGMAGICAL(svvalue)) {
			mg_get(svvalue);
		}
		
		/* delete header for the first array item */
		g_mime_object_remove_header (GMIME_OBJECT(msg), key);

		if (svvaltype == SVt_PVAV) {
			AV *	avvalue;
			I32		i, avlen;
			SV *	svtmp;

			/* set header */
			avvalue = (AV *)svvalue;
			avlen = av_len(avvalue);
			for (i=avlen; i>=0; --i) {
				svtmp = (SV *)(*(av_fetch (avvalue, i, 0)));

				if (SvGMAGICAL(svtmp)) {
			  		mg_get(svtmp);
				}
			
				if (svtmp && SvPOKp(svtmp)) {
					value = (char *)SvPV(svtmp, vallen);
					message_set_header (msg, key, value);
				}
			}
		} else if (SvPOK(svvalue) || SvIOK(svvalue) || SvNOK(svvalue)) {
			value = (char *)SvPV (svvalue, vallen);
			message_set_header (msg, key, value);
		} else { /* assume scalar value */
			/* undefined value -> remove header */
			if (!(SvOK(svvalue))) {
				g_mime_object_remove_header (GMIME_OBJECT(msg), key);
			}
		}

gboolean
hash_EXISTS (obj, key)
		Mail::Rspamd::Hash::Header	obj
		const char *		key
	PREINIT:
		Mail__Rspamd__Message		msg;
		GList			*gret, *item;
	CODE:
		msg = obj->objptr;
		gret = message_get_header (msg, key);
		RETVAL = (gret != NULL && gret->data != NULL);
		if (gret) {
			item = gret;
			while (item) {
				if (item->data) {
					g_free((char *)(item->data));
				}
				item = item->next;
			}
			g_list_free(gret);
		}
	OUTPUT:
		RETVAL

void
hash_DELETE(obj, key)
		Mail::Rspamd::Hash::Header	obj
		const char *		key
	CODE:
		g_mime_object_remove_header (GMIME_OBJECT(obj->objptr), key);

void
hash_NEXTKEY(obj, lastkey = NULL)
		Mail::Rspamd::Hash::Header	obj
		const char *		lastkey
	ALIAS:
		Mail::Rspamd::Hash::Header::FIRSTKEY = 1
	PREINIT:
		char *			key = NULL;
		char *			value = NULL;
		Mail__Rspamd__Message		msg;
		I32			gimme = GIMME_V;
		gint			i, j, found;
		local_GMimeHeader *		header;
		struct raw_header	*h;
	INIT:
		if (ix == 1) {
			obj->keyindex = -1;
		}
	PPCODE:
		msg = obj->objptr;
		++obj->keyindex;
		i = obj->keyindex;
		header = GMIME_OBJECT(msg)->headers;

		h = header->headers;
		j = 0;
		found = 0;
		while (h) {
			if (j >= i) {
				key = h->name;
				value = h->value;
				found = 1;
				break;
			}
			j++;
			h = h->next;
		}
		
		if (!found && key == NULL) {
			obj->keyindex = -1;
		}

		/* THE HACK - FETCH method would get value indirectly */
		obj->fetchvalue = NULL;

		if (key) {
			XPUSHs (sv_2mortal (newSVpv (key, 0)));
			if (gimme != G_SCALAR && value) {
				XPUSHs (sv_2mortal (newSVpv (value, 0)));
			}
		  	/* THE HACK - FETCH method would get value indirectly */
		  	obj->fetchvalue = value;
		}

void
hash_CLEAR(obj)
		Mail::Rspamd::Hash::Header	obj
	PREINIT:
		Mail__Rspamd__Message		message;
		local_GMimeHeader		*header;
	CODE:
		message = obj->objptr;
		
		g_free (message->from);
		message->from = NULL;

		g_free (message->reply_to);
		message->reply_to = NULL;
		
		/* destroy all recipients */
		g_hash_table_foreach_remove (message->recipients, recipients_destroy, NULL);
		
		g_free (message->subject);
		message->subject = NULL;
		
		g_free (message->message_id);
		message->message_id = NULL;

		/* free all the headers */
		header = GMIME_OBJECT(message)->headers;
		g_mime_header_destroy (header);
		GMIME_OBJECT(message)->headers = g_mime_header_new ();


