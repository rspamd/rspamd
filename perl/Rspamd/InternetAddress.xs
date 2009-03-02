MODULE = Mail::Rspamd PACKAGE = Mail::Rspamd::InternetAddress PREFIX = rspamd_internet_address_

Mail::Rspamd::InternetAddress
rspamd_internet_address_new (Class, name, address)
	CASE: items <= 1
		char *		Class
	CODE:
#ifdef GMIME24
		XSRETURN_UNDEF;
#else
		RETVAL = internet_address_new ();
		plist = g_list_prepend (plist, RETVAL);
#endif
	OUTPUT:
		RETVAL
	CASE: items == 2
		char *		Class
		char *		name
	CODE:
#ifdef GMIME24
		RETVAL = internet_address_group_new (name);
#else
		RETVAL = internet_address_new_group (name);
#endif
		plist = g_list_prepend (plist, RETVAL);
	OUTPUT:
		RETVAL
	CASE: items == 3
		char *		Class
		char *		name
		char *		address
	CODE:
#ifdef GMIME24
		RETVAL = internet_address_mailbox_new (name, address);
#else
		RETVAL = internet_address_new_name (name, address);
#endif
		plist = g_list_prepend (plist, RETVAL);
	OUTPUT:
		RETVAL

void
DESTROY(ia)
		Mail::Rspamd::InternetAddress	ia
	CODE:
		if (g_list_find (plist,ia)) {
			internet_address_unref (ia);
			plist = g_list_remove (plist, ia);
		}

AV *
rspamd_internet_address_parse_string (str)
		const char *		str
	PREINIT:
		InternetAddressList *		addrlist;
		AV * 		retav;
		int i;
	CODE:
#ifdef GMIME24
		addrlist = internet_address_list_parse_string (str);
#else
		addrlist = internet_address_parse_string (str);
#endif
		retav = newAV ();
#ifdef GMIME24
		i = internet_address_list_length (addrlist);
		while (i > 0) {
			SV * address = newSViv(0);
			sv_setref_pv (address, "Mail::Rspamd::InternetAddress", (Mail__Rspamd__InternetAddress)internet_address_list_get_address (addrlist, i));
			av_push (retav, address);
			-- i;
		}
#else
		while (addrlist) {
		  SV * address = newSViv (0);
		  sv_setref_pv (address, "Mail::Rspamd::InternetAddress", (Mail__Rspamd__InternetAddress)(addrlist->address));
		  av_push (retav, address);
		  addrlist = addrlist->next;
		}
#endif
		RETVAL = retav;
	OUTPUT:
		RETVAL

#ifdef GMIME24

void
interface_ia_set (ia, value)
		Mail::Rspamd::InternetAddress	ia
	char *				value
	INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_RSPAMD_IA_SET
	INTERFACE:
	set_name

#else

void
interface_ia_set (ia, value)
		Mail::Rspamd::InternetAddress	ia
	char *				value
	INTERFACE_MACRO:
	XSINTERFACE_FUNC
	XSINTERFACE_FUNC_RSPAMD_IA_SET
	INTERFACE:
	set_name
	set_addr

#endif

SV *
rspamd_internet_address_to_string (ia, encode = TRUE)
		Mail::Rspamd::InternetAddress	ia
		gboolean		encode
	PREINIT:
		char *		textdata;
	CODE:
		textdata = internet_address_to_string (ia, encode);
		if (textdata == NULL) {
			XSRETURN_UNDEF;
		}
		RETVAL = newSVpv (textdata, 0);
	OUTPUT:
		RETVAL

void
rspamd_internet_address_set_group (ia, ...)
		Mail::Rspamd::InternetAddress	ia
	PREINIT:
		Mail__Rspamd__InternetAddress	addr;
		InternetAddressList *		addrlist = NULL;
		int			i;
	CODE:
		if (items < 2) {
	  		XSRETURN_UNDEF;
		}
		for (i = items - 1; i > 0; --i) {
			/* retrieve each address from the perl array */
			if (sv_derived_from (ST (items - i), "Mail::Rspamd::InternetAddress")) {
				IV tmp = SvIV ((SV*)SvRV (ST (items - i)));
				addr = INT2PTR (Mail__Rspamd__InternetAddress, tmp);
			}
			if (addr) {
#ifdef GMIME24
				internet_address_list_add (addrlist, addr);
#else
				internet_address_list_append (addrlist, addr);
#endif
			}
		}
		if (addrlist) {
			internet_address_set_group (ia, addrlist);
		}

void
rspamd_internet_address_add_member (ia, member)
		Mail::Rspamd::InternetAddress	ia
		Mail::Rspamd::InternetAddress	member
	CODE:
		internet_address_add_memeber (ia, member);

Mail::Rspamd::InternetAddressType
rspamd_internet_address_type (ia)
		Mail::Rspamd::InternetAddress	ia
	CODE:
#ifndef GMIME24
		RETVAL = ia->type;
#else
		XSRETURN_UNDEF;
#endif
	OUTPUT:
		RETVAL

