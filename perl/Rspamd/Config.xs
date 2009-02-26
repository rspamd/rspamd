MODULE = Mail::Rspamd   PACKAGE = Mail::Rspamd::Config PREFIX = rspamd_config_
PROTOTYPES: DISABLE

SV *
rspamd_config_get_scalar (cfg, param)
		Mail::Rspamd::Config cfg
		const char *param
	CODE:
		struct config_scalar *sc;
		int val;

		sc = g_hash_table_lookup (cfg->cfg_params, param);
		if (sc == NULL) {
			XSRETURN_UNDEF;
		}
		else {
			switch (sc->type) {
				case SCALAR_TYPE_SIZE:
					RETVAL = newSViv ((int)(*(size_t *)sc->pointer));
					break;
				case SCALAR_TYPE_INT:
				case SCALAR_TYPE_UINT:
					RETVAL = newSViv (*(int *)sc->pointer);
					break;
				case SCALAR_TYPE_STR:
					RETVAL = newSVpv ((char *)sc->pointer, 0);
					break;
			}
		}


void
rspamd_config_set_scalar (cfg, param, value)
		Mail::Rspamd::Config cfg
		const char *param
		SV* value
	CODE:
		char *param, *charval;
		int intval;

		sc = g_hash_table_lookup (cfg->cfg_params, param);
		if (sc == NULL) {
			XSRETURN_UNDEF;
		}
		else {
			switch (sc->type) {
				case SCALAR_TYPE_SIZE:
					intval = (int)SvIV (value);
					*((size_t *)sc->pointer) = intval;
					break;
				case SCALAR_TYPE_INT:
				case SCALAR_TYPE_UINT:
					intval = (int)SvIV (value);
					*((int *)sc->pointer) = intval;
					break;
				case SCALAR_TYPE_STR:
					charval = (char *)SvPVX (value);
					*((char **)sc->pointer) = charval;
					break;
			}
		}

HV *
rspamd_config_get_metric (r, name)
		Mail::Rspamd::Config cfg
		const char *name
	CODE:
		struct metric *val;
		
		val = g_hash_table_lookup (r->metrics, name);
		if (val == NULL) {
			XSRETURN_UNDEF;
		}
		else {
			RETVAL = newHV();

			(void)hv_store_ent (RETVAL, 
					newSVpv ("name", sizeof ("name") - 1), 
					newSVpv (val->name, strlen (val->name)), 0);
			(void)hv_store_ent (RETVAL, 
					newSVpv ("func_name", sizeof ("func_name") - 1), 
					newSVpv (val->func_name, strlen (val->func_name)), 0);
			(void)hv_store_ent (RETVAL, 
					newSVpv ("required_score", sizeof ("required_score") - 1), 
					newSVnv (val->required_score), 0);
			sv_2mortal((SV*)RETVAL);
		}
	OUTPUT:
		RETVAL

HV *
rspamd_config_get_statfile (r, name)
		Mail::Rspamd::Config cfg
		const char *name
	CODE:
		struct statfile *val;
		char *name;
		
		val = g_hash_table_lookup (r->statfiles, name);
		if (val == NULL) {
			XSRETURN_UNDEF;
		}
		else {
			RETVAL = newHV();

			(void)hv_store_ent (RETVAL, 
					newSVpv ("alias", sizeof ("alias") - 1), 
					newSVpv (val->alias, strlen (val->alias)), 0);
			(void)hv_store_ent (RETVAL, 
					newSVpv ("pattern", sizeof ("pattern") - 1), 
					newSVpv (val->pattern, strlen (val->pattern)), 0);
			(void)hv_store_ent (RETVAL, 
					newSVpv ("metric", sizeof ("metric") - 1), 
					newSVpv (val->metric, strlen (val->metric)), 0);
			(void)hv_store_ent (RETVAL, 
					newSVpv ("weight", sizeof ("weight") - 1), 
					newSVnv (val->weight), 0);
			(void)hv_store_ent (RETVAL, 
					newSVpv ("size", sizeof ("size") - 1), 
					newSViv (val->size), 0);
			sv_2mortal((SV*)RETVAL);
		}
	OUTPUT:
		RETVAL

SV*
rspamd_config_get_module_param (r, modulename, paramname)
		Mail::Rspamd::Config cfg
		const char *modulename
		const char *paramname
	CODE:
		char *value;

		value = get_module_opt (r, modulename, paramname);
		if (value == NULL) {
			XSRETURN_UNDEF;
		}
		RETVAL = newSVpv (value, 0);
	OUTPUT:
		RETVAL

