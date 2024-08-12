# Public suffixes list

Update procedure:

1. Download the list from the [official mirror](https://publicsuffix.org/list/public_suffix_list.dat)
2. Proceed through `idn.pl` script

1 liner: `curl https://publicsuffix.org/list/public_suffix_list.dat | idn.pl > effective_tld_names.dat`
