# Public suffixes list

Update procedure:

1. Download the list from the [official mirror](https://publicsuffix.org/list/public_suffix_list.dat)
2. Proceed through `idn.pl` script

1 liner: `curl https://publicsuffix.org/list/public_suffix_list.dat | perl idn.pl > effective_tld_names.dat`

## Deps installation

Ensure that you have `cpanm` installed (e.g. by `brew install cpanm`).
Run `cpanm --installdeps .` once.
