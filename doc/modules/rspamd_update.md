---
layout: doc_modules
title: Rspamd updates module
---
# Rspamd update module

This module allows to load rspamd rules, adjust symbols scores and actions without full daemon restart.
`rspamd_update` provides method to backport new rules and scores changing without updating rspamd itself. This might be useful, for example, if you want to use the stable version of rspamd but would like to improve filtering quality at the same time.

## Security considerations

Rspamd update module can execute lua code which is executed with scanner's privilleges - usually `_rspamd` or `nobody` user. Therefore, you should not use untrusted sources of updates.
Rspamd supports digital signatures to check the validity of updates downloaded using [EdDSA](http://ed25519.cr.yp.to/) signatures scheme.
For your own updates that are loaded from the filesystem or from some trusted network you might use unsigned files, however, signing is recommended even in this case.

To sign a map you can use `rspamadm signtool` and to generate signing keypair - `rspamadm keypair -s -u`:

~~~ucl
keypair {
   pubkey = "zo4sejrs9e5idqjp8rn6r3ow3x38o8hi5pyngnz6ktdzgmamy48y";
   privkey = "pwq38sby3yi68xyeeuup788z6suqk3fugrbrxieri637bypqejnqbipt1ec9tsm8h14qerhj1bju91xyxamz5yrcrq7in8qpsozywxy";
   id = "bs4zx9tcf1cs5ed5mt4ox8za54984frudpzzny3jwdp8mkt3feh7nz795erfhij16b66piupje4wooa5dmpdzxeh5mi68u688ixu3yd";
   encoding = "base32";
   algorithm = "curve25519";
   type = "sign";
}
~~~

Then you can use `signtool` to edit map's file:

```
rspamadm signtool -e --editor=vim -k <keypair_file> <map_file>
```

To enforce signing policies you should add `sign+` string to your map definition:

~~~ucl
map = "sign+http://example.com/map"
~~~

To specify trusted key you could either put **public** key from the keypair to `local.d/options.inc` file as following:

```
trusted_keys = ["<public key string>"];
```

or add it as `key` definition to the map string:

~~~ucl
map = "sign+key=<key_string>+http://example.com/map"
~~~

## Module configuration

The module itself has very few parameters:

* `key`: use this key (base32 encoded) as trusted key

All other keys are threated as rules to load maps. By default, rspamd tries to load signed updates from `rspamd.com` site using trusted key `qxuogdh5eghytji1utkkte1dn3n81c3y5twe61uzoddzwqzuxxyb`:

~~~ucl
rspamd_update {
    rules = "sign+http://rspamd.com/update/rspamd-${BRANCH_VERSION}.ucl";
    key = "qxuogdh5eghytji1utkkte1dn3n81c3y5twe61uzoddzwqzuxxyb";
}
~~~

## Updates structure

Update files are quite simple: they have 3 sections:

* `symbols` - list of new scores for symbols that are already in rspamd (loaded with `priority = 1` to override default settings)
* `actions` - list of scores for actions (also loaded with `priority = 1`)
* `rules` - list of lua code fragments to load into rspamd, they can use `rspamd_config` global to register new rules

Here is an example of update file:

~~~ucl
rules = {
	test =<<EOD
rspamd_config.TEST = {
	callback = function(task) return true end,
	score = 1.0,
	description = 'test',
}
EOD
}
actions = {
	greylist = 3.4,
}
symbols = {
	R_DKIM_ALLOW = -0.5,
}
~~~
