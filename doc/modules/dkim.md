---
layout: doc_modules
title: DKIM module
---
# DKIM module

This module checks [DKIM](http://www.dkim.org/) signatures for emails scanned.
DKIM signatures can establish that this specific message has been signed by a trusted
relay. For example, if a message comes from `gmail.com` then a valid DKIM signature
means that this message was definitely signed by `gmail.com` (unless gmail.com private
key has been compromised, which is not a likewise case).

## Supported features

Rspamd can deal with many types of DKIM signatures and messages canonicalisation.
The major difficulty with DKIM are line endings: many MTA treat them differently which
leads to broken signatures. Basically, rspamd treats all line endings as `CR+LF` that
is compatible with the most of DKIM implementations. From the version 1.3, Rspamd DKIM module also supports signing of messages.

## Configuration

DKIM module has several useful configuration options:

- `dkim_cache_size` (or `expire`) - maximum size of DKIM keys cache
- `whitelist` - a map of domains that should not be checked with DKIM (e.g. if that domains have totally broken DKIM signer)
- `domains` - a map of domains that should have more strict scores for DKIM violation
- `strict_multiplier` - multiply the value of symbols by this value if received from `domains` map
- `trusted_only` - do not check DKIM signatures for all domains but those which are from the `domains` map
- `skip_multi` - skip DKIM check for messages with multiple signatures

The last option can help for some circumstances when rspamd lacks the proper support of
multiple DKIM signatures. Unfortunately, with some mailing lists, or other software
this option could be useful to reduce false positives rate as rspamd deals with
multiple signatures poorly: it just uses the first one to check. On the other hand,
the proper support of multiple DKIM signatures is planned to be implemented in rspamd 
in the next releases, which will make this option meaningless.

## DKIM signatures

Since version 1.3, Rspamd can also add DKIM signatures to messages. This could be used, for example, to sign outbound messages with some key. To use this ability, there is an option called `sign_condition` which defines Lua script that is intended to analyze a task object and return signing params if a signature is desired:

- `key`: path to private key for the domain
- `selector`: DKIM selector value
- `domain`: domain used for signing

If no signature is required, then this function should return `nil` or `false`. Here is an example of `learn_condition` script that is intended to sign messages that come from `example.com` domains:

~~~ucl
# local.d/dkim.conf
sign_condition =<<EOD
return function(task)
  local from = task:get_from('smtp')

  if from and from[1]['addr'] then
    if string.find(from[1]['addr'], '@example.com$') then
      return {
        key = "/etc/dkim/example.com",
        domain = "example.com",
        selector = "test"
      }
    end
  end

  return false
end
EOD;
~~~

Multiple domains signing example:

~~~ucl
sign_condition =<<EOD
return function(task)
  local rspamd_logger = require "rspamd_logger"

  local domains = {
    'example.com',
    'example1.com',
    'example2.com'
  }

  local from = task:get_from('smtp')
  if from and from[1]['addr'] then
    for _,d in ipairs(domains) do
      if string.match(from[1]['addr'], '@(.+)$') == d then

        local ip = task:get_ip()
        if not task:get_user() and not (ip and ip:is_local()) then
          rspamd_logger.infox(task, "skip DKIM signing for unauthorized user from non-local network")
          return false
        end
        -- Keys are searched in `/usr/local/etc/dkim/domain.dkim.key`
        -- You can generate them using the following command:
        -- rspamadm dkim_keygen -s 'dkim' -d 'example.com' -s /usr/local/etc/dkim/example.com.dkim.key
        return {
          key = "/usr/local/etc/dkim/" .. d .. ".dkim.key",
          domain = d,
          selector = "dkim"
        }
      end
    end
  end

  return false
end
EOD;
~~~

Alternatively, you can use maps in this code, for example, to limit signing policy to some network:

~~~ucl
# local.d/dkim.conf
sign_condition =<<EOD
-- Closure
local dkim_ip_map = rspamd_config:add_map({
  url = '/etc/rspamd/dkim_ip.map', 
  type = 'radix', 
  description = 'dkim sign map'
})
-- Callback function
return function(task)
  local ip = task:get_ip()

  if ip and dkim_ip_map and dkim_ip_map:get_key(ip) then
    return {
      key = "/etc/dkim/example.com",
      domain = "example.com",
      selector = "test"
    }
  end
end
EOD;
~~~

You need to ensure that Rspamd can **open** signing keys, so they should be accessible for the user `_rspamd` in the most of the cases.

### Rmilter support

There is also convenience setting since Rmilter 1.10.0 to enable DKIM signing via Rspamd. Your `dkim` section should look like the following one in this case:

~~~ucl
dkim {
  rspamd_sign = yes;
}
~~~

### DKIM keys management

Rspamd always use `relaxed/relaxed` encoding with `rsa-sha256` signature algorithm. This selection seems to be the most appropriate for all cases. Rspamd adds a special element called `DKIM-Signature` to the output when signing has been done. [Rmilter]({{ site.baseurl }}/rmilter/) can use this header out of the box. Other integration methods cannot recognize this header so far.

You can also generate DKIM keys for your domain using `rspamadm dkim_keygen` utility:

~~~
rspamadm dkim_keygen -s 'test' -d example.com

-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
test._domainkey IN TXT ( "v=DKIM1; k=rsa; "
  "p=MIGJAoGBALBrq9K6yxAXHwircsTnDTsd2Kg426z02AnoKTvyYNqwYT5Dxa02lyOiAXloXVIJsyfuGOOoSx543D7DGWw0plgElHXKStXy1TZ7fJfbEtuc5RASIKqOAT1iHGfGB1SZzjt3a3vJBhoStjvLulw4h8NC2jep96/QGuK8G/3b/SJNAgMBAAE=" ) ;
~~~

The first part is DKIM private key (that should be saved to some file) and the second part is DNS record for the public part that you should place in your zone's file. This command can also save both private and public parts to files.
