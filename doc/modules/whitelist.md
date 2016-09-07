---
layout: doc_modules
title: Whitelist module
---
# Whitelist module

Whitelist module is intended to negate or increase scores for some messages that are known to
be from the trusted sources. Due to `SMTP` protocol design flaws, it is quite easy to
forge sender. Therefore, rspamd tries to validate sender based on the following additional
properties:

- `DKIM`: a message has a valid DKIM signature for this domain
- `SPF`: a message matches SPF record for the domain
- `DMARC`: a message satisfies domain's DMARC policy (implies SPF or DKIM)

## Whitelist setup

Whitelist configuration is quite straightforward. You can define a set of rules within
`rules` section. Each rule **must** have `domains` attribute that specifies either
map of domains (if specified as a string) or a direct list of domains (if specified as an array).

### Whitelist constraints

The following constraints are allowed:

- `valid_spf`: require a valid SPF policy
- `valid_dkim`: require DKIM validation
- `valid_dmarc`: require a valid DMARC policy

### Whitelist rules modes

Each whitelist rule can work in 3 modes:

- `whitelist` (default): add symbol when a domain has been found and one of constraints defined is satisfied (e.g. `valid_dmarc`)
- `blacklist`: add symbol when a domain has been found and one of constraints defined is *NOT* satisfied (e.g. `valid_dmarc`)
- `strict`: add symbol with negative (ham) score when a domain has been found and one of constraints defined is satisfied (e.g. `valid_dmarc`) and add symbol with **POSITIVE** (spam) score when some of constraints defined has failed

If you do not define any constraints, then all both `strict` and `whitelist` rules just insert result for all mail from the specified domains. For `blacklist` rules the result has normally positive score.

These options are combined using `AND` operator for `whitelist` and using `OR` for `blacklist` and `strict` rules. Therefore, if `valid_dkim = true` and
`valid_spf = true` would require both DKIM and SPF validation to whitelist domains from
the list. On the contrary, for blacklist and strict rules any violation would cause positive score symbol being inserted.

### Optional settings

You can also set the default metric settings using the ordinary attributes, such as:

- `score`: default score
- `group`: default group (`whitelist` group is used if not specified explicitly)
- `one_shot`: default one shot mode
- `description`: default description

Within lists, you can also use optional `multiplier` argument that defines additional
multiplier for the score added by this module. For example, let's define twice bigger
score for `github.com`:

    ["github.com", 2.0]

or if using map:

    github.com 2.0

## Configuration example

~~~ucl
whitelist {
    rules {
        WHITELIST_SPF = {
            valid_spf = true;
            domains = [
                "github.com",
            ];
            score = -1.0;
        }

        WHITELIST_DKIM = {
            valid_dkim = true;
            domains = [
                "github.com",
            ];
            score = -2.0;
        }

        WHITELIST_SPF_DKIM = {
            valid_spf = true;
            valid_dkim = true;
            domains = [
                ["github.com", 2.0],
            ];
            score = -3.0;
        }

        STRICT_SPF_DKIM = {
            valid_spf = true;
            valid_dkim = true;
            strict = true;
            domains = [
                ["paypal.com", 2.0],
            ];
            score = -3.0; # For strict rules negative score should be defined
        }

        BLACKLIST_DKIM = {
            valid_spf = true;
            valid_dkim = true;
            blacklist = true;
            domains = "/some/file/blacklist_dkim.map";
            score = 3.0; # Mention positive score here
        }

        WHITELIST_DMARC_DKIM = {
            valid_dkim = true;
            valid_dmarc = true;
            domains = [
                "github.com",
            ];
            score = -7.0;
        }
    }
}
~~~

Rspamd also comes with a set of pre-defined whitelisted domains that could be useful for start.
