# Whitelist module

Whitelist module is intended to negate scores for some messages that are known to
be from the trusted sources. Due to `SMTP` protocol design flaws, it is quite easy to
forge sender. Therefore, rspamd tries to validate sender based on the following additional
properties:

- `DKIM`: a message has a valid DKIM signature for this domain
- `SPF`: a message matches SPF record for the domain
- `DMARC`: a message also satisfies domain's DMARC policy (usually implies SPF and DMARC)

## Whitelist setup

Whitelist configuration is quite straightforward. You can define a set of rules within
`rules` section. Each rule **must** have `domains` attribute that specifies either
map of domains (if specified as a string) or a direct list of domains (if specified as an array).
The following optional parameters are allowed:

- `valid_spf`: require a valid SPF policy
- `valid_dkim`: require DKIM validation
- `valid_dmarc`: require a valid DMARC policy

These options are combined using `AND` operator, therefore `valid_dkim = true` and
`valid_spf = true` would require both DKIM and SPF validation to whitelist domains from
the list.

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

~~~nginx
whitelist {
    rules {
        WHITELIST_SPF = {
            valid_spf = true;
            domains = [
                "github.com",
            ]
            score = -1.0
        }
    
        WHITELIST_DKIM = {
            valid_dkim = true;
            domains = [
                "github.com",
            ]
            score = -2.0
        }
        
        WHITELIST_SPF_DKIM = {
            valid_spf = true;
            valid_dkim = true;
            domains = [
                ["github.com", 2.0],
            ]
            score = -3.0
        }
        
        WHITELIST_DMARC_DKIM = {
            valid_dkim = true;
            valid_dmarc = true;
            domains = [
                "github.com",
            ]
            score = -7.0
        }
    }
}
~~~

Rspamd also comes with a set of pre-defined whitelisted domains that could be useful for start.