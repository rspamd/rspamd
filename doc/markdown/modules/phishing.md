# Phishing module

This module is designed to report about potentially phished URL's.

## Principles of phishing detection

Rspamd tries to detect phished URL's merely in HTML text parts. First,
it get URL from `href` or `src` attribute and then tries to find the text enclosed
within this link tag. If some url is also enclosed in the specific tag then
rspamd decides to compare whether these two URL's are related, namely if they
belong to the same top level domain. Here are examples of urls that are considered
to be non-phished:

    <a href="http://sub.example.com/path">http://example.com/other</a>
    <a href="https://user:password@sub.example.com/path">http://example.com/</a>

And the following URLs are considered as phished:

    <a href="http://evil.co.uk">http://example.co.uk</a>
    <a href="http://t.co/xxx">http://example.com</a>
    <a href="http://redir.to/example.com">http://example.com</a>

## Configuration of phishing module

Here is an example of full module configuration.

~~~ucl
phishing {
	symbol = "R_PHISHING"; # Default symbol

	# Check only domains from this list
	domains = "file:///path/to/map";

	# Make exclusions for known redirectors
	# Entry format: URL/path for map, colon, name of symbol
	redirector_domains = [
		"${CONFDIR}/redirectors.map:REDIRECTOR_FALSE"
	];
	# For certain domains from the specified strict maps
	# use another symbol for phishing plugin
	strict_domains = [
		"${CONFDIR}/paypal.map:PAYPAL_PHISHING"
	];
}
~~~

If an anchoring (actual as opposed to phished) domain is found in a map
referenced by the `redirector_domains` setting then the related symbol is
yielded and the URL is not checked further. This allows making exclusions
for known redirectors, especially ESPs.

Further to this, if the phished domain is found in a map referenced by
`strict_domains` the related symbol is yielded and the URL not checked
further. This allows fine-grained control to avoid false positives and
enforce some really bad phishing mails, such as bank phishing or other
payments system phishing.

Finally, the default symbol is yielded- if `domains` is specified then
only if the phished domain is found in the related map.

## Openphish support

Since version 1.3, there is [openphish](https://openphish.com) support in rspamd.
Now rspamd loads this public feed as a map (using HTTPS) and checks URLs in messages using
openphish list. If any match is found, then rspamd adds symbol `PHISHED_OPENPHISH`.

If you use research or commercial data feed, rspamd can also use its data and gives
more details about URLs found: their sector (e.g. 'Finance'), brand name (e.g.
'Bank of Zimbabwe') and other useful information.

There are couple of options available to configure openphish module:

~~~ucl
phishing {
	# URL of feed, default is public url:
	openphish_map = "https://www.openphish.com/feed.txt";
	# For premium feed, change that to your personal URL, e.g.
	# openphish_map = "https://openphish.com/samples/premium_feed.json";

	# Change this to true if premium feed is enabled
	openphish_premium = false;
}
~~~
