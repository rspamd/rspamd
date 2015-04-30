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

Unfortunately, rspamd can generate false positives for different redirectors or
URL shorteners. In future rspamd releases, this issue is going to be fixed.

## Configuration of phishing module

Here is an example of full module configuraition.

~~~nginx
phishing {
	symbol = "R_PHISHING"; # Default symbol
	
	# Check only domains from this list
	domains = "file:///path/to/map";
	
	# For certain domains from the specified strict maps
	# use another symbol for phishing plugin
	strict_domains = [
		"PAYPAL_PHISHING:${CONFDIR}/paypal.map",
		"REDIRECTOR_FALSE:${CONFDIR}/redirectors.map"
	];
}
~~~

If `domains` is unspecified then rspamd checks all domains for phishing. `strict_domains`
allows fine-grained control to avoid false positives and enforce some really bad phishing
mails, such as bank phishing or other payments system phishing.