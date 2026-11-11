# Allowed wrapper-domain -> displayed-domain pairs (hash map).
# The same permission as phishing_rewrite_domains.inc, indexed by wrapper.
# Keys and values use lowercase ASCII/punycode domain names.
# Values are separated by whitespace or commas. Exact hosts or registrable
# domains match; a registrable domain also covers its subdomains.
# This grants no permission to reverse the displayed and wrapper domains.
# Example (comment only):
# wrapper-one.net example.com other.org
# No default pairs until specific domain relationships have been reviewed.
