# Allowed displayed-domain -> wrapper-domain pairs (hash map).
# Keys and values use lowercase ASCII/punycode domain names.
# Values are separated by whitespace or commas. Exact hosts or registrable
# domains match; a registrable domain also covers its subdomains.
# This grants no permission to reverse the displayed and wrapper domains.
# Example (comment only):
# example.com wrapper-one.net wrapper-two.org
# No default pairs until specific domain relationships have been reviewed.
