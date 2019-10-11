# Proxy worker setup
# Please don't modify this file as your changes might be overwritten with
# the next update.
#
# You can modify 'local.d/worker-proxy.inc' to add and merge
# parameters defined inside this section
#
# You can modify 'override.d/worker-proxy.inc' to strictly override all
# parameters defined inside this section
#
# See https://rspamd.com/doc/faq.html#what-are-the-locald-and-overrided-directories
# for details
# Module documentation: https://rspamd.com/doc/workers/rspamd_proxy.html

milter = yes; # Enable milter mode
timeout = 120s; # Needed for Milter usually

upstream "local" {
  default = yes;
  hosts = "localhost";
}

count = 1; # Do not spawn too many processes of this type
max_retries = 5; # How many times master is queried in case of failure
discard_on_reject = false; # Discard message instead of rejection
quarantine_on_reject = false; # Tell MTA to quarantine rejected messages
spam_header = "X-Spam"; # Use the specific spam header
reject_message = "Spam message rejected"; # Use custom rejection message
