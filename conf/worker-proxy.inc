# Included from top-level .conf file

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
