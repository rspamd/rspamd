# Included from top-level .conf file

type = "proxy";

milter = yes; # Enable milter mode
timeout = 120s; # Needed for Milter usually

upstream "local" {
  default = yes;
  hosts = "localhost";
}

count = 1; # Do not spawn too many processes of this type
