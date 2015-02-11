# RBL module

The RBL module provides support for checking the IPv4/IPv6 source address of a message's sender against a set of RBLs as well as various less conventional methods of using RBLs: against addresses in Received headers; against the reverse DNS name of the sender and against the parameter used for HELO/EHLO at SMTP time.

Configuration is structured as follows:

~~~nginx
rbl {
  # default settings defined here
  rbls {
  # 'rbls' subsection under which the RBL definitions are nested
    an_rbl {
       # rbl-specific subsection 
    }
    # ...
  }
}
~~~

The default settings define the ways in which the RBLs are used unless overridden in an RBL-specific subsection.

Defaults may be set for the following parameters (default values used if these are not set are shown in brackets - note that these may be redefined in the default config):

- default_ipv4 (true)

Use this RBL to test IPv4 addresses.

- default_ipv6 (false)

Use this RBL to test IPv6 addresses.

- default_received (true)

Use this RBL to test IPv4/IPv6 addresses found in Received headers. The RBL should also be configured to check one/both of IPv4/IPv6 addresses.

- default_from (false)

Use this RBL to test IPv4/IPv6 addresses of message senders. The RBL should also be configured to check one/both of IPv4/IPv6 addresses.

- default_rdns (false)

Use this RBL to test reverse DNS names of message senders (hostnames passed to rspamd should have been validated with a forward lookup, particularly if this is to be used to provide whitelisting).

- default_helo (false)

Use this RBL to test parameters sent for HELO/EHLO at SMTP time.

- default_unknown (false)

If set to false, do not yield a result unless the response received from the RBL is defined in its related returncodes {} subsection, else return the default symbol for the RBL.

- deault_user (true)

If set to false, do not use this RBL if the message sender is authenticated.

RBL-specific subsection is structured as follows:

~~~nginx
# Descriptive name of RBL or symbol if symbol is not defined.
an_rbl {
        # Explicitly defined symbol
	symbol = "SOME_SYMBOL";
        # RBL-specific defaults (where different from global defaults)
        #The global defaults may be overridden using 'helo' to override 'default_helo' and so on.
        ipv6 = true;
	ipv4 = false;
	# Address used for RBL-testing
	rbl = "v6bl.example.net";
	# Possible responses from RBL and symbols to yield
	returncodes {
		# Name_of_symbol = "address";
		EXAMPLE_ONE = "127.0.0.1";
		EXAMPLE_TWO = "127.0.0.2";
       }
}
~~~

