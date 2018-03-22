FROM debian:stretch

RUN	apt-get update \
	&& apt-get install -y --no-install-recommends gnupg dirmngr curl \
	&& curl -fsSL http://rspamd.com/apt-stable/gpg.key | apt-key add - \
	&& apt-get purge -y --auto-remove curl \
	&& rm -rf /var/lib/apt/lists/*

RUN	echo "deb http://rspamd.com/apt-stable/ stretch main" > /etc/apt/sources.list.d/rspamd.list

RUN	apt-get update \
	&& apt-get install -y rspamd \
	&& rm -rf /var/lib/apt/lists/*

RUN	echo 'type = "console";' > /etc/rspamd/override.d/logging.inc \
	&& echo 'bind_socket = "*:11334";' > /etc/rspamd/override.d/worker-controller.inc \
	&& echo 'pidfile = false;' > /etc/rspamd/override.d/options.inc

VOLUME	[ "/var/lib/rspamd" ]

CMD	[ "/usr/bin/rspamd", "-f", "-u", "_rspamd", "-g", "_rspamd" ]

EXPOSE	11333 11334
