
FROM debian:latest
MAINTAINER Matt Simerson <matt@tnpi.net>

# if Debian's ancient 0.6.10 is new enough...
#RUN apt-get update && apt-get install -y rspamd

# Instead, get latest release, from the source
COPY rspamd.list /etc/apt/sources.list.d/rspamd.list
RUN apt-get update \
    && apt-get install -y curl \
    && curl -o - http://rspamd.com/apt-stable/gpg.key | apt-key add - \
    && apt-get install -y --force-yes \
       rspamd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# start up rspamd once, as it does some initialization
RUN update-rc.d rspamd defaults && service rspamd start && sleep 30

# Debian 8's rspamd.conf is for systemd, which is not running in container
COPY rspamd.conf /etc/rspamd/rspamd.conf
CMD ["/usr/bin/rspamd","-f", "-u", "_rspamd", "-g", "_rspamd"]

EXPOSE 11333 11334
