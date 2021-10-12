ARG DEBIAN_RELEASE=bullseye
FROM debian:${DEBIAN_RELEASE}-slim
ARG DEBIAN_RELEASE=bullseye
ENV DEBIAN_RELEASE=$DEBIAN_RELEASE

RUN	apt-get update && apt-get install -y --no-install-recommends \
		ca-certificates \
		dirmngr \
		gnupg \
	&& rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-c"]
RUN	set -x \
# gpg: key FFA232EDBF21E25E: public key "Rspamd Nightly Builds (Rspamd Nightly Builds) <vsevolod@highsecure.ru>" imported
	&& key='3FA347D5E599BE4595CA2576FFA232EDBF21E25E' \
	&& export GNUPGHOME="$(mktemp -d)" \
	&& gpg --import <<<$'\
-----BEGIN PGP PUBLIC KEY BLOCK-----                                    \n\
                                                                        \n\
mQINBFW3VB8BEADAV1lBy8DPcSEBSLYVKgwsBx/dRmgenKeliMpiZyNYJJmF6tSV        \n\
s3v5DtDIUESgI2mBKNeptdneri3CDJScI/LgPLKqemrLBkAMfe+f57JgppY5ti4H        \n\
xo+VZdbF9bhCAwYwJnqnyuLjYSUu6nCuW4uPDoqBHXynwsIWr1O3fREpY+vgIgaT        \n\
Oqm3ncssqxSicymd6k0yuo55xuUvrc4Yu4IEnhFVRU53e0E3zmHg/7ONI99YtBan        \n\
7G/w2IfA1bfRDYZ2Avau+JqGcEl8vy+eLmYayKirdsMPN8Tx6RFOstDf1CnjW/bj        \n\
IX7SDOklIGJjJwcWW/iY+1P9SfNNqSDgXavJj2wmLMlUhgjyJFTXfdDRjmN0PFxo        \n\
f6OQu5xok1WHfKFJL+hLGknjHdXLmGd5MSuFlutdVHJQrieknjBea9xCiEsrfe8V        \n\
zyNqGhzgIYjOi/bO7jGpY/WiFHvM9XtBVp862tqM1S1WbAWW5u+es6NK4q9Cv0DR        \n\
tIalss+5gFhdsIFGFYQWfY7CrjOIC+C0+c5IGaBkHte35hCCvDpOO909xxVqUZYe        \n\
9Pl8zYgPDe1H4arMO+p6rSvVntvIWOqLqkuWYSiOY4TGADJTkeZRbopZhvqs/9mc        \n\
847fVMbOwKfkbeuGiHhUK0QFewXSu+cXJyGtyu3RgokBWr2yyzJFXIvJbQARAQAB        \n\
tEZSc3BhbWQgTmlnaHRseSBCdWlsZHMgKFJzcGFtZCBOaWdodGx5IEJ1aWxkcykg        \n\
PHZzZXZvbG9kQGhpZ2hzZWN1cmUucnU+iQI4BBMBAgAiBQJVt1QfAhsDBgsJCAcD        \n\
AgYVCAIJCgsEFgIDAQIeAQIXgAAKCRD/ojLtvyHiXucND/4ja0t+4RMiD0c0z3xD        \n\
Vp0Ysq7kZvzlteUrw98f1BMYbmSTJ+43JVZV67GJ8fV2d9/atIlyLce8Gn9hYmF7        \n\
C5nPpCCOlNejkwkc9MhZgoM0z7sTNZwKLZ4fSnxHD10Z923G+IRQYeXswM7hE/T5        \n\
8NgANOWBFs9BxIEIT6IfRNHF23SCmCeNFNmUen6uXLznjRzYbMmwP7u2BopfJcpN        \n\
ajnm66IypQDsUqVwBRnm9o9GAWUPbp4ahhf1vYu04T1vD7n4qhrLdhHmEJpukEhD        \n\
q613Wl/k0g0O8SahfSAaM1x5zLOJ0sMacyxCktQKXypAhkhhJc4J1KLbnNUsxZdk        \n\
Gn4wLZuhfIuzh2KfKBdwoL3zRq7kjgumJo7AQhEIIDGKutl6sZnbRHjBr4qBb1NJ        \n\
/7GC7UiZhIesdO6HdqrriNF0l8dRVIaHXGKF0PQWWG+J+147oQM+SJmm4W4oONSx        \n\
YCjyTllxwh/54fhu81jhSyBgbKAmV1gYLIPvAUgPkguAb5JWcvZOeXytHWZYLK9T        \n\
8rW5R0bviiouHHRyQYu0AX+wiSyAfoVnTVyad6xTWUT3aQ8jeL0I3uy323Mrq56U        \n\
7Yo0NFwKPF9z5kbuQje3daudQQymkhOfNcQm3dOaaWKGp5KPRi3OtKYMu+5Aphor        \n\
lwJWDec6PUe835YwqrARXtPaNA==                                            \n\
=4Cm3                                                                   \n\
-----END PGP PUBLIC KEY BLOCK-----' \
	&& gpg --keyserver hkps://keys.openpgp.org --recv-keys "$key" \
	&& gpg --export "$key" > /etc/apt/trusted.gpg.d/rspamd.gpg \
	&& rm -rf "$GNUPGHOME" \
	&& apt-key list > /dev/null

RUN	echo "deb [signed-by=/etc/apt/trusted.gpg.d/rspamd.gpg] https://rspamd.com/apt-stable/ $DEBIAN_RELEASE main" > /etc/apt/sources.list.d/rspamd.list

RUN	apt-get update \
	&& apt-get install -y rspamd \
	&& rm -rf /var/lib/apt/lists/*

RUN	echo 'type = "console";' > /etc/rspamd/override.d/logging.inc \
	&& echo 'bind_socket = "*:11334";' > /etc/rspamd/override.d/worker-controller.inc \
	&& echo 'pidfile = false;' > /etc/rspamd/override.d/options.inc

VOLUME	[ "/var/lib/rspamd" ]

CMD	[ "/usr/bin/rspamd", "-f", "-u", "_rspamd", "-g", "_rspamd" ]

EXPOSE	11333 11334
