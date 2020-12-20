# <a href="https://rspamd.com"><img src="https://rspamd.com/img/rspamd_logo_black.png" alt="Rspamd" width="220px"/></a>

[![DroneCI](https://ci.rspamd.com/api/badges/rspamd/rspamd/status.svg)](https://ci.rspamd.com/rspamd/rspamd)


## Introduction

[Rspamd](https://rspamd.com) is an advanced spam filtering system and email processing framework that allows evaluation of messages by a number of
rules including regular expressions, statistical analysis and custom services
such as URL black lists. Each message is analysed by Rspamd and given a verdict that might be used by MTA for further processing (e.g. to reject a message, or add a special header indicating spam) along with other information, such as possible DKIM signature or modifications suggested for a message.

Rspamd can act as a [Milter](https://en.wikipedia.org/wiki/Milter) allowing direct interaction with popular MTA systems, such as Postfix or Sendmail.

Rspamd is designed to process hundreds of messages per second simultaneously, and provides a number of
useful features including a comprehensive [Lua API](https://rspamd.com/doc/lua/) that allows access to messages processing in various aspects as well as [asynchronous](https://rspamd.com/doc/lua/sync_async.html) network API to access external resources, such as DNS, HTTP or even generic TCP/UDP services.


## Getting Started

A good starting point to study how to install and configure Rspamd is [the quick start guide](https://rspamd.com/doc/quickstart.html).

Rspamd is [packaged](https://rspamd.com/downloads.html) for the major Linux distributions, and is also available via [FreeBSD ports](https://freshports.org/mail/rspamd), NetBSD [pkgsrc](https://pkgsrc.org) and [OpenBSD ports](http://openports.se/mail/rspamd).

We advice to use packages provided by Rspamd project if available for your OS instead of packages that might be provided by some Linux distributives, as they are usually out of date and does not provide the desired spam filtering quality nor supported by Rspamd project.

## Spam filtering features

Rspamd is shipped with various spam filtering modules and features enabled just out of the box.
The full list of built-in modules could be found in the [Rspamd documentation](https://rspamd.com/doc/modules/).

If that is not enough, Rspamd provides an extensive [Lua API](https://rspamd.com/doc/lua/) to write your own rules and plugins: <https://rspamd.com/doc/tutorials/writing_rules.html>

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on the process for submitting pull requests to us.

## Authors

* **Vsevolod Stakhov** - [vstakhov](https://github.com/vstakhov)

See also the list of [contributors](AUTHORS.md) who participated in this project.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE.md](LICENSE.md) file for details

## References

* Home site: <https://rspamd.com>
* Development: <https://github.com/rspamd/rspamd>
* Site repository: <https://github.com/rspamd/rspamd.com>
