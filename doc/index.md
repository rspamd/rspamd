---
layout: doc_main
title: Rspamd Documentation
---
## Instalation and Administation

Here are the main introduction documents that are recommended for reading if you are going to use Rspamd in your mail system.

* **[Quick start](quickstart.html)** - learn how to install, setup and perform initial configuring of Rspamd
* **[MTA integration](integration.html)** document describes how to integrate Rspamd into your mail infrastructure
* **[Upgrading](migration.html)** - the list of incompatible changes between versions of Rspamd
* **[Frequently asked questions](faq.html)** - common questions about Rspamd and Rmilter
* **[Migrating from SA](./tutorials/migrate_sa.html)** - the guide for those who wants to migrate an existing SpamAssassin system to Rspamd

## Reference guide

This section contains documents about various configuration details.

* **[General information](./configuration/index.html)** explains basic principles of Rspamd configuration
* **[Modules documentation](./modules/)** gives a detailed description of each Rspamd module
* **[Workers documentation](./workers/)** contains information about different Rspamd worker processes: scanners, controller, fuzzy storage and so on
* **[Users settings description](./configuration/settings.html)** could be useful if you need to setup per-user configuration or want process mail in different ways, for example, for inbound and outbound messages.

## Developers documentation

This section contains details about Rspamd internals, documents about writing new rules for Rspamd and, in particular, Rspamd Lua API.

* **[General information](./architecture/index.html)** provides an overview of the Rspamd architecture
* **[Protocol documentation](./architecture/protocol.html)** describes Rspamd protocol which is used to communicate with external tools, such as Rmilter or `rspamc` client utility
* **[Writing Rspamd rules](./tutorials/writing_rules.html)** is a step-by-step guide that describes how to write rules for Rspamd
* **[Lua API reference](./lua/)** provides the extensive information about all Lua modules available in Rspamd
* **[Creating your fuzzy storage](http://rspamd.com/doc/fuzzy_storage.html)** document provides information about how to make your own hashes storage and how to learn it efficiently

## External resources

* [Training Rspamd with Dovecot antispam plugin, part 1](https://kaworu.ch/blog/2014/03/25/dovecot-antispam-with-rspamd/) - this tutorial describes how to train Rspamd automatically using the `antispam` plugin of the `Dovecot` IMAP server
* [Training Rspamd with Dovecot antispam plugin, part 2](https://kaworu.ch/blog/2015/10/12/dovecot-antispam-with-rspamd-part2/) - continuation of the previous tutorial
