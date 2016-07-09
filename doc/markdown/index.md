# Rspamd documentation

## Tutorials and introduction documents

Here are the main introduction documents that are recommended for reading if you are going to use Rspamd in your mail system.

* **[Quick Start](quick_start.md)** - learn how to install, setup and perform initial configuring of Rspamd
* **[Upgrading](migration.md)** - the list of incompatible changes between versions of Rspamd
* **[Frequently asked questions](faq.md)** - common questions about Rspamd and Rmilter
* **[Migrating from SA](migrate_sa.md)** - the guide for those who wants to migrate an existing SpamAssassin system to Rspamd
* **[MTA integration](integration.md)** document describes how to integrate Rspamd into your mail infrastructure
* **[Creating your fuzzy storage](http://rspamd.com/doc/fuzzy_storage.html)** document provides information about how to make your own hashes storage and how to learn it efficiently

### Rspamd and Dovecot Antispam integration

* [Training Rspamd with Dovecot antispam plugin, part 1](https://kaworu.ch/blog/2014/03/25/dovecot-antispam-with-rspamd/) - this tutorial describes how to train Rspamd automatically using the `antispam` plugin of the `Dovecot` IMAP server
* [Training Rspamd with Dovecot antispam plugin, part 2](https://kaworu.ch/blog/2015/10/12/dovecot-antispam-with-rspamd-part2/) - continuation of the previous tutorial

## Configuration

This section contains documents about various configuration details.

* **[General information](./configuration/index.md)** explains basic principles of Rspamd configuration
* **[Modules documentation](./modules/)** gives a detailed description of each Rspamd module
* **[Workers documentation](./workers/)** contains information about different Rspamd worker processes: scanners, controller, fuzzy storage and so on
* **[Users settings description](./configuration/settings.md)** could be useful if you need to setup per-user configuration or want process mail in different ways, for example, for inbound and outbound messages.

## Architecture

These documents are useful if you need to know details about Rspamd internals.

* **[General information](./architecture/index.md)** provides an overview of the Rspamd architecture
* **[Protocol documentation](./architecture/protocol.md)** describes Rspamd protocol which is used to communicate with external tools, such as Rmilter or `rspamc` client utility


## Extending Rspamd

This section contains documents about writing new rules for Rspamd and, in particular, Rspamd Lua API.

* **[Writing Rspamd rules](./tutorials/writing_rules.md)** is a step-by-step guide that describes how to write rules for Rspamd
* **[Lua API reference](./lua/)** provides the extensive information about all Lua modules available in Rspamd
