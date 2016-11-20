---
layout: default
title: Rspamd web interface
---

# Rspamd web interface

## Overview.

This is a simple control interface for Rspamd spam filtering system.
It provides basic functions for setting metric actions, scores,
viewing statistic and learning.

<img src="{{ site.baseurl }}/img/webui.png" class="img-responsive" alt="Webui screenshot">

## Rspamd setup.

Default configuration is expected to work but it's strongly recommended to [change
the default controller password]({{ site.baseurl }}/doc/quickstart.html#setting-the-controller-password)
(whether you plan on using webui or not).

Furthermore, if you intend to expose the webui via a proxy running on the same
machine (or some other machine which has been added to `secure_ip` setting) then
it is important that this is configured correctly, see the [FAQ]({{ site.baseurl }}/doc/faq.html#how-to-use-the-webui-behind-a-proxy-server)
for details & example configurations.

## Interface setup.

Interface itself is written in pure HTML5/js and, hence, it requires zero setup.
Just point your web browser at http://localhost:11334 ; enter a password for webui access and you are ready.
