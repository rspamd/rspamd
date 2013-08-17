---
layout: default
title: Rspamd web interface
---

#Rspamd web interface

##Overview.

This is a simple control interface for rspamd spam filtering system.
It provides basic functions for setting metric actions, scores,
viewing statistic and learning.

##Rspamd setup.

It is required to configure dynamic settings to store configured values.
Basically this can be done by providing the following line in options settings:

{% highlight xml %}
<options>
 <dynamic_conf>/var/lib/rspamd/rspamd_dynamic</dynamic_conf>
</options>
{% endhighlight %}

Please note that this path must have write access for rspamd user.

Then webui worker should be configured:

{% highlight xml %}
<worker>
  <type>webui</type>
  <bind_socket>localhost:11336</bind_socket>
  <password>q1</password>
</worker>
{% endhighlight %}

Basically, this worker should be accessed by some proxying HTTP server
like nginx or apache, since HTTP part of rspamd is quite poor to interact
with real world.

Password option should be changed for sure for your specific configuration.

##Proxy and HTTP server setup.

HTTP server is required for displaying static rspamd-interface files and for
proxying ajax requests. So it is possible to use any widely-spread HTTP
server, like `nginx` or `apache` with `mod_proxy` support.

Proxying should be setup to send HTTP requests to the URL called `/rspamd`
to the webui interface (via local interface or via local network).

Here is a sample setup for nginx:

{% highlight nginx %}
server {
	listen 10.0.0.1;
	server_name example.com;
	root /home/rspamdui/rspamd-interface;
	index index.html;

	location /rspamd/ {
		proxy_pass http://10.0.0.2:11336/;
	}
}
{% endhighlight %}


##Interface setup.

Interface itself is written in pure HTML5/js and, hence, it requires zero setup.
Just enter a password for webui access and you are ready.

##Contact information.

Rspamd interface is `GPLv3` licensed software. For all questions rlated to this
product please email to `rspamd-interface <at> highsecure.ru`.
