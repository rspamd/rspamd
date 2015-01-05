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

{% highlight nginx %}
options {
 dynamic_conf = "/var/lib/rspamd/rspamd_dynamic";
}
{% endhighlight %}

Please note that this path must have write access for rspamd user.

Then controller worker should be configured:

{% highlight nginx %}
worker {
	type = "controller";
	bind_socket = "localhost:11334";
	count = 1;
	# Password for normal commands
	password = "q1";
	# Password for privilleged commands
	enable_password = "q2";
	# Path to webiu static files
	static_dir = "${WWWDIR}";
}
{% endhighlight %}

Basically, this worker should be accessed by some proxying HTTP server
like nginx or apache, but rspamd could be used as a standalone HTTP server as well.

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

	proxy_pass http://10.0.0.2:11334/;
}
{% endhighlight %}


##Interface setup.

Interface itself is written in pure HTML5/js and, hence, it requires zero setup.
Just enter a password for webui access and you are ready.

##Contact information.

Rspamd interface is `GPLv3` licensed software. For all questions rlated to this
product please email to `rspamd-interface <at> highsecure.ru`.
