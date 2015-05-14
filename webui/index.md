---
layout: default
title: Rspamd web interface
---

#Rspamd web interface

##Overview.

This is a simple control interface for rspamd spam filtering system.
It provides basic functions for setting metric actions, scores,
viewing statistic and learning.

<img src="/img/webui.png" class="img-responsive" alt="Webui screenshot"> 

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

Password option should be changed for sure for your specific configuration. Encrypted password using is encouraged (`rspamd --encrypt-password`).

##Interface setup.

Interface itself is written in pure HTML5/js and, hence, it requires zero setup.
Just enter a password for webui access and you are ready.


##Contact information.

Rspamd interface is `Apache-2.0` licensed software. For all questions rlated to this
product please email to `rspamd-interface <at> highsecure.ru`.
