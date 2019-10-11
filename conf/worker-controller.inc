# Controller worker setup
# Please don't modify this file as your changes might be overwritten with
# the next update.
#
# You can modify 'local.d/worker-controller.inc' to add and merge
# parameters defined inside this section
#
# You can modify 'override.d/worker-controller.inc' to strictly override all
# parameters defined inside this section
#
# See https://rspamd.com/doc/faq.html#what-are-the-locald-and-overrided-directories
# for details
# Module documentation: https://rspamd.com/doc/workers/controller.html

count = 1;
password = "q1";
secure_ip = "127.0.0.1";
secure_ip = "::1";
static_dir = "${WWWDIR}";
