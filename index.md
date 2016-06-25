---
layout: default
title: Rspamd spam filtering system
---
<div class="row main-small-text-block">
		<div class="col-xs-12 col-sm-6 col-md-4 main-small-text">
		    <div class="thumbnail">
				    <img src="img/performance.jpg" class="" height="80" width="80">
						<div class="caption">
								<h2><a href="#">Performance <small><i class="fa fa-chevron-right" style="color: #dd4814"></i></small></a></h2>
								<p>Short simple text.Short simple text. Short simple text.
								Short simple text.Short simple text. Short simple text.
								Short simple text.Short simple text. Short simple text.</p>
						</div>
				</div>
		</div>
		<div class="col-xs-12 col-sm-6 col-md-4 main-small-text">
		    <div class="thumbnail">
				    <img src="img/features.jpg" class="" height="80" width="80">
						<div class="caption">
								<h2><a href="#">Features <small><i class="fa fa-chevron-right" style="color: #dd4814"></i></small></a></h2>
								<p>Short simple text.Short simple text. Short simple text.</p>
						</div>
				</div>
		</div>
		<div class="col-xs-12 col-sm-6 col-md-4 main-small-text">
				<div class="thumbnail">
						<img src="img/compare.jpg" class="" height="80" width="80">
						<div class="caption">
								<h2><a href="#">Compare <small><i class="fa fa-chevron-right" style="color: #dd4814"></i></small></a></h2>
								<p>Short simple text.Short simple text. Short simple text.
								Short simple text.Short simple text. Short simple text.</p>
						</div>
				</div>
		</div>
		<div class="col-xs-12 col-sm-6 col-md-4 main-small-text">
				<div class="thumbnail">
						<img src="img/documentation.jpg" class="" height="80" width="80">
						<div class="caption">
								<h2><a href="#">Documentation <small><i class="fa fa-chevron-right" style="color: #dd4814"></i></small></a></h2>
								<p>Short simple text.Short simple text. Short simple text.
								Short simple text.Short simple text. Short simple text.</p>
						</div>
				</div>
		</div>
		<div class="col-xs-12 col-sm-6 col-md-4 main-small-text">
				<div class="thumbnail">
						<img src="img/media.jpg" class="" height="80" width="80">
						<div class="caption">
								<h2><a href="#">Media <small><i class="fa fa-chevron-right" style="color: #dd4814"></i></small></a></h2>
								<p>Short simple text.Short simple text. Short simple text.
								Short simple text.Short simple text. Short simple text.
								Short simple text.Short simple text. Short simple text.</p>
						</div>
				</div>
		</div>
		<div class="col-xs-12 col-sm-6 col-md-4 main-small-text">
				<div class="thumbnail">
						<img src="img/support.jpg" class="" height="80" width="80">
						<div class="caption">
								<h2><a href="#">Donation & Support <small><i class="fa fa-chevron-right" style="color: #dd4814"></i></small></a></h2>
								<p>Short simple text.Short simple text. Short simple text.
								Short simple text.Short simple text. Short simple text.
								Short simple text.Short simple text. Short simple text.</p>
						</div>
				</div>
		</div>
</div>


<!--div class="row myRowEq">
	<div class="col-xs-12 col-sm-4 myMainPageText">
			<div>
					<h2>Performance</h2>
					<p>&bull;&nbsp;Rspamd is a mail filtering tool that is designed to work as fast as possible.</p>
					<p>&bull;&nbsp;It can <strong>save</strong> your hardware resources by applying clever techniques, such as an event based processing model, <a class="undecor" href="https://highsecure.ru/ast-rspamd.pdf">abstract syntax tree</a> constructions, careful algorithm selection and a number of global and local optimisations, such as the use of <a class="undecor" href="https://github.com/01org/hyperscan">hyperscan</a> for <a class="undecor" href="https://highsecure.ru/rspamd-hyperscan.pdf">regular expressions optimisation</a>.</p>
					<p>&bull;&nbsp;Rspamd's core is written completely in C and the most critical parts are written in dedicated assembly for the target hardware platforms.
					</p>
		 </div>
		 <a class="btn btn-primary" href="about.html#performance">View details &raquo;</a>
	</div>
	<div class="col-xs-12 col-sm-4 myMainPageText">
		  <div>
					<h2>Features</h2>
					<p>&bull;&nbsp;Rspamd ships with a wide selection of filters to process messages, such as <a class="undecor" href="/doc/modules/regexp.html">regular expressions</a>, DNS black and white <a class="undecor" href="/doc/modules/rbl.html">lists</a>, <a class="undecor" href="/doc/modules/surbl.html">URL</a> black lists, <a class="undecor" href="/doc/modules/multimap.html">dynamic</a> IP/hosts or DNS lists, <a class="undecor" href="/doc/modules/spf.html">SPF</a> module, <a class="undecor" href="/doc/modules/dkim.html">DKIM</a> plugin and <a class="undecor" href="/doc/modules/dmarc.html">DMARC</a> policy check support.</p>
				    <p>&bull;&nbsp;For advanced filtering rspamd provides an improved statistics module (based on
					   <a class="undecor" href="http://osbf-lua.luaforge.net/papers/osbf-eddc.pdf">an OSB-Bayes algorithm</a>) and a <a class="undecor" href="/doc/modules/fuzzy_check.html">fuzzy hashes</a> database that is generated based on <a class="undecor" href="http://en.wikipedia.org/wiki/Honeypot_%28computing%29">honeypot</a> traffic.</p>
				     <p>&bull;&nbsp;Rspamd also keeps partial compatibility with <a class="undecor" href="http://spamassassin.apache.org">spamassassin</a> rules via <a class="undecor" href="/doc/modules/spamassassin.html">the translation module</a>.</p>
			</div>
		  <a class="btn btn-primary" href="about.html#features">View details &raquo;</a>
	</div>
	<div class="col-xs-12 col-sm-4 myMainPageText">
			<div>
					<h2>Easy to manage</h2>
					<p>&bull;&nbsp;<a href="/rmilter">Rmilter</a> is a powerful tool that provides <a class="undecor" href="http://www.postfix.org">postfix</a> <a class="undecor" href="/doc/integration.html">integration</a> as well as many other features, such as greylisting, rate limits and <a class="undecor" href="http://www.clamav.org">clamav</a> checks.</p>
					<p>&bull;&nbsp;There is also a nice <a href="/webui/">web interface</a> shipped in the rspamd distribution that simplifies the most common operations and displays statistics.</p>
					<p>&bull;&nbsp;Moreover, it is possible to <a class="undecor" href="/doc/tutorials/writing_rules.html">write your own rules and plugins</a> for rspamd using the marvelous and simple <a class="undecor" href="http://www.lua.org">Lua</a> language.</p>
      </div>
			<a class="btn btn-primary" href="about.html#extensions">View details &raquo;</a>
	</div>
</div-->

{% for post in site.posts limit:3 %}
<div class="row">
	<div class="well col-xs-12">
  <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
  <p class="author">
    <span class="date"><small>{{ post.date }}</small></span>
  </p>
<div class="short-news content" markdown="1">
{{ post.content }}
</div>
</div>
</div>
{% endfor %}
