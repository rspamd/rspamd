---
layout: default
title: Compare Rspamd with other spam filters
---

<div class="compare-table">
  <div class="table-responsive">
    <table class="table">
      <thead>
        <tr>
          <th class="col-xs-3"></th>
          <th class="col-xs-3"><img src="img/rspamd_logo_small_black_simple.jpg" class="img-responsive"></th>
          <th class="col-xs-3"><img src="img/spamassassin_logo.jpg" class="img-responsive"></th>
          <th class="col-xs-3"><img src="img/dspam_logo.jpg" class="img-responsive"></th>
        </tr>
      </thead>
      <tbody>
        <tr class="info">
          <th colspan="4">
            General
          </th>
        </tr>
        <tr>
          <td>Written in</td>
          <td>C</td>
          <td>Perl</td>
          <td>C</td>
        </tr>
        <tr>
          <td>Process model</td>
          <td>event driven</td>
          <td>pre-forked pool</td>
          <td>LDA and pre-forked</td>
        </tr>
        <tr>
          <td>MTA integration</td>
          <td>milter, LDA, custom</td>
          <td>milter, custom (Amavis)</td>
          <td>LDA</td>
        </tr>
        <tr>
          <td>Web interface</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> embedded</td>
          <td><span class="fa fa-lg fa-question-circle"></span> 3rd party</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Languages support</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> full, UTF-8 conversion, lemmatization</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span> naïve (ASCII lowercase)</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span> naïve</td>
        </tr>
        <tr>
          <td>Scripting support</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> Lua API</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> Perl plugins</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Licence</td>
          <td>Apache 2</td>
          <td>Apache 2</td>
          <td>GPL</td>
        </tr>
        <tr>
          <td>Development status</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> very active</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> active</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span> abandoned</td>
        </tr>
        <tr class="info">
          <th colspan="4">
            Mail filtering features
          </th>
        </tr>
        <tr>
          <td>Greylisting</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Ratelimit</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Replies whitelisting</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Rules composition</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr class="info">
          <th colspan="4">
            Filtering methods
          </th>
        </tr>
        <tr>
          <td>Regular expressions filtering</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>DKIM</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>SPF</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>DMARC</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> with reports support</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Policies white and blacklists</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>DNS lists</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>URL DNS lists</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Phishing checks</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> advanced with external resources</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> very basic</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Custom lists</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> with dynamic reload</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Pyzor/Razor</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Own fuzzy storage</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>DCC</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>HTML rules</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> own parser</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> many regexp rules</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>PDF filtering</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr class="info">
          <th colspan="4">
            Statistical methods
          </th>
        </tr>
        <tr>
          <td>Bayes classifier</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> hidden Markov</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> naïve</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> hidden Markov</td>
        </tr>
        <tr>
          <td>Bayes autolearn</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> with custom Lua rules</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> by threshold</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Bayes window</td>
          <td>5 words</td>
          <td>1 word</td>
          <td>2 words (5 words in SBPH/OSB mode)</td>
        </tr>
        <tr>
          <td>Plain files backend</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
        </tr>
        <tr>
          <td>SQLite3 backend</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
        </tr>
        <tr>
          <td>MySQL backend</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
        </tr>
        <tr>
          <td>Redis backend</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr>
          <td>Neural networks support</td>
          <td><span class="glyphicon glyphicon-ok icon-green"></span> via libfann</td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
          <td><span class="glyphicon glyphicon-remove icon-red"></span></td>
        </tr>
        <tr class="info">
          <th colspan="4">&nbsp;
          </th>
        </tr>
      </tbody>
      <thead>
        <tr>
          <th></th>
          <th><img src="img/rspamd_logo_small_black_simple.jpg" class="img-responsive"></th>
          <th><img src="img/spamassassin_logo.jpg" class="img-responsive"></th>
          <th><img src="img/dspam_logo.jpg" class="img-responsive"></th>
        </tr>
      </thead>
    </table>
  </div>
</div>
