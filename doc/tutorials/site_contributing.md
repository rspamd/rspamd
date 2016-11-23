---
layout: doc
title: Contributing to rspamd.com web-site
---
# Contributing to rspamd.com web-site

## Local links

At build time Markdown sources are being converted into HTML pages and their file names are being changed (`*.md` → `*.html`). You should replace `.md` file extension with `.html` when you are creating local links.

To keep web-site portable please use `site.url` and `site.baseurl` variables when creating local links. Absolute local links should start with {{ "{{" }}&nbsp;site.url&nbsp;}}{{ "{{" }}&nbsp;site.baseurl&nbsp;}} and root-relative ones with {{ "{{" }}&nbsp;site.baseurl&nbsp;}}:

<div class="table-responsive">
  <table class="table">
    <thead>
      <tr class="info">
        <th>correct</th>
        <th>incorrect</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>[link]({{ "{{ site.url " }}}}{{ "{{ site.baseurl " }}}}/dir/doc.html)</code></td>
        <td><code>[link](https://rspamd.com/dir/doc.html)</code></td>
      </tr>
      <tr>
        <td><code>[link]({{ "{{ site.baseurl " }}}}/dir/doc.html)</code></td>
        <td><code>[link](/dir/doc.html)</code></td>
      </tr>
    </tbody>
  </table>
</div>

## Testing changes

It is always a good idea to check how exactly your changes will break the web-site (formatting, links, highlighting, etc.) before sending a pull request. Fortunately it could be easily done with GitHub Pages.

To publish web-site from your forked repository as `<username>.github.io/rspamd.com` you should create a `gh-pages` branch and [set it as a publishing source](https://help.github.com/articles/configuring-a-publishing-source-for-github-pages/#enabling-github-pages-to-publish-your-site-from-master-or-gh-pages).
