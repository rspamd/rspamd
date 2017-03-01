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
	
To ensure your `gh-pages` fork renders properly you should remove the `url` in the `_config.yml` on the `gh-pages` branch:

```diff
$ git diff -U1
diff --git a/_config.yml b/_config.yml
index 583d419..59f5ea8 100644
--- a/_config.yml
+++ b/_config.yml
@@ -6,3 +6,2 @@ paginate_path: "blog/page:num"
 description: Rspamd home.
-url: http://rspamd.com
 keep_files: ["CentOS/6/os/x86_64/"]
```

You only need to do this just once by making a commit into `gh-pages` branch. Then you can merge in changes from `master` or feature branch onto `gh-pages`, so the `url` used on `gh-pages` will stay the way it is.
  
The `url` in the upstream `rspamd.com` repository should never be touched. Make sure your pull requests are not including a change of the `url`.
