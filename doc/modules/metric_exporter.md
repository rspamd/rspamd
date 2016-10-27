---
layout: doc_modules
title: Metric exporter
---

# Metric exporter

Metric exporter collects statistics from Rspamd and feeds them to external monitoring/graphing systems. [Graphite](https://graphiteapp.org/) is the only supported backend for now.

### Configuration

Settings which must be set are shown below. Configuration could be added to `rspamd.conf.local`:

~~~ucl
metric_exporter {
  # Backend: just "graphite" for now
  backend = "graphite";
  # Statefile: Path to file at which to persist last run information
  statefile = "$DBDIR/metric_exporter_last_push";
}
~~~

Additionally, backend-specific settings may be set. Graphite-specific settings are shown below:

~~~ucl
metric_exporter {
  # List of metrics to export - must be set.
  # See next section for list of metrics
  metrics = [
    "ham_count",
    "spam_count",
  ];
  # Hostname for Carbon: "localhost" if unset
  host = "localhost";
  # Port for Carbon: 2003 if unset
  port = 2003;
  # Prefix for metric names: "rspamd" if unset
  metric_prefix = "rspamd";
}
~~~

Metrics which may be exported are as follows:
~~~ 
metrics = [
  "actions.add header",
  "actions.greylist",
  "actions.no action",
  "actions.reject",
  "actions.rewrite subject",
  "actions.soft reject",
  "bytes_allocated",
  "chunks_allocated",
  "chunks_freed",
  "chunks_oversized",
  "connections",
  "control_connections",
  "ham_count",
  "learned",
  "pools_allocated",
  "pools_freed",
  "scanned",
  "shared_chunks_allocated",
  "spam_count"
];
~~~
