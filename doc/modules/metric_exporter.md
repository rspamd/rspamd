---
layout: doc_modules
title: Metric exporter
---

# Metric exporter

Metric exporter collects statistics from Rspamd and feeds them to external monitoring/graphing systems. [Graphite](https://graphiteapp.org/) is the only supported backend for now.

### Configuration

Non-backend-specific settings are shown below. Configuration could be added to `rspamd.conf.local`:

~~~ucl
metric_exporter {
  # Backend: just "graphite" for now - MUST be set
  backend = "graphite";
  # List of metrics to export - MUST be set.
  # See next section for list of metrics
  metrics = [
    "ham_count",
    "spam_count",
  ];
  # Below settings are optional and values shown will be used as defaults if these are unset:
  # Statefile: Path to file at which to persist last run information
  statefile = "$DBDIR/metric_exporter_last_push";
  # Timeout in seconds for pushing stats to backend
  timeout = 15;
  # Interval in seconds at which stats should be pushed
  interval = 120;
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

Additionally, backend-specific settings may be set. Graphite-specific settings are shown below:

~~~ucl
metric_exporter {
  # Hostname for Carbon: "localhost" if unset
  host = "localhost";
  # Port for Carbon: 2003 if unset
  port = 2003;
  # Prefix for metric names: "rspamd" if unset
  metric_prefix = "rspamd";
}
~~~

