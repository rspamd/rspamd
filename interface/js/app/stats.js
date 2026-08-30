/*
 * Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>
 */

define(["app/common", "app/libft", "d3pie", "d3"],
    (common, libft, D3Pie, d3) => {
        "use strict";
        // @ ms to date
        function msToTime(seconds) {
            if (!Number.isFinite(seconds)) return "???";
            /* eslint-disable no-bitwise */
            const years = seconds / 31536000 >> 0; // 3600*24*365
            const months = seconds % 31536000 / 2628000 >> 0; // 3600*24*365/12
            const days = seconds % 31536000 % 2628000 / 86400 >> 0; // 24*3600
            const hours = seconds % 31536000 % 2628000 % 86400 / 3600 >> 0;
            const minutes = seconds % 31536000 % 2628000 % 86400 % 3600 / 60 >> 0;
            /* eslint-enable no-bitwise */
            // eslint-disable-next-line no-useless-assignment
            let out = null;
            if (years > 0) {
                if (months > 0) {
                    out = years + "yr " + months + "mth";
                } else {
                    out = years + "yr " + days + "d";
                }
            } else if (months > 0) {
                out = months + "mth " + days + "d";
            } else if (days > 0) {
                out = days + "d " + hours + "hr";
            } else if (hours > 0) {
                out = hours + "hr " + minutes + "min";
            } else {
                out = minutes + "min";
            }
            return out;
        }

        let rowspanHoverHandlersInitialized = false;

        // Parse JSON, returning {} for an empty body or a non-JSON response
        // (jQuery without dataType hands non-JSON bodies to success as raw text;
        // {} yields the same undefined property reads downstream).
        function parseJsonOrEmpty(text) {
            try {
                return text ? JSON.parse(text) : {};
            } catch (err) {
                return {};
            }
        }

        // sessionStorage key holding per-server rate/last-seen baselines
        const STAT_HISTORY_KEY = "StatHistory";
        // The load rate is averaged over a trailing one-minute window of
        // samples (growing to the refresh interval when it is slower), so a
        // short burst does not spike an extrapolated per-interval value.
        // Rate spans outside this range are discarded (too small = double
        // fire, too large = stale). The stale limit must exceed the largest
        // auto-refresh preset (1 hour), otherwise the 30-minute and 1-hour
        // presets discard every sample span
        const RATE_WINDOW_MS = 60 * 1000;
        const MAX_RATE_SAMPLES = 100;
        const MIN_RATE_WINDOW_MS = 1000;
        const STALE_RATE_WINDOW_MS = 2 * 60 * 60 * 1000;

        // Servers whose details row is expanded (module state: survives the
        // periodic tbody re-render, intentionally not a page reload)
        const expandedServers = new Set();
        let clusterToggleHandlerInitialized = false;

        // Monotonic id of the latest stat refresh cycle: a delayed completion
        // of an older cycle (slow health probes, legacy fallback) must not
        // overwrite the state written by a newer one
        let statCycleId = 0;

        // @ ms to latency string
        function formatLatency(ms) {
            if (!Number.isFinite(ms)) return "-";
            if (ms < 1000) return Math.round(ms) + " ms";
            return (ms / 1000).toFixed(2) + " s";
        }

        // @ messages per minute to string (no d3-SI below 10: it would render
        // 0.35 as "350m")
        function formatRate(rate) {
            if (!Number.isFinite(rate)) return "-";
            const f = (rate >= 10) ? d3.format(".3~s") : d3.format(".2f");
            return f(rate) + "/min";
        }

        // @ epoch ms to "5min ago"-style relative time, null when unknown
        function relativeTime(epochMs) {
            if (!Number.isFinite(epochMs)) return null;
            const seconds = Math.max(0, Math.floor((Date.now() - epochMs) / 1000));
            const days = Math.floor(seconds / 86400);
            const hours = Math.floor(seconds % 86400 / 3600);
            const minutes = Math.floor(seconds % 3600 / 60);
            if (days > 0) return days + "\u00a0d " + hours + "\u00a0hr ago";
            if (hours > 0) return hours + "\u00a0hr " + minutes + "\u00a0min ago";
            if (minutes > 0) return minutes + "\u00a0min ago";
            return seconds + "\u00a0s ago";
        }

        // Derive the display state (row class, status glyph, cell values) of
        // one cluster-table row from its Credentials snapshot entry.
        function serverRowState(key, val, statHistory) {
            const state = {
                row_class: "danger",
                glyph_status: "fas fa-times",
                version: "???",
                uptime: "???",
                short_id: "???",
                scan_times: {
                    data: "???",
                    title: ""
                },
                status_title: "",
                status_extra: ""
            };
            if (!val.status) {
                // Down server: show when it was last seen answering. Inline
                // (single row line) on wide screens, wraps under the status
                // glyph on narrow ones — see the cluster-status CSS
                const lastSeen = statHistory[key]?.lastSeen;
                const seenAgo = relativeTime(lastSeen);
                if (seenAgo) {
                    const seenDate = new Date(lastSeen);
                    state.status_extra = '<span class="small text-secondary cluster-last-seen" title="' +
                        common.escapeHTML("Last seen: " + (common.locale
                            ? seenDate.toLocaleString(common.locale)
                            : seenDate.toLocaleString())) +
                        '">seen ' + seenAgo + "</span>";
                }
                return state;
            }

            state.row_class = "success";
            state.glyph_status = "fas fa-check";
            if (val.health?.state === "degraded") {
                state.row_class = "warning";
                state.glyph_status = "fas fa-exclamation-triangle";
                state.status_title = ' title="Degraded: ' +
                    common.escapeHTML(val.health.reason || "unknown reason") + '"';
            }
            if (Number.isFinite(val.data.uptime)) {
                state.uptime = msToTime(val.data.uptime);
            }
            if ("version" in val.data) {
                state.version = val.data.version;
            }
            if (key === "All SERVERS") {
                state.short_id = "";
                state.scan_times.data = "";
            } else {
                if ("config_id" in val.data) {
                    state.short_id = val.data.config_id.substring(0, 8);
                }
                if ("scan_times" in val.data) {
                    const [min, max] = d3.extent(val.data.scan_times);
                    if (max) {
                        const f = d3.format(".3f");
                        state.scan_times = {
                            data: "<small>" + f(min) + "/</small>" +
                                f(d3.mean(val.data.scan_times)) +
                                "<small>/" + f(max) + "</small>",
                            title: ' title="min/avg/max"'
                        };
                    } else {
                        state.scan_times = {
                            data: "-",
                            title: ' title="Have not scanned anything yet"'
                        };
                    }
                }
            }
            return state;
        }

        // Probe a neighbour's /healthy or /ready endpoint. These report real
        // server-side health (lost worker heartbeats, scanner availability) as
        // HTTP 500 with a JSON {"error": reason} body. Always resolves, never
        // logs: a probe failure is data, not an error. Any outcome other than
        // 2xx/500 (endpoint missing on old rspamd, auth or network issues)
        // yields "unknown" so the server renders exactly as before.
        function probeHealth(neighbour, endpoint) {
            return new Promise((resolve) => {
                const xhr = new XMLHttpRequest();
                xhr.open("GET", neighbour.url + endpoint, true);
                xhr.setRequestHeader("Password", common.getPassword());
                const timeout = Math.min(common.getAjaxTimeout() || Infinity, 10000);
                if (timeout > 0) xhr.timeout = timeout;

                xhr.onload = () => {
                    if (xhr.status >= 200 && xhr.status < 300) {
                        resolve({state: "ok"});
                    } else if (xhr.status === 500) {
                        const data = parseJsonOrEmpty(xhr.responseText);
                        resolve({state: "degraded", reason: data.error || xhr.statusText});
                    } else {
                        resolve({state: "unknown"});
                    }
                };
                xhr.onerror = () => resolve({state: "unknown"});
                xhr.ontimeout = () => resolve({state: "unknown"});
                xhr.send();
            });
        }

        // Majority-based cluster drift detection: flag servers whose value
        // differs from the largest group, but only when 2+ servers share a
        // value (a real cluster). All-unique values (centrally managed
        // standalone servers) and majority ties are not flagged. Returns
        // {majorityValue, majorityCount, total, deviants} or null.
        function findDeviants(servers, key) {
            const present = servers.filter(({data}) => key in data);
            const counts = new Map();
            present.forEach(({data}) => counts.set(data[key], (counts.get(data[key]) || 0) + 1));
            if (counts.size < 2) return null;

            let maxCount = 0;
            counts.forEach((count) => {
                if (count > maxCount) maxCount = count;
            });
            // No group of 2+, or a split with no identifiable majority
            if (maxCount < 2 ||
                Array.from(counts.values()).filter((count) => count === maxCount).length > 1) {
                return null;
            }

            let majorityValue = null;
            counts.forEach((count, value) => {
                if (count === maxCount) majorityValue = value;
            });

            return {
                majorityValue,
                majorityCount: maxCount,
                total: present.length,
                deviants: new Set(present.filter(({data}) => data[key] !== majorityValue)
                    .map(({name}) => name))
            };
        }

        // @ messages-per-minute over the trailing window of samples, or null
        // when the span is unusable (single sample, double fire, stale). Pure:
        // does not modify `samples`
        function rateFromSamples(samples) {
            if (samples.length < 2) return null;
            const newest = samples[samples.length - 1];
            const dt = newest.ts - samples[0].ts;
            if (dt < MIN_RATE_WINDOW_MS || dt > STALE_RATE_WINDOW_MS) return null;
            return (newest.scanned - samples[0].scanned) / (dt / 60000);
        }

        // Update per-server rate and last-seen baselines from the fresh /stat
        // snapshot. `history` (sessionStorage["StatHistory"]) is keyed by
        // server name: {lastSeen, samples: [{scanned, ts, uptime}]}. The rate
        // spans a trailing RATE_WINDOW_MS window (like Prometheus rate()),
        // not the refresh interval; with refresh presets slower than the
        // window it degrades to the actual interval between samples. Baselines
        // of down servers are kept so that on recovery the rate is the true
        // average since the last successful poll. Returns the sum of per-server
        // rates (null when no server has one) for the "All SERVERS" row.
        function updateStatHistory(neighbours_status, history) {
            const now = Date.now();
            let rateSum = 0;
            let hasRate = false;

            neighbours_status.forEach((neighbour) => {
                const h = history[neighbour.name] || (history[neighbour.name] = {});
                if (neighbour.status !== true) return;

                h.lastSeen = now;

                // Migrate the pre-window storage ({prev}) to a samples queue
                const samples = Array.isArray(h.samples)
                    ? h.samples
                    : (h.samples = h.prev ? [h.prev] : []);
                if (h.prev) delete h.prev;

                const {scanned, uptime} = neighbour.data;
                const last = samples[samples.length - 1];
                // statreset or restart invalidates the scanned history
                if (last && Number.isFinite(scanned) && Number.isFinite(uptime) &&
                    (scanned < last.scanned || uptime < last.uptime)) {
                    samples.length = 0;
                }
                if (Number.isFinite(scanned)) {
                    samples.push({scanned, ts: now, uptime});
                }

                // Keep the trailing window plus the sample just outside it
                // (the rate spans the window boundary); the hard cap bounds
                // rapid manual refreshes
                while (samples.length > 2 && now - samples[1].ts >= RATE_WINDOW_MS) {
                    samples.shift();
                }
                while (samples.length > MAX_RATE_SAMPLES) {
                    samples.shift();
                }
                // A span wider than the stale limit means the oldest anchor
                // predates a pause or downtime: drop it so the rate re-arms on
                // the next cycle
                const newest = samples[samples.length - 1];
                if (samples.length > 1 && newest.ts - samples[0].ts > STALE_RATE_WINDOW_MS) {
                    samples.splice(0, samples.length - 1);
                }

                const rate = rateFromSamples(samples);
                neighbour.rate = rate;
                if (rate !== null) {
                    rateSum += rate;
                    hasRate = true;
                }
            });

            // Drop baselines of servers no longer present in the neighbours
            // configuration
            Object.keys(history).forEach((name) => {
                if (!neighbours_status.some((neighbour) => neighbour.name === name)) {
                    delete history[name];
                }
            });

            return hasRate ? rateSum : null;
        }

        // Details row revealed by clicking a server row: the /stat fields not
        // shown in the main row (traffic and memory counters) — no extra
        // requests.
        function buildDetailsRow(data, expanded) {
            function fmtInt(value) {
                return Number.isFinite(value) ? d3.format(",")(value) : "-";
            }
            function fmtBytes(value) {
                return Number.isFinite(value) ? libft.formatBytesIEC(value) : "-";
            }
            // @ pair of <dt>/<dd> elements
            function dd(term, definition) {
                return "<dt>" + term + "</dt><dd>" + definition + "</dd>";
            }

            return '<tr class="cluster-details' + (expanded ? "" : " d-none") + '">' +
                '<td colspan="11">' +
                // mx-0 cancels .row negative gutters that would overflow the td
                '<div class="row row-cols-1 row-cols-sm-2 g-3 mx-0 py-1 small text-secondary">' +
                '<div class="col"><div class="fw-bold">Traffic</div>' +
                '<dl class="cluster-dl">' +
                    dd("Scanned", fmtInt(data.scanned)) +
                    dd("Spam / Ham", fmtInt(data.spam_count) + " / " + fmtInt(data.ham_count)) +
                    dd("Learned", fmtInt(data.learned)) +
                    dd("Connections", fmtInt(data.connections)) +
                    dd("Control connections", fmtInt(data.control_connections)) +
                "</dl></div>" +
                '<div class="col"><div class="fw-bold">Memory</div>' +
                '<dl class="cluster-dl">' +
                    dd("Allocated", fmtBytes(data.bytes_allocated)) +
                    dd("Fragmented", fmtBytes(data.fragmented)) +
                    dd("Pools alloc / freed", fmtInt(data.pools_allocated) + " / " + fmtInt(data.pools_freed)) +
                    dd("Chunks alloc / freed", fmtInt(data.chunks_allocated) + " / " + fmtInt(data.chunks_freed)) +
                    dd("Chunks shared / oversized",
                        fmtInt(data.shared_chunks_allocated) + " / " + fmtInt(data.chunks_oversized)) +
                "</dl></div>" +
                "</div></td></tr>";
        }

        function attachRowspanHoverHandlers(tableId) {
            const table = document.querySelector(tableId);

            function prevSiblingCount(el) {
                let n = 0;
                let prev = el.previousElementSibling;
                while (prev) {
                    n++;
                    prev = prev.previousElementSibling;
                }
                return n;
            }

            // Cells with rowspan in rows above `row` that still span into it.
            function findRowspanCells(row) {
                const headerCount = table.querySelectorAll("thead th").length;
                if (row.querySelectorAll("td").length >= headerCount) return [];

                const rowIndex = prevSiblingCount(row);
                const result = [];
                let prevRow = row.previousElementSibling;
                while (prevRow) {
                    prevRow.querySelectorAll("td[rowspan]").forEach((cell) => {
                        const rowspan = parseInt(cell.getAttribute("rowspan"), 10);
                        const distance = rowIndex - prevSiblingCount(cell.parentElement);
                        if (distance < rowspan) result.push(cell);
                    });
                    prevRow = prevRow.previousElementSibling;
                }
                return result;
            }

            function addClassTo(cells) {
                cells.forEach((cell) => cell.classList.add("table-hover-cell"));
            }

            function highlightCell(cell) {
                const row = cell.parentElement;

                if (cell.getAttribute("rowspan")) {
                    // Hovering over rowspan cell - highlight entire group
                    const rowspan = parseInt(cell.getAttribute("rowspan"), 10);
                    addClassTo(row.querySelectorAll("td"));
                    let next = row.nextElementSibling;
                    for (let i = 0; i < rowspan - 1 && next; i++) {
                        addClassTo(next.querySelectorAll("td"));
                        next = next.nextElementSibling;
                    }

                    // Also highlight parent rowspan cells (e.g. server when hovering classifier)
                    findRowspanCells(row).forEach((parentCell) => {
                        if (parentCell !== cell) parentCell.classList.add("table-hover-cell");
                    });
                } else {
                    // Hovering over regular cell - highlight current row
                    addClassTo(row.querySelectorAll("td"));

                    // Highlight all rowspan cells for this row
                    addClassTo(findRowspanCells(row));
                }
            }

            // jQuery's delegated mouseenter/mouseleave is simulated via mouseover/
            // mouseout (mouseenter/mouseleave don't bubble). Fire only on a genuine
            // enter/leave of the matched td by checking relatedTarget containment.
            //
            // For mouseover `related` is the element the pointer left; for mouseout
            // the element it entered. Either way the test is the same: a crossing
            // happened iff `related` is null (entered/left the document) or lies
            // outside `td`. td.contains(td) is true, so moving between a td and its
            // own descendant — or staying within it — does not register as a crossing.
            function crosses(td, related) {
                return !related || !td.contains(related);
            }

            table.addEventListener("mouseover", (event) => {
                const td = event.target.closest("tbody td");
                if (td && table.contains(td) && crosses(td, event.relatedTarget)) {
                    highlightCell(td);
                }
            });
            table.addEventListener("mouseout", (event) => {
                const td = event.target.closest("tbody td");
                if (td && table.contains(td) && crosses(td, event.relatedTarget)) {
                    table.querySelectorAll("tbody td").forEach((cell) => {
                        cell.classList.remove("table-hover-cell");
                    });
                }
            });
        }

        function displayStatWidgets(checked_server) {
            const servers = JSON.parse(sessionStorage.getItem("Credentials") || "{}");
            const data = servers[checked_server]?.data ?? {};

            const statWidgets = document.getElementById("statWidgets");
            const stat_w = [];
            statWidgets.replaceChildren();
            common.hide(statWidgets);
            Object.entries(data).forEach(([i, item]) => {
                const widgetsOrder = ["scanned", "no action", "greylist", "add header", "rewrite subject", "reject", "learned"];

                function widget(k, v, cls) {
                    const c = (typeof cls === "undefined") ? "" : cls;
                    const titleAtt = d3.format(",")(v) + " " + k;
                    return '<div class="card stat-box d-inline-block text-center shadow-sm me-3 px-3">' +
                        '<div class="widget overflow-hidden p-2' + c + '" title="' + titleAtt +
                        '"><strong class="d-block mt-2 mb-1 fw-bold">' +
                        d3.format(".3~s")(v) + "</strong>" + k + "</div></div>";
                }

                if (i === "auth" || i === "error") return; // Skip to the next iteration
                if (i === "uptime" || i === "version") {
                    let cls = "border-end ";
                    let val = item;
                    if (i === "uptime") {
                        cls = "";
                        val = msToTime(item);
                    }
                    statWidgets.insertAdjacentHTML("beforeend",
                        '<div class="' + cls + 'float-start px-3"><strong class="d-block mt-2 mb-1 fw-bold">' +
                        val + "</strong>" + i + "</div>");
                } else if (i === "actions") {
                    Object.entries(item).forEach(([action, count]) => {
                        stat_w[widgetsOrder.indexOf(action)] = widget(action, count);
                    });
                } else {
                    stat_w[widgetsOrder.indexOf(i)] = widget(i, item, " text-capitalize");
                }
            });
            stat_w.forEach((html) => statWidgets.insertAdjacentHTML("beforeend", html));

            // Wrap the uptime/version widgets (the non-stat-box children) in a
            // trailing card, mirroring $.wrapAll + moving the float-end card last.
            const nonStatBoxDivs = Array.from(statWidgets.children)
                .filter((child) => child.tagName === "DIV" && !child.classList.contains("stat-box"));
            if (nonStatBoxDivs.length) {
                const inner = common.el("div", {class: "widget overflow-hidden p-2 text-capitalize"},
                    ...nonStatBoxDivs);
                statWidgets.append(common.el("div",
                    {class: "card stat-box text-center shadow-sm float-end"}, inner));
            }
            common.show(statWidgets);

            const clusterTbody = document.querySelector("#clusterTable tbody");
            const selSrv = document.getElementById("selSrv");
            clusterTbody.replaceChildren();
            selSrv.replaceChildren();

            const statHistory = parseJsonOrEmpty(sessionStorage.getItem(STAT_HISTORY_KEY));
            const realServers = Object.entries(servers)
                .filter(([key, val]) => key !== "All SERVERS" && val.status)
                .map(([key, val]) => ({name: key, data: val.data || {}}));
            const configDrift = findDeviants(realServers, "config_id");
            const versionDrift = findDeviants(realServers, "version");

            // @ warning triangle marking a server deviating from the cluster majority
            function driftBadge(drift, what, value) {
                return ' <span class="icon cluster-drift" title="' +
                    common.escapeHTML(what + " differs: " + drift.majorityCount + " of " +
                        drift.total + " servers " + value) +
                    '"><i class="fas fa-exclamation-triangle"></i></span>';
            }

            Object.entries(servers).forEach(([key, val]) => {
                const rowState = serverRowState(key, val, statHistory);

                const checked = checked_server === key;
                const disabled = !checked && !val.status;
                const escKey = common.escapeHTML(key);
                const escHost = common.escapeHTML(val.host);
                const radioAttrs = 'value="' + escKey + '"' +
                    (checked ? " checked" : "") + (disabled ? " disabled" : "");

                const realUp = val.status && key !== "All SERVERS";
                const expanded = expandedServers.has(key);
                const toggle = realUp
                    ? '<td class="cluster-toggle" role="button" aria-expanded="' + expanded +
                        '" title="Show/hide details"><span class="cluster-toggle-icon">' +
                            '<i class="fas fa-chevron-down"></i></span></td>'
                    : "<td></td>";
                let latency = "";
                if (key !== "All SERVERS") {
                    latency = val.status ? formatLatency(val.latency) : "-";
                }
                // Same badge as the Configuration tab: shown when writable,
                // nothing in read-only mode; right-aligned within the cell
                const writable_badge = (val.data.read_only === false)
                    ? '<span class="badge text-bg-success float-end">Writable</span>'
                    : "";

                clusterTbody.insertAdjacentHTML("beforeend",
                    '<tr class="' + rowState.row_class + '" data-server="' + escKey + '">' +
                    toggle +
                    '<td class="align-middle"><input type="radio" class="form-check m-auto" name="clusterName" ' +
                        radioAttrs + "></td>" +
                    "<td>" + escKey + writable_badge + "</td>" +
                    "<td>" + escHost + "</td>" +
                    '<td class="text-center cluster-status"' + rowState.status_title + ">" +
                        '<span class="icon"><i class="' + rowState.glyph_status + '"></i></span>' +
                        rowState.status_extra + "</td>" +
                    '<td class="text-center"' + rowState.scan_times.title + ">" +
                        rowState.scan_times.data + "</td>" +
                    '<td class="text-end" title="Messages scanned per minute">' +
                        formatRate(val.rate) + "</td>" +
                    '<td class="text-end">' + latency + "</td>" +
                    '<td class="text-end' +
                      ((Number.isFinite(val.data.uptime) && val.data.uptime < 3600)
                          ? ' warning" title="Has been restarted within the last hour"'
                          : "") +
                      '">' + rowState.uptime + "</td>" +
                    "<td>" + common.escapeHTML(rowState.version) +
                        (versionDrift?.deviants.has(key)
                            ? driftBadge(versionDrift, "Version", "run " + versionDrift.majorityValue)
                            : "") +
                    "</td>" +
                    "<td>" + common.escapeHTML(rowState.short_id) +
                        (configDrift?.deviants.has(key)
                            ? driftBadge(configDrift, "Configuration ID",
                                "share " + String(configDrift.majorityValue).substring(0, 8))
                            : "") +
                    "</td></tr>" +
                    (realUp ? buildDetailsRow(val.data, expanded) : "")
                );

                selSrv.insertAdjacentHTML("beforeend",
                    '<option value="' + escKey + '"' +
                    (checked ? " selected" : "") + (disabled ? " disabled" : "") + ">" + escKey + "</option>");
            });

            if (!clusterToggleHandlerInitialized) {
                // Clicking anywhere on a server row toggles its details row,
                // except the radio (which selects the server)
                common.delegate(document, "click", "#clusterTable tbody tr[data-server]",
                    function (event) {
                        if (event.target.closest("input")) return;
                        const detailsRow = this.nextElementSibling;
                        if (!detailsRow || !detailsRow.classList.contains("cluster-details")) return;

                        if (expandedServers.has(this.dataset.server)) {
                            expandedServers.delete(this.dataset.server);
                        } else {
                            expandedServers.add(this.dataset.server);
                        }
                        detailsRow.classList.toggle("d-none");
                        this.querySelector(".cluster-toggle").setAttribute("aria-expanded",
                            String(!detailsRow.classList.contains("d-none")));
                    });
                clusterToggleHandlerInitialized = true;
            }

            function addStatfiles(server, statfiles) {
                const safeStatfiles = Array.isArray(statfiles) ? statfiles : [];
                const classToSymbolClass = {spam: "symbol-positive", ham: "symbol-negative"};
                const rowsCount = safeStatfiles.length;
                const bayesTbody = document.querySelector("#bayesTable tbody");

                function coerceNumber(value) { return (Number.isFinite(value) ? value : Number(value) || 0); }

                function guessClassFromSymbol(symbol) {
                    if (!symbol) return "-";

                    const upperSymbol = symbol.toUpperCase();
                    if (upperSymbol.includes("SPAM")) return "spam";
                    if (upperSymbol.includes("HAM")) return "ham";

                    return "-";
                }

                function formatClassifierLabel(statfile) {
                    const classifier = statfile.classifier ?? {};
                    const badges = [];
                    function badge(cls, text) { return ` <span class="badge ${cls} ms-1">${text}</span>`; }

                    if (classifier.type === "multi-class") badges.push(badge("bg-secondary", "multi-class"));
                    if (classifier.per_user) badges.push(badge("bg-info", "per-user"));

                    return common.escapeHTML(classifier.name ?? "-") + badges.join("");
                }

                function renderCell(value, className) {
                    const cls = className?.trim();
                    return cls ? `<td class="${cls}">${value}</td>` : `<td>${value}</td>`;
                }

                safeStatfiles.forEach((statfile, i) => {
                    const symbol = statfile.symbol ?? "-";
                    const classValue = statfile.class ?? guessClassFromSymbol(symbol);
                    const cls = classToSymbolClass[classValue] || "";
                    const clName = statfile.classifier?.name ?? "-";
                    const prevClName = i > 0 ? (safeStatfiles[i - 1].classifier?.name ?? "-") : null;

                    const serverCell = i === 0 ? `<td rowspan="${rowsCount}">${common.escapeHTML(server)}</td>` : "";

                    let classifierCell = "";
                    if (clName !== prevClName) {
                        let groupSize = 1;
                        for (let k = i + 1; k < safeStatfiles.length; k++) {
                            if ((safeStatfiles[k].classifier?.name ?? "-") === clName) {
                                groupSize++;
                            } else break;
                        }
                        classifierCell = `<td rowspan="${groupSize}">${formatClassifierLabel(statfile)}</td>`;
                    }

                    bayesTbody.insertAdjacentHTML("beforeend", `<tr>${serverCell}${classifierCell}${[
                        renderCell(common.escapeHTML(classValue), cls),
                        renderCell(common.escapeHTML(symbol), cls),
                        renderCell(common.escapeHTML(statfile.type ?? "-"), cls),
                        renderCell(coerceNumber(statfile.revision), `text-end ${cls}`),
                        renderCell(coerceNumber(statfile.users), `text-end ${cls}`),
                    ].join("")}</tr>`);
                });
            }

            function addFuzzyStorage(server, storages) {
                let i = 0;
                const fuzzyTbody = document.querySelector("#fuzzyTable tbody");
                Object.entries(storages || {}).forEach(([storage, hashes]) => {
                    const serverCell = (i === 0)
                        ? '<td rowspan="' + Object.keys(storages || {}).length + '">' + common.escapeHTML(server) + "</td>"
                        : "";
                    fuzzyTbody.insertAdjacentHTML("beforeend", "<tr>" + serverCell +
                      "<td>" + common.escapeHTML(storage) + "</td>" +
                      '<td class="text-end">' + hashes + "</td></tr>");
                    i++;
                });
            }

            document.querySelectorAll("#bayesTable tbody, #fuzzyTable tbody")
                .forEach((tbody) => tbody.replaceChildren());
            if (checked_server === "All SERVERS") {
                Object.entries(servers).forEach(([server, val]) => {
                    if (server !== "All SERVERS") {
                        addStatfiles(server, val.data.statfiles);
                        addFuzzyStorage(server, val.data.fuzzy_hashes);
                    }
                });
            } else {
                addStatfiles(checked_server, data.statfiles);
                addFuzzyStorage(checked_server, data.fuzzy_hashes);
            }

            if (!rowspanHoverHandlersInitialized) {
                attachRowspanHoverHandlers("#bayesTable");
                attachRowspanHoverHandlers("#fuzzyTable");
                rowspanHoverHandlersInitialized = true;
            }
        }

        function getChart(graphs, checked_server) {
            if (!graphs.chart) {
                graphs.chart = new D3Pie("chart", {
                    labels: {
                        inner: {
                            offset: 0
                        },
                        outer: {
                            collideHeight: 18,
                        }
                    },
                    size: {
                        pieInnerRadius: "50%"
                    },
                    title: "Rspamd filter stats",
                    total: {
                        enabled: true,
                        label: "Scanned"
                    }
                });
            }

            const data = [];
            const creds = JSON.parse(sessionStorage.getItem("Credentials") || "{}");
            // Controller doesn't return the 'actions' object until at least one message is scanned
            if (creds[checked_server]?.data?.scanned) {
                const {actions} = creds[checked_server].data;

                ["no action", "soft reject", "add header", "rewrite subject", "greylist", "reject"]
                    .forEach((action) => {
                        data.push({
                            color: common.chartLegend.find((item) => item.label === action).color,
                            label: action,
                            value: actions[action]
                        });
                    });
            }
            graphs.chart.data(data);
        }

        // Public API
        const ui = {
            statWidgets: function (graphs, checked_server) {
                common.query("stat", {
                    success: function (neighbours_status) {
                        const cycleId = ++statCycleId;
                        const statHistory = parseJsonOrEmpty(sessionStorage.getItem(STAT_HISTORY_KEY));
                        const neighbours_sum = {
                            version: neighbours_status[0].data.version,
                            uptime: 0,
                            scanned: 0,
                            learned: 0,
                            actions: {
                                "no action": 0,
                                "add header": 0,
                                "rewrite subject": 0,
                                "greylist": 0,
                                "reject": 0,
                                "soft reject": 0,
                            }
                        };
                        let status_count = 0;
                        const promises = [];
                        const healthPromises = [];
                        const to_Credentials = {
                            "All SERVERS": {
                                name: "All SERVERS",
                                url: "",
                                host: "",
                                checked: true,
                                status: true
                            }
                        };

                        function process_node_stat(e) {
                            const {data} = neighbours_status[e];
                            // Controller doesn't return the 'actions' object until at least one message is scanned
                            if (data.scanned) {
                                for (const action in neighbours_sum.actions) {
                                    if ({}.hasOwnProperty.call(neighbours_sum.actions, action)) {
                                        neighbours_sum.actions[action] += data.actions[action];
                                    }
                                }
                            }
                            ["learned", "scanned", "uptime"].forEach((p) => {
                                neighbours_sum[p] += data[p];
                            });
                            status_count++;
                        }

                        // Get config_id, version and uptime using /auth query for Rspamd 2.5 and earlier
                        function get_legacy_stat(e) {
                            const alerted = "alerted_stats_legacy_" + neighbours_status[e].name;
                            promises.push(new Promise((resolve) => {
                                const xhr = new XMLHttpRequest();
                                xhr.open("GET", neighbours_status[e].url + "auth", true);
                                xhr.setRequestHeader("Password", common.getPassword());
                                const timeout = common.getAjaxTimeout();
                                if (timeout > 0) xhr.timeout = timeout;

                                function onFailure(errorThrown) {
                                    if (!(alerted in sessionStorage)) {
                                        sessionStorage.setItem(alerted, true);
                                        common.logError({
                                            server: neighbours_status[e].name,
                                            endpoint: "graph",
                                            message: "Cannot receive legacy stats data" +
                                                (errorThrown ? ": " + errorThrown : ""),
                                            httpStatus: xhr.status,
                                            errorType: "http_error"
                                        });
                                    }
                                    process_node_stat(e);
                                    resolve();
                                }

                                xhr.onload = () => {
                                    if (xhr.status >= 200 && xhr.status < 300) {
                                        sessionStorage.removeItem(alerted);
                                        const data = parseJsonOrEmpty(xhr.responseText);
                                        ["config_id", "version", "uptime"].forEach((p) => {
                                            neighbours_status[e].data[p] = data[p];
                                        });
                                        process_node_stat(e);
                                        resolve();
                                    } else {
                                        onFailure(xhr.statusText);
                                    }
                                };
                                xhr.onerror = () => onFailure(xhr.statusText);
                                xhr.ontimeout = () => onFailure("timeout");
                                xhr.send();
                            }));
                        }

                        for (const e in neighbours_status) {
                            if ({}.hasOwnProperty.call(neighbours_status, e)) {
                                to_Credentials[neighbours_status[e].name] = neighbours_status[e];
                                if (neighbours_status[e].status === true) {
                                    // Remove alert status
                                    sessionStorage.removeItem("alerted_stats_" + neighbours_status[e].name);

                                    // Three-state health: /healthy and /ready
                                    // report server-side degradation as HTTP 500.
                                    // The probes run outside the render path: the
                                    // table renders as soon as /stat settles and
                                    // is re-rendered with the health state once
                                    // every probe has answered.
                                    healthPromises.push(Promise.all([
                                        probeHealth(neighbours_status[e], "healthy"),
                                        probeHealth(neighbours_status[e], "ready"),
                                    ]).then(([healthy, ready]) => {
                                        const degraded = [healthy, ready]
                                            .filter((probe) => probe.state === "degraded");
                                        neighbours_status[e].health = degraded.length
                                            ? {
                                                state: "degraded",
                                                reason: degraded
                                                    .map((probe) => probe.reason)
                                                    .filter(Boolean)
                                                    .join("; ")
                                            }
                                            : {
                                                state: (healthy.state === "ok" && ready.state === "ok")
                                                    ? "ok"
                                                    : "unknown"
                                            };
                                    }));

                                    if ({}.hasOwnProperty.call(neighbours_status[e].data, "version")) {
                                        process_node_stat(e);
                                    } else {
                                        get_legacy_stat(e);
                                    }
                                }
                            }
                        }
                        const settled = new Promise((resolve) => {
                            setTimeout(() => {
                                Promise.all(promises).finally(() => {
                                    // A newer refresh cycle superseded this one:
                                    // drop its (stale) state entirely
                                    if (cycleId === statCycleId) {
                                        neighbours_sum.uptime = Math.floor(neighbours_sum.uptime / status_count);
                                        neighbours_sum.rate = updateStatHistory(neighbours_status, statHistory);
                                        sessionStorage.setItem(STAT_HISTORY_KEY, JSON.stringify(statHistory));
                                        to_Credentials["All SERVERS"].data = neighbours_sum;
                                        // Cluster-wide load for the "All SERVERS" row,
                                        // mirroring neighbour.rate of real servers
                                        to_Credentials["All SERVERS"].rate = neighbours_sum.rate;
                                        sessionStorage.setItem("Credentials", JSON.stringify(to_Credentials));
                                        displayStatWidgets(checked_server);
                                        getChart(graphs, checked_server);
                                    }
                                    resolve();
                                });
                            }, promises.length ? 100 : 0);
                        });

                        if (healthPromises.length) {
                            // Second and final pass: strictly ordered after the
                            // stat-data render above (chained through `settled` —
                            // the probes answer later), so it overwrites the
                            // just-written Credentials instead of racing it.
                            // Skipped when the Status tab is no longer active —
                            // the next cycle renders it anyway — and when a newer
                            // cycle has superseded this one.
                            Promise.all(healthPromises).then(() => settled).then(() => {
                                if (cycleId !== statCycleId) return;
                                sessionStorage.setItem("Credentials", JSON.stringify(to_Credentials));
                                if (document.getElementById("status").classList.contains("active")) {
                                    displayStatWidgets(checked_server);
                                }
                            });
                        }
                    },
                    complete: function () {
                        const refreshBtn = document.getElementById("refresh");
                        refreshBtn.disabled = false;
                        refreshBtn.classList.remove("disabled");
                    },
                    errorMessage: "Cannot receive stats data",
                    errorOnceId: "alerted_stats_",
                    server: "All SERVERS"
                });
            },
        };

        return ui;
    }
);
