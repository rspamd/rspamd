/*
 * Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>
 */

define(["app/common", "d3pie", "d3"],
    (common, D3Pie, d3) => {
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
            Object.entries(servers).forEach(([key, val]) => {
                let row_class = "danger";
                let glyph_status = "fas fa-times";
                let version = "???";
                let uptime = "???";
                let short_id = "???";
                let scan_times = {
                    data: "???",
                    title: ""
                };
                if (val.status) {
                    row_class = "success";
                    glyph_status = "fas fa-check";
                    if (Number.isFinite(val.data.uptime)) {
                        uptime = msToTime(val.data.uptime);
                    }
                    if ("version" in val.data) {
                        ({version} = val.data);
                    }
                    if (key === "All SERVERS") {
                        short_id = "";
                        scan_times.data = "";
                    } else {
                        if ("config_id" in val.data) {
                            short_id = val.data.config_id.substring(0, 8);
                        }
                        if ("scan_times" in val.data) {
                            const [min, max] = d3.extent(val.data.scan_times);
                            if (max) {
                                const f = d3.format(".3f");
                                scan_times = {
                                    data: "<small>" + f(min) + "/</small>" +
                                        f(d3.mean(val.data.scan_times)) +
                                        "<small>/" + f(max) + "</small>",
                                    title: ' title="min/avg/max"'
                                };
                            } else {
                                scan_times = {
                                    data: "-",
                                    title: ' title="Have not scanned anything yet"'
                                };
                            }
                        }
                    }
                }

                const checked = checked_server === key;
                const disabled = !checked && !val.status;
                const escKey = common.escapeHTML(key);
                const escHost = common.escapeHTML(val.host);
                const radioAttrs = 'value="' + escKey + '"' +
                    (checked ? " checked" : "") + (disabled ? " disabled" : "");

                clusterTbody.insertAdjacentHTML("beforeend",
                    '<tr class="' + row_class + '">' +
                    '<td class="align-middle"><input type="radio" class="form-check m-auto" name="clusterName" ' +
                        radioAttrs + "></td>" +
                    "<td>" + escKey + "</td>" +
                    "<td>" + escHost + "</td>" +
                    '<td class="text-center"><span class="icon"><i class="' + glyph_status + '"></i></span></td>' +
                    '<td class="text-center"' + scan_times.title + ">" + scan_times.data + "</td>" +
                    '<td class="text-end' +
                      ((Number.isFinite(val.data.uptime) && val.data.uptime < 3600)
                          ? ' warning" title="Has been restarted within the last hour"'
                          : "") +
                      '">' + uptime + "</td>" +
                    "<td>" + common.escapeHTML(version) + "</td>" +
                    "<td>" + common.escapeHTML(short_id) + "</td></tr>"
                );

                selSrv.insertAdjacentHTML("beforeend",
                    '<option value="' + escKey + '"' +
                    (checked ? " selected" : "") + (disabled ? " disabled" : "") + ">" + escKey + "</option>");
            });

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

                                    if ({}.hasOwnProperty.call(neighbours_status[e].data, "version")) {
                                        process_node_stat(e);
                                    } else {
                                        get_legacy_stat(e);
                                    }
                                }
                            }
                        }
                        setTimeout(() => {
                            Promise.all(promises).finally(() => {
                                neighbours_sum.uptime = Math.floor(neighbours_sum.uptime / status_count);
                                to_Credentials["All SERVERS"].data = neighbours_sum;
                                sessionStorage.setItem("Credentials", JSON.stringify(to_Credentials));
                                displayStatWidgets(checked_server);
                                getChart(graphs, checked_server);
                            });
                        }, promises.length ? 100 : 0);
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
