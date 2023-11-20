/*
 The MIT License (MIT)

 Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 */

define(["jquery", "app/rspamd", "d3pie", "d3"],
    function ($, rspamd, D3Pie, d3) {
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

        function displayStatWidgets(checked_server) {
            const servers = JSON.parse(sessionStorage.getItem("Credentials"));
            let data = {};
            if (servers && servers[checked_server]) {
                data = servers[checked_server].data;
            }

            const stat_w = [];
            $("#statWidgets").empty().hide();
            $.each(data, function (i, item) {
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
                    $('<div class="' + cls + 'float-start px-3"><strong class="d-block mt-2 mb-1 fw-bold">' +
                      val + "</strong>" + i + "</div>")
                        .appendTo("#statWidgets");
                } else if (i === "actions") {
                    $.each(item, function (action, count) {
                        stat_w[widgetsOrder.indexOf(action)] = widget(action, count);
                    });
                } else {
                    stat_w[widgetsOrder.indexOf(i)] = widget(i, item, " text-capitalize");
                }
            });
            $.each(stat_w, function (i, item) {
                $(item).appendTo("#statWidgets");
            });
            $("#statWidgets > div:not(.stat-box)")
                .wrapAll('<div class="card stat-box text-center shadow-sm float-end">' +
                  '<div class="widget overflow-hidden p-2 text-capitalize"></div></div>');
            $("#statWidgets").find("div.float-end").appendTo("#statWidgets");
            $("#statWidgets").show();

            $("#clusterTable tbody").empty();
            $("#selSrv").empty();
            $.each(servers, function (key, val) {
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
                        version = val.data.version;
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

                $("#clusterTable tbody").append('<tr class="' + row_class + '">' +
                '<td class="align-middle"><input type="radio" class="form-check m-auto" name="clusterName" value="' +
                    key + '"></td>' +
                "<td>" + key + "</td>" +
                "<td>" + val.host + "</td>" +
                '<td class="text-center"><span class="icon"><i class="' + glyph_status + '"></i></span></td>' +
                '<td class="text-center"' + scan_times.title + ">" + scan_times.data + "</td>" +
                '<td class="text-end' +
                  ((Number.isFinite(val.data.uptime) && val.data.uptime < 3600)
                      ? ' warning" title="Has been restarted within the last hour"'
                      : "") +
                  '">' + uptime + "</td>" +
                "<td>" + version + "</td>" +
                "<td>" + short_id + "</td></tr>");

                $("#selSrv").append($('<option value="' + key + '">' + key + "</option>"));

                if (checked_server === key) {
                    $('#clusterTable tbody [value="' + key + '"]').prop("checked", true);
                    $('#selSrv [value="' + key + '"]').prop("selected", true);
                } else if (!val.status) {
                    $('#clusterTable tbody [value="' + key + '"]').prop("disabled", true);
                    $('#selSrv [value="' + key + '"]').prop("disabled", true);
                }
            });

            function addStatfiles(server, statfiles) {
                $.each(statfiles, function (i, statfile) {
                    let cls = "";
                    switch (statfile.symbol) {
                        case "BAYES_SPAM":
                            cls = "symbol-positive";
                            break;
                        case "BAYES_HAM":
                            cls = "symbol-negative";
                            break;
                        default:
                    }
                    $("#bayesTable tbody").append("<tr>" +
                      (i === 0 ? '<td rowspan="' + statfiles.length + '">' + server + "</td>" : "") +
                      '<td class="' + cls + '">' + statfile.symbol + "</td>" +
                      '<td class="' + cls + '">' + statfile.type + "</td>" +
                      '<td class="text-end ' + cls + '">' + statfile.revision + "</td>" +
                      '<td class="text-end ' + cls + '">' + statfile.users + "</td></tr>");
                });
            }

            function addFuzzyStorage(server, storages) {
                let i = 0;
                $.each(storages, function (storage, hashes) {
                    $("#fuzzyTable tbody").append("<tr>" +
                      (i === 0 ? '<td rowspan="' + Object.keys(storages).length + '">' + server + "</td>" : "") +
                      "<td>" + storage + "</td>" +
                      '<td class="text-end">' + hashes + "</td></tr>");
                    i++;
                });
            }

            $("#bayesTable tbody, #fuzzyTable tbody").empty();
            if (checked_server === "All SERVERS") {
                $.each(servers, function (server, val) {
                    if (server !== "All SERVERS") {
                        addStatfiles(server, val.data.statfiles);
                        addFuzzyStorage(server, val.data.fuzzy_hashes);
                    }
                });
            } else {
                addStatfiles(checked_server, data.statfiles);
                addFuzzyStorage(checked_server, data.fuzzy_hashes);
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
            const creds = JSON.parse(sessionStorage.getItem("Credentials"));
            // Controller doesn't return the 'actions' object until at least one message is scanned
            if (creds && creds[checked_server] && creds[checked_server].data.scanned) {
                const actions = creds[checked_server].data.actions;

                ["no action", "soft reject", "add header", "rewrite subject", "greylist", "reject"]
                    .forEach(function (action) {
                        data.push({
                            color: rspamd.chartLegend.find(function (item) { return item.label === action; }).color,
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
                rspamd.query("stat", {
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
                            const data = neighbours_status[e].data;
                            // Controller doesn't return the 'actions' object until at least one message is scanned
                            if (data.scanned) {
                                for (const action in neighbours_sum.actions) {
                                    if ({}.hasOwnProperty.call(neighbours_sum.actions, action)) {
                                        neighbours_sum.actions[action] += data.actions[action];
                                    }
                                }
                            }
                            ["learned", "scanned", "uptime"].forEach(function (p) {
                                neighbours_sum[p] += data[p];
                            });
                            status_count++;
                        }

                        // Get config_id, version and uptime using /auth query for Rspamd 2.5 and earlier
                        function get_legacy_stat(e) {
                            const alerted = "alerted_stats_legacy_" + neighbours_status[e].name;
                            promises.push($.ajax({
                                url: neighbours_status[e].url + "auth",
                                headers: {Password: rspamd.getPassword()},
                                success: function (data) {
                                    sessionStorage.removeItem(alerted);
                                    ["config_id", "version", "uptime"].forEach(function (p) {
                                        neighbours_status[e].data[p] = data[p];
                                    });
                                    process_node_stat(e);
                                },
                                error: function (jqXHR, textStatus, errorThrown) {
                                    if (!(alerted in sessionStorage)) {
                                        sessionStorage.setItem(alerted, true);
                                        rspamd.alertMessage("alert-error", neighbours_status[e].name + " > " +
                                          "Cannot receive legacy stats data" + (errorThrown ? ": " + errorThrown : ""));
                                    }
                                    process_node_stat(e);
                                }
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
                        setTimeout(function () {
                            $.when.apply($, promises).always(function () {
                                neighbours_sum.uptime = Math.floor(neighbours_sum.uptime / status_count);
                                to_Credentials["All SERVERS"].data = neighbours_sum;
                                sessionStorage.setItem("Credentials", JSON.stringify(to_Credentials));
                                displayStatWidgets(checked_server);
                                getChart(graphs, checked_server);
                            });
                        }, promises.length ? 100 : 0);
                    },
                    complete: function () { $("#refresh").removeAttr("disabled").removeClass("disabled"); },
                    errorMessage: "Cannot receive stats data",
                    errorOnceId: "alerted_stats_",
                    server: "All SERVERS"
                });
            },
        };

        return ui;
    }
);
