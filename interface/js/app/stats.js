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

/* global d3:false */

define(["jquery", "d3pie"],
    function ($) {
        "use strict";
        // @ ms to date
        function msToTime(seconds) {
            if (!Number.isFinite(seconds)) return "???";
            /* eslint-disable no-bitwise */
            var years = seconds / 31536000 >> 0; // 3600*24*365
            var months = seconds % 31536000 / 2628000 >> 0; // 3600*24*365/12
            var days = seconds % 31536000 % 2628000 / 86400 >> 0; // 24*3600
            var hours = seconds % 31536000 % 2628000 % 86400 / 3600 >> 0;
            var minutes = seconds % 31536000 % 2628000 % 86400 % 3600 / 60 >> 0;
            /* eslint-enable no-bitwise */
            var out = null;
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
            var servers = JSON.parse(sessionStorage.getItem("Credentials"));
            var data = {};
            if (servers && servers[checked_server]) {
                data = servers[checked_server].data;
            }

            var stat_w = [];
            $("#statWidgets").empty().hide();
            $.each(data, function (i, item) {
                var widgetsOrder = ["scanned", "no action", "greylist", "add header", "rewrite subject", "reject", "learned"];

                function widget(k, v, cls) {
                    var c = (typeof cls === "undefined") ? "" : cls;
                    var titleAtt = d3.format(",")(v) + " " + k;
                    return '<div class="card stat-box d-inline-block text-center bg-light shadow-sm mr-3 px-3">' +
                      '<div class="widget overflow-hidden p-2' + c + '" title="' + titleAtt +
                      '"><strong class="d-block mt-2 mb-1 font-weight-bold">' +
                    d3.format(".3~s")(v) + "</strong>" + k + "</div></div>";
                }

                if (i === "auth" || i === "error") return; // Skip to the next iteration
                if (i === "uptime" || i === "version") {
                    var cls = "border-right ";
                    var val = item;
                    if (i === "uptime") {
                        cls = "";
                        val = msToTime(item);
                    }
                    $('<div class="' + cls + 'float-left px-3"><strong class="d-block mt-2 mb-1 font-weight-bold">' +
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
                .wrapAll('<div class="card stat-box text-center bg-light shadow-sm float-right">' +
                  '<div class="widget overflow-hidden p-2 text-capitalize"></div></div>');
            $("#statWidgets").find("div.float-right").appendTo("#statWidgets");
            $("#statWidgets").show();

            $("#clusterTable tbody").empty();
            $("#selSrv").empty();
            $.each(servers, function (key, val) {
                var row_class = "danger";
                var glyph_status = "fas fa-times";
                var version = "???";
                var uptime = "???";
                var short_id = "???";
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
                    } else if ("config_id" in val.data) {
                        short_id = val.data.config_id.substring(0, 8);
                    }
                }

                $("#clusterTable tbody").append('<tr class="' + row_class + '">' +
                '<td class="align-middle"><input type="radio" class="form-check m-auto" name="clusterName" value="' + key + '"></td>' +
                "<td>" + key + "</td>" +
                "<td>" + val.host + "</td>" +
                '<td class="text-center"><span class="icon"><i class="' + glyph_status + '"></i></span></td>' +
                '<td class="text-right' +
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
                    var cls = "";
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
                      '<td class="text-right ' + cls + '">' + statfile.revision + "</td>" +
                      '<td class="text-right ' + cls + '">' + statfile.users + "</td></tr>");
                });
            }

            function addFuzzyStorage(server, storages) {
                var i = 0;
                $.each(storages, function (storage, hashes) {
                    $("#fuzzyTable tbody").append("<tr>" +
                      (i === 0 ? '<td rowspan="' + Object.keys(storages).length + '">' + server + "</td>" : "") +
                      "<td>" + storage + "</td>" +
                      '<td class="text-right">' + hashes + "</td></tr>");
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

        function getChart(rspamd, graphs, checked_server) {
            if (graphs.chart) {
                graphs.chart.destroy();
                delete graphs.chart;
            }

            var creds = JSON.parse(sessionStorage.getItem("Credentials"));
            // Controller doesn't return the 'actions' object until at least one message is scanned
            if (!creds || !creds[checked_server] || !creds[checked_server].data.scanned) {
                // Show grayed out pie as percentage is undefined
                return rspamd.drawPie(graphs.chart,
                    "chart",
                    [{
                        value: 1,
                        color: "#ffffff",
                        label: "undefined"
                    }],
                    {
                        labels: {
                            mainLabel: {
                                fontSize: 14,
                            },
                            inner: {
                                format: "none",
                            },
                            lines: {
                                color: "#cccccc"
                            }
                        },
                        tooltips: {
                            enabled: true,
                            string: "{label}"
                        },
                    }
                );
            }

            var data = creds[checked_server].data.actions;
            var new_data = [{
                color: "#66CC00",
                label: "no action",
                data: data["no action"],
                value: data["no action"]
            }, {
                color: "#BF8040",
                label: "soft reject",
                data: data["soft reject"],
                value: data["soft reject"]
            }, {
                color: "#FFAD00",
                label: "add header",
                data: data["add header"],
                value: data["add header"]
            }, {
                color: "#FF6600",
                label: "rewrite subject",
                data: data["rewrite subject"],
                value: data["rewrite subject"]
            }, {
                color: "#436EEE",
                label: "greylist",
                data: data.greylist,
                value: data.greylist
            }, {
                color: "#FF0000",
                label: "reject",
                data: data.reject,
                value: data.reject
            }];

            return rspamd.drawPie(graphs.chart, "chart", new_data);
        }
        // Public API
        var ui = {
            statWidgets: function (rspamd, graphs, checked_server) {
                rspamd.query("stat", {
                    success: function (neighbours_status) {
                        var neighbours_sum = {
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
                        var status_count = 0;
                        var promises = [];
                        var to_Credentials = {
                            "All SERVERS": {
                                name: "All SERVERS",
                                url: "",
                                host: "",
                                checked: true,
                                status: true
                            }
                        };

                        function process_node_stat(e) {
                            var data = neighbours_status[e].data;
                            // Controller doesn't return the 'actions' object until at least one message is scanned
                            if (data.scanned) {
                                for (var action in neighbours_sum.actions) {
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
                            var alerted = "alerted_stats_legacy_" + neighbours_status[e].name;
                            promises.push($.ajax({
                                url: neighbours_status[e].url + "auth",
                                headers: {Password:rspamd.getPassword()},
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

                        for (var e in neighbours_status) {
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
                                graphs.chart = getChart(rspamd, graphs, checked_server);
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
