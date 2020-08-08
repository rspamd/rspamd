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
                if (!("config_id" in val.data)) {
                    val.data.config_id = "";
                }
                if (val.status) {
                    row_class = "success";
                    glyph_status = "fas fa-check";
                    uptime = msToTime(val.data.uptime);
                    version = val.data.version;
                    short_id = val.data.config_id.substring(0, 8);
                }

                $("#clusterTable tbody").append('<tr class="' + row_class + '">' +
                '<td class="align-middle"><input type="radio" class="form-check m-auto" name="clusterName" value="' + key + '"></td>' +
                "<td>" + key + "</td>" +
                "<td>" + val.host + "</td>" +
                '<td class="text-center"><span class="icon"><i class="' + glyph_status + '"></i></span></td>' +
                '<td class="text-right">' + uptime + "</td>" +
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
                      '<td class="' + cls + '">' + statfile.revision + "</td>" +
                      '<td class="' + cls + '">' + statfile.users + "</td></tr>");
                });
            }
            $("#bayesTable tbody").empty();
            if (checked_server === "All SERVERS") {
                $.each(servers, function (server, val) {
                    if (server !== "All SERVERS") {
                        addStatfiles(server, val.data.statfiles);
                    }
                });
            } else {
                addStatfiles(checked_server, data.statfiles);
            }
        }

        function getChart(rspamd, pie, checked_server) {
            var creds = JSON.parse(sessionStorage.getItem("Credentials"));
            if (!creds || !creds[checked_server]) return null;

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

            return rspamd.drawPie(pie, "chart", new_data);
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
                        for (var e in neighbours_status) {
                            if (neighbours_status[e].status === true) {
                                // Remove alert status
                                localStorage.removeItem(e + "_alerted");

                                var data = neighbours_status[e].data;
                                for (var action in neighbours_sum.actions) {
                                    if ({}.hasOwnProperty.call(neighbours_sum.actions, action)) {
                                        neighbours_sum.actions[action] += data.actions[action];
                                    }
                                }
                                var items = ["learned", "scanned", "uptime"];
                                for (var i in items) {
                                    if ({}.hasOwnProperty.call(items, i)) {
                                        neighbours_sum[items[i]] += data[items[i]];
                                    }
                                }
                                status_count++;
                            }
                        }
                        neighbours_sum.uptime = Math.floor(neighbours_sum.uptime / status_count);
                        var to_Credentials = {};
                        to_Credentials["All SERVERS"] = {
                            name: "All SERVERS",
                            url: "",
                            host: "",
                            checked: true,
                            data: neighbours_sum,
                            status: true
                        };
                        neighbours_status.forEach(function (elmt) {
                            to_Credentials[elmt.name] = elmt;
                        });
                        sessionStorage.setItem("Credentials", JSON.stringify(to_Credentials));
                        displayStatWidgets(checked_server);
                        graphs.chart = getChart(rspamd, graphs.chart, checked_server);
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
