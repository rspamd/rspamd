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
            var widgets = $("#statWidgets");
            $(widgets).empty().hide();

            var servers = JSON.parse(sessionStorage.getItem("Credentials"));
            var data = {};

            if (servers && servers[checked_server]) {
                data = servers[checked_server].data;
            }
            var stat_w = [];

            $.each(data, function (i, item) {
                var widget = "";
                if (i === "auth" || i === "error") return; // Skip to the next iteration
                if (i === "version") {
                    widget = "<div class=\"left\"><strong>" + item + "</strong>" +
                    i + "</div>";
                    $(widget).appendTo(widgets);
                } else if (i === "uptime") {
                    widget = "<div class=\"right\"><strong>" + msToTime(item) +
                    "</strong>" + i + "</div>";
                    $(widget).appendTo(widgets);
                } else {
                    var titleAtt = d3.format(",")(item) + " " + i;
                    widget = "<li class=\"stat-box\"><div class=\"widget\" title=\"" + titleAtt + "\"><strong>" +
                    d3.format(".3~s")(item) + "</strong>" + i + "</div></li>";
                    if (i === "scanned") {
                        stat_w[0] = widget;
                    } else if (i === "clean") {
                        stat_w[1] = widget;
                    } else if (i === "greylist") {
                        stat_w[2] = widget;
                    } else if (i === "probable") {
                        stat_w[3] = widget;
                    } else if (i === "reject") {
                        stat_w[4] = widget;
                    } else if (i === "learned") {
                        stat_w[5] = widget;
                    }
                }
            });
            $.each(stat_w, function (i, item) {
                $(item).appendTo(widgets);
            });
            $("#statWidgets .left,#statWidgets .right").wrapAll("<li class=\"stat-box pull-right\"><div class=\"widget\"></div></li>");
            $("#statWidgets").find("li.pull-right").appendTo("#statWidgets");

            $("#clusterTable tbody").empty();
            $("#selSrv").empty();
            $.each(servers, function (key, val) {
                var glyph_status = "glyphicon glyphicon-remove-circle";
                var short_id = "???";
                if (!("config_id" in val.data)) {
                    val.data.config_id = "";
                }
                if (val.status) {
                    glyph_status = "glyphicon glyphicon-ok-circle";
                    short_id = val.data.config_id.substring(0, 8);
                }

                $("#clusterTable tbody").append("<tr>" +
                "<td class=\"col1\" title=\"Radio\"><input type=\"radio\" class=\"form-control radio\" name=\"clusterName\" value=\"" + key + "\"></td>" +
                "<td class=\"col2\" title=\"SNAme\">" + key + "</td>" +
                "<td class=\"col3\" title=\"SHost\">" + val.host + "</td>" +
                "<td class=\"col4\" title=\"SStatus\"><span class=\"icon\"><i class=\"" + glyph_status + "\"></i></span></td>" +
                "<td class=\"col5\" title=\"short_id\">" + short_id + "</td></tr>");

                $("#selSrv").append($("<option value=\"" + key + "\">" + key + "</option>"));

                if (checked_server === key) {
                    $("#clusterTable tbody [value=\"" + key + "\"]").prop("checked", true);
                    $("#selSrv [value=\"" + key + "\"]").prop("selected", true);
                } else if (!val.status) {
                    $("#clusterTable tbody [value=\"" + key + "\"]").prop("disabled", true);
                    $("#selSrv [value=\"" + key + "\"]").prop("disabled", true);
                }
            });
            $(widgets).show();
        }

        function getChart(rspamd, pie, checked_server) {
            var creds = JSON.parse(sessionStorage.getItem("Credentials"));
            if (!creds || !creds[checked_server]) return null;

            var data = creds[checked_server].data;
            var new_data = [{
                color: "#66CC00",
                label: "Clean",
                data: data.clean,
                value: data.clean
            }, {
                color: "#BF8040",
                label: "Temporarily rejected",
                data: data.soft_reject,
                value: data.soft_reject
            }, {
                color: "#FFAD00",
                label: "Probable spam",
                data: data.probable,
                value: data.probable
            }, {
                color: "#436EEE",
                label: "Greylisted",
                data: data.greylist,
                value: data.greylist
            }, {
                color: "#FF0000",
                label: "Rejected",
                data: data.reject,
                value: data.reject
            }];

            return rspamd.drawPie(pie, "chart", new_data);
        }
        // Public API
        var ui = {
            statWidgets: function (rspamd, graphs, checked_server) {
                rspamd.query("auth", {
                    success: function (neighbours_status) {
                        var neighbours_sum = {
                            version: neighbours_status[0].data.version,
                            auth: "ok",
                            uptime: 0,
                            clean: 0,
                            probable: 0,
                            greylist: 0,
                            reject: 0,
                            soft_reject: 0,
                            scanned: 0,
                            learned: 0,
                            config_id: ""
                        };
                        var status_count = 0;
                        for (var e in neighbours_status) {
                            if (neighbours_status[e].status === true) {
                            // Remove alert status
                                localStorage.removeItem(e + "_alerted");
                                neighbours_sum.clean += neighbours_status[e].data.clean;
                                neighbours_sum.probable += neighbours_status[e].data.probable;
                                neighbours_sum.greylist += neighbours_status[e].data.greylist;
                                neighbours_sum.reject += neighbours_status[e].data.reject;
                                neighbours_sum.soft_reject += neighbours_status[e].data.soft_reject;
                                neighbours_sum.scanned += neighbours_status[e].data.scanned;
                                neighbours_sum.learned += neighbours_status[e].data.learned;
                                neighbours_sum.uptime += neighbours_status[e].data.uptime;
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
