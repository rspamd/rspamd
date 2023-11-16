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

/* global require */

define(["jquery", "app/rspamd"],
    function ($, rspamd) {
        "use strict";
        var ui = {};

        function cleanTextUpload(source) {
            $("#" + source + "TextSource").val("");
        }

        // @upload text
        function uploadText(data, source, headers) {
            var url = null;
            if (source === "spam") {
                url = "learnspam";
            } else if (source === "ham") {
                url = "learnham";
            } else if (source === "fuzzy") {
                url = "fuzzyadd";
            } else if (source === "scan") {
                url = "checkv2";
            }

            function server() {
                if (rspamd.getSelector("selSrv") === "All SERVERS" &&
                    rspamd.getSelector("selLearnServers") === "random") {
                    const servers = $("#selSrv option").slice(1).map(function (_, o) { return o.value; });
                    return servers[Math.floor(Math.random() * servers.length)];
                }
                return null;
            }

            rspamd.query(url, {
                data: data,
                params: {
                    processData: false,
                },
                method: "POST",
                headers: headers,
                success: function (json, jqXHR) {
                    cleanTextUpload(source);
                    rspamd.alertMessage("alert-success", "Data successfully uploaded");
                    if (jqXHR.status !== 200) {
                        rspamd.alertMessage("alert-info", jqXHR.statusText);
                    }
                },
                server: server()
            });
        }

        function columns_v2() {
            return [{
                name: "id",
                title: "ID",
                style: {
                    "font-size": "11px",
                    "minWidth": 130,
                    "overflow": "hidden",
                    "textOverflow": "ellipsis",
                    "wordBreak": "break-all",
                    "whiteSpace": "normal"
                }
            }, {
                name: "action",
                title: "Action",
                style: {
                    "font-size": "11px",
                    "minwidth": 82
                }
            }, {
                name: "score",
                title: "Score",
                style: {
                    "font-size": "11px",
                    "maxWidth": 110
                },
                sortValue: function (val) { return Number(val.options.sortValue); }
            }, {
                name: "symbols",
                title: "Symbols" +
                        '<div class="sym-order-toggle">' +
                            '<br><span style="font-weight:normal;">Sort by:</span><br>' +
                            '<div class="btn-group btn-group-xs btn-sym-order-scan">' +
                                '<label type="button" class="btn btn-outline-secondary btn-sym-scan-magnitude">' +
                                    '<input type="radio" class="btn-check" value="magnitude">Magnitude</label>' +
                                '<label type="button" class="btn btn-outline-secondary btn-sym-scan-score">' +
                                    '<input type="radio" class="btn-check" value="score">Value</label>' +
                                '<label type="button" class="btn btn-outline-secondary btn-sym-scan-name">' +
                                    '<input type="radio" class="btn-check" value="name">Name</label>' +
                            "</div>" +
                        "</div>",
                breakpoints: "all",
                style: {
                    "font-size": "11px",
                    "width": 550,
                    "maxWidth": 550
                }
            }, {
                name: "time_real",
                title: "Scan time",
                breakpoints: "xs sm md",
                style: {
                    "font-size": "11px",
                    "maxWidth": 72
                },
                sortValue: function (val) { return Number(val); }
            }, {
                sorted: true,
                direction: "DESC",
                name: "time",
                title: "Time",
                style: {
                    "font-size": "11px"
                },
                sortValue: function (val) { return Number(val.options.sortValue); }
            }];
        }

        function get_server() {
            var checked_server = rspamd.getSelector("selSrv");
            return (checked_server === "All SERVERS") ? "local" : checked_server;
        }

        // @upload text
        function scanText(data, headers) {
            rspamd.query("checkv2", {
                data: data,
                params: {
                    processData: false,
                },
                method: "POST",
                headers: headers,
                success: function (neighbours_status) {
                    function scrollTop(rows_total) {
                        // Is there a way to get an event when all rows are loaded?
                        rspamd.waitForRowsDisplayed("scan", rows_total, function () {
                            $("#cleanScanHistory").removeAttr("disabled", true);
                            $("html, body").animate({
                                scrollTop: $("#scanResult").offset().top
                            }, 1000);
                        });
                    }

                    var json = neighbours_status[0].data;
                    if (json.action) {
                        rspamd.alertMessage("alert-success", "Data successfully scanned");

                        var rows_total = $("#historyTable_scan > tbody > tr:not(.footable-detail-row)").length + 1;
                        var o = rspamd.process_history_v2({rows:[json]}, "scan");
                        var items = o.items;
                        rspamd.symbols.scan.push(o.symbols[0]);

                        if (Object.prototype.hasOwnProperty.call(rspamd.tables, "scan")) {
                            rspamd.tables.scan.rows.load(items, true);
                            scrollTop(rows_total);
                        } else {
                            rspamd.destroyTable("scan");
                            require(["footable"], function () {
                                // Is there a way to get an event when the table is destroyed?
                                setTimeout(function () {
                                    rspamd.initHistoryTable(data, items, "scan", columns_v2(), true);
                                    scrollTop(rows_total);
                                }, 200);
                            });
                        }
                    } else {
                        rspamd.alertMessage("alert-error", "Cannot scan data");
                    }
                },
                errorMessage: "Cannot upload data",
                statusCode: {
                    404: function () {
                        rspamd.alertMessage("alert-error", "Cannot upload data, no server found");
                    },
                    500: function () {
                        rspamd.alertMessage("alert-error", "Cannot tokenize message: no text data");
                    },
                    503: function () {
                        rspamd.alertMessage("alert-error", "Cannot tokenize message: no text data");
                    }
                },
                server: get_server()
            });
        }

        function getFuzzyHashes(data) {
            function fillHashTable(rules) {
                $("#hashTable tbody").empty();
                for (const [rule, hashes] of Object.entries(rules)) {
                    hashes.forEach(function (hash, i) {
                        $("#hashTable tbody").append("<tr>" +
                          (i === 0 ? '<td rowspan="' + Object.keys(hashes).length + '">' + rule + "</td>" : "") +
                          "<td>" + hash + "</td></tr>");
                    });
                }
                $("#hash-card").slideDown();
            }

            rspamd.query("plugins/fuzzy/hashes?flag=" + $("#fuzzy-flag").val(), {
                data: data,
                params: {
                    processData: false,
                },
                method: "POST",
                success: function (neighbours_status) {
                    var json = neighbours_status[0].data;
                    if (json.success) {
                        rspamd.alertMessage("alert-success", "Message successfully processed");
                        fillHashTable(json.hashes);
                    } else {
                        rspamd.alertMessage("alert-error", "Unexpected error processing message");
                    }
                },
                server: get_server()
            });
        }


        rspamd.set_page_size("scan", $("#scan_page_size").val());
        rspamd.bindHistoryTableEventHandlers("scan", 3);

        $("#cleanScanHistory").off("click");
        $("#cleanScanHistory").on("click", function (e) {
            e.preventDefault();
            if (!confirm("Are you sure you want to clean scan history?")) { // eslint-disable-line no-alert
                return;
            }
            rspamd.destroyTable("scan");
            rspamd.symbols.scan.length = 0;
            $("#cleanScanHistory").attr("disabled", true);
        });

        function enable_disable_scan_btn() {
            $("#scan button:not(#cleanScanHistory, #scanOptionsToggle)").prop("disabled", ($.trim($("textarea").val()).length === 0));
        }
        enable_disable_scan_btn();
        $("textarea").on("input", function () {
            enable_disable_scan_btn();
        });

        $("#scanClean").on("click", function () {
            $("#scan button:not(#cleanScanHistory, #scanOptionsToggle)").attr("disabled", true);
            $("#scanForm")[0].reset();
            $("#scanResult").hide();
            $("#scanOutput tbody").remove();
            $("html, body").animate({scrollTop:0}, 1000);
            return false;
        });

        $(".card-close-btn").on("click", function () {
            $(this).closest(".card").slideUp();
        });

        $("[data-upload]").on("click", function () {
            var source = $(this).data("upload");
            var data = $("#scanMsgSource").val();
            var headers = {};
            if ($.trim(data).length > 0) {
                if (source === "scan") {
                    headers = ["IP", "User", "From", "Rcpt", "Helo", "Hostname"].reduce(function (o, header) {
                        var value = $("#scan-opt-" + header.toLowerCase()).val();
                        if (value !== "") o[header] = value;
                        return o;
                    }, {});
                    if ($("#scan-opt-pass-all").prop("checked")) headers.Pass = "all";
                    scanText(data, headers);
                } else if (source === "compute-fuzzy") {
                    getFuzzyHashes(data);
                } else {
                    if (source === "fuzzy") {
                        headers = {
                            flag: $("#fuzzyFlagText").val(),
                            weight: $("#fuzzyWeightText").val()
                        };
                    }
                    uploadText(data, source, headers);
                }
            } else {
                rspamd.alertMessage("alert-error", "Message source field cannot be blank");
            }
            return false;
        });

        return ui;
    });
