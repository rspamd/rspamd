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

define(["jquery"],
    function ($) {
        "use strict";
        var ui = {};

        function cleanTextUpload(source) {
            $("#" + source + "TextSource").val("");
        }

        // @upload text
        function uploadText(rspamd, data, source, headers) {
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
                }
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
                title: "Symbols<br /><br />" +
                        '<span style="font-weight:normal;">Sort by:</span><br />' +
                        '<div class="btn-group btn-group-toggle btn-group-xs btn-sym-order-scan" data-toggle="buttons">' +
                            '<label type="button" class="btn btn-outline-secondary btn-sym-scan-magnitude">' +
                                '<input type="radio" value="magnitude">Magnitude</label>' +
                            '<label type="button" class="btn btn-outline-secondary btn-sym-scan-score">' +
                                '<input type="radio" value="score">Value</label>' +
                            '<label type="button" class="btn btn-outline-secondary btn-sym-scan-name">' +
                                '<input type="radio" value="name">Name</label>' +
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

        // @upload text
        function scanText(rspamd, tables, data, server) {
            rspamd.query("checkv2", {
                data: data,
                params: {
                    processData: false,
                },
                method: "POST",
                success: function (neighbours_status) {
                    function scrollTop(rows_total) {
                        // Is there a way to get an event when all rows are loaded?
                        rspamd.waitForRowsDisplayed("scan", rows_total, function () {
                            $("html, body").animate({
                                scrollTop: $("#scanResult").offset().top
                            }, 1000);
                        });
                    }

                    var json = neighbours_status[0].data;
                    if (json.action) {
                        rspamd.alertMessage("alert-success", "Data successfully scanned");

                        var rows_total = $("#historyTable_scan > tbody > tr:not(.footable-detail-row)").length + 1;
                        var o = rspamd.process_history_v2(rspamd, {rows:[json]}, "scan");
                        var items = o.items;
                        rspamd.symbols.scan.push(o.symbols[0]);

                        if (Object.prototype.hasOwnProperty.call(tables, "scan")) {
                            tables.scan.rows.load(items, true);
                            scrollTop(rows_total);
                        } else {
                            rspamd.destroyTable("scan");
                            // Is there a way to get an event when the table is destroyed?
                            setTimeout(function () {
                                rspamd.initHistoryTable(rspamd, data, items, "scan", columns_v2(), true);
                                scrollTop(rows_total);
                            }, 200);
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
                server: server
            });
        }

        ui.setup = function (rspamd, tables) {
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
            });

            function enable_disable_scan_btn() {
                $("#scan button").prop("disabled", ($.trim($("textarea").val()).length === 0));
            }
            enable_disable_scan_btn();
            $("textarea").on("input", function () {
                enable_disable_scan_btn();
            });

            $("#scanClean").on("click", function () {
                $("#scan button").attr("disabled", true);
                $("#scanMsgSource").val("");
                $("#scanResult").hide();
                $("#scanOutput tbody").remove();
                $("html, body").animate({scrollTop:0}, 1000);
                return false;
            });
            // @init upload
            $("[data-upload]").on("click", function () {
                var source = $(this).data("upload");
                var data = $("#scanMsgSource").val();
                var headers = (source === "fuzzy")
                    ? {
                        flag: $("#fuzzyFlagText").val(),
                        weight: $("#fuzzyWeightText").val()
                    }
                    : {};
                if ($.trim(data).length > 0) {
                    if (source === "scan") {
                        var checked_server = rspamd.getSelector("selSrv");
                        var server = (checked_server === "All SERVERS") ? "local" : checked_server;
                        scanText(rspamd, tables, data, server);
                    } else {
                        uploadText(rspamd, data, source, headers);
                    }
                } else {
                    rspamd.alertMessage("alert-error", "Message source field cannot be blank");
                }
                return false;
            });
        };


        return ui;
    });
