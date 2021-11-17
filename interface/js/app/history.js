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

/* global d3:false FooTable:false */

define(["jquery", "footable"],
    function ($) {
        "use strict";
        var ui = {};
        var prevVersion = null;

        function process_history_legacy(rspamd, data) {
            var items = [];

            var compare = function (e1, e2) {
                return e1.name.localeCompare(e2.name);
            };

            $("#selSymOrder_history, label[for='selSymOrder_history']").hide();

            $.each(data, function (i, item) {
                item.time = rspamd.unix_time_format(item.unix_time);
                rspamd.preprocess_item(rspamd, item);
                item.symbols = Object.keys(item.symbols)
                    .map(function (key) {
                        return item.symbols[key];
                    })
                    .sort(compare)
                    .map(function (e) { return e.name; })
                    .join(", ");
                item.time = {
                    value: rspamd.unix_time_format(item.unix_time),
                    options: {
                        sortValue: item.unix_time
                    }
                };

                items.push(item);
            });

            return {items:items};
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
                name: "ip",
                title: "IP address",
                breakpoints: "xs sm md",
                style: {
                    "font-size": "11px",
                    "minWidth": "calc(7.6em + 8px)",
                    "word-break": "break-all"
                }
            }, {
                name: "sender_mime",
                title: "[Envelope From] From",
                breakpoints: "xs sm md",
                style: {
                    "font-size": "11px",
                    "minWidth": 100,
                    "maxWidth": 200,
                    "word-wrap": "break-word"
                }
            }, {
                name: "rcpt_mime_short",
                title: "[Envelope To] To/Cc/Bcc",
                breakpoints: "xs sm md",
                style: {
                    "font-size": "11px",
                    "minWidth": 100,
                    "maxWidth": 200,
                    "word-wrap": "break-word"
                }
            }, {
                name: "rcpt_mime",
                title: "[Envelope To] To/Cc/Bcc",
                breakpoints: "all",
                style: {
                    "font-size": "11px",
                    "word-wrap": "break-word"
                }
            }, {
                name: "subject",
                title: "Subject",
                breakpoints: "xs sm md",
                style: {
                    "font-size": "11px",
                    "word-break": "break-all",
                    "minWidth": 150
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
                        '<div class="btn-group btn-group-toggle btn-group-xs btn-sym-order-history" data-toggle="buttons">' +
                            '<label type="button" class="btn btn-outline-secondary btn-sym-history-magnitude">' +
                                '<input type="radio" value="magnitude">Magnitude</label>' +
                            '<label type="button" class="btn btn-outline-secondary btn-sym-history-score">' +
                                '<input type="radio" value="score">Value</label>' +
                            '<label type="button" class="btn btn-outline-secondary btn-sym-history-name">' +
                                '<input type="radio" value="name">Name</label>' +
                        "</div>",
                breakpoints: "all",
                style: {
                    "font-size": "11px",
                    "width": 550,
                    "maxWidth": 550
                }
            }, {
                name: "size",
                title: "Msg size",
                breakpoints: "xs sm md",
                style: {
                    "font-size": "11px",
                    "minwidth": 50,
                },
                formatter: d3.format(".3~s")
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
            }, {
                name: "user",
                title: "Authenticated user",
                breakpoints: "xs sm md",
                style: {
                    "font-size": "11px",
                    "minWidth": 100,
                    "maxWidth": 130,
                    "word-wrap": "break-word"
                }
            }];
        }

        function columns_legacy() {
            return [{
                name: "id",
                title: "ID",
                style: {
                    "font-size": "11px",
                    "width": 300,
                    "maxWidth": 300,
                    "overflow": "hidden",
                    "textOverflow": "ellipsis",
                    "wordBreak": "keep-all",
                    "whiteSpace": "nowrap"
                }
            }, {
                name: "ip",
                title: "IP address",
                breakpoints: "xs sm",
                style: {
                    "font-size": "11px",
                    "width": 150,
                    "maxWidth": 150
                }
            }, {
                name: "action",
                title: "Action",
                style: {
                    "font-size": "11px",
                    "width": 110,
                    "maxWidth": 110
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
                title: "Symbols",
                breakpoints: "all",
                style: {
                    "font-size": "11px",
                    "width": 550,
                    "maxWidth": 550
                }
            }, {
                name: "size",
                title: "Message size",
                breakpoints: "xs sm",
                style: {
                    "font-size": "11px",
                    "width": 120,
                    "maxWidth": 120
                },
                formatter: d3.format(".3~s")
            }, {
                name: "scan_time",
                title: "Scan time",
                breakpoints: "xs sm",
                style: {
                    "font-size": "11px",
                    "maxWidth": 80
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
            }, {
                name: "user",
                title: "Authenticated user",
                breakpoints: "xs sm",
                style: {
                    "font-size": "11px",
                    "width": 200,
                    "maxWidth": 200
                }
            }];
        }

        var columns = {
            2: columns_v2,
            legacy: columns_legacy
        };

        function process_history_data(rspamd, data) {
            var process_functions = {
                2: rspamd.process_history_v2,
                legacy: process_history_legacy
            };
            var pf = process_functions.legacy;

            if (data.version) {
                var strkey = data.version.toString();
                if (process_functions[strkey]) {
                    pf = process_functions[strkey];
                }
            }

            return pf(rspamd, data, "history");
        }

        function get_history_columns(data) {
            var func = columns.legacy;

            if (data.version) {
                var strkey = data.version.toString();
                if (columns[strkey]) {
                    func = columns[strkey];
                }
            }

            return func();
        }

        ui.getHistory = function (rspamd, tables) {
            rspamd.query("history", {
                success: function (req_data) {
                    function differentVersions(neighbours_data) {
                        var dv = neighbours_data.some(function (e) {
                            return e.version !== neighbours_data[0].version;
                        });
                        if (dv) {
                            rspamd.alertMessage("alert-error",
                                "Neighbours history backend versions do not match. Cannot display history.");
                            return true;
                        }
                        return false;
                    }

                    var neighbours_data = req_data
                        .filter(function (d) { return d.status; }) // filter out unavailable neighbours
                        .map(function (d) { return d.data; });
                    if (neighbours_data.length && !differentVersions(neighbours_data)) {
                        var data = {};
                        var version = neighbours_data[0].version;
                        if (version) {
                            data.rows = [].concat.apply([], neighbours_data
                                .map(function (e) {
                                    return e.rows;
                                }));
                            data.version = version;
                        } else {
                            // Legacy version
                            data = [].concat.apply([], neighbours_data);
                        }
                        var o = process_history_data(rspamd, data);
                        var items = o.items;
                        rspamd.symbols.history = o.symbols;

                        if (Object.prototype.hasOwnProperty.call(tables, "history") &&
                            version === prevVersion) {
                            tables.history.rows.load(items);
                        } else {
                            rspamd.destroyTable("history");
                            // Is there a way to get an event when the table is destroyed?
                            setTimeout(function () {
                                rspamd.initHistoryTable(rspamd, data, items, "history", get_history_columns(data), false);
                            }, 200);
                        }
                        prevVersion = version;
                    } else {
                        rspamd.destroyTable("history");
                    }
                },
                complete: function () { $("#refresh").removeAttr("disabled").removeClass("disabled"); },
                errorMessage: "Cannot receive history",
            });
        };

        ui.setup = function (rspamd, tables) {
            rspamd.set_page_size("history", $("#history_page_size").val());
            rspamd.bindHistoryTableEventHandlers("history", 8);

            $("#updateHistory").off("click");
            $("#updateHistory").on("click", function (e) {
                e.preventDefault();
                ui.getHistory(rspamd, tables);
            });

            // @reset history log
            $("#resetHistory").off("click");
            $("#resetHistory").on("click", function (e) {
                e.preventDefault();
                if (!confirm("Are you sure you want to reset history log?")) { // eslint-disable-line no-alert
                    return;
                }
                rspamd.destroyTable("history");
                rspamd.destroyTable("errors");

                rspamd.query("historyreset", {
                    success: function () {
                        ui.getHistory(rspamd, tables);
                        ui.getErrors(rspamd, tables);
                    },
                    errorMessage: "Cannot reset history log"
                });
            });
        };

        function initErrorsTable(rspamd, tables, rows) {
            tables.errors = FooTable.init("#errorsLog", {
                columns: [
                    {
                        sorted: true,
                        direction: "DESC",
                        name: "ts",
                        title: "Time",
                        style: {"font-size": "11px", "width": 300, "maxWidth": 300},
                        sortValue: function (val) { return Number(val.options.sortValue); }
                    },
                    {name:"type", title:"Worker type", breakpoints:"xs sm", style:{"font-size":"11px", "width":150, "maxWidth":150}},
                    {name:"pid", title:"PID", breakpoints:"xs sm", style:{"font-size":"11px", "width":110, "maxWidth":110}},
                    {name:"module", title:"Module", style:{"font-size":"11px"}},
                    {name:"id", title:"Internal ID", style:{"font-size":"11px"}},
                    {name:"message", title:"Message", breakpoints:"xs sm", style:{"font-size":"11px"}},
                ],
                rows: rows,
                paging: {
                    enabled: true,
                    limit: 5,
                    size: rspamd.page_size.errors
                },
                filtering: {
                    enabled: true,
                    position: "left",
                    connectors: false
                },
                sorting: {
                    enabled: true
                }
            });
        }

        ui.getErrors = function (rspamd, tables) {
            if (rspamd.read_only) return;

            rspamd.query("errors", {
                success: function (data) {
                    var neighbours_data = data
                        .filter(function (d) {
                            return d.status;
                        }) // filter out unavailable neighbours
                        .map(function (d) {
                            return d.data;
                        });
                    var rows = [].concat.apply([], neighbours_data);
                    $.each(rows, function (i, item) {
                        item.ts = {
                            value: rspamd.unix_time_format(item.ts),
                            options: {
                                sortValue: item.ts
                            }
                        };
                    });
                    if (Object.prototype.hasOwnProperty.call(tables, "errors")) {
                        tables.errors.rows.load(rows);
                    } else {
                        initErrorsTable(rspamd, tables, rows);
                    }
                }
            });

            $("#updateErrors").off("click");
            $("#updateErrors").on("click", function (e) {
                e.preventDefault();
                ui.getErrors(rspamd, tables);
            });
        };

        return ui;
    });
