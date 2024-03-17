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

/* global FooTable */

define(["jquery", "app/common", "app/libft", "footable"],
    ($, common, libft) => {
        "use strict";
        const ui = {};
        let prevVersion = null;

        function process_history_legacy(data) {
            const items = [];

            function compare(e1, e2) { return e1.name.localeCompare(e2.name); }

            $("#selSymOrder_history, label[for='selSymOrder_history']").hide();

            $.each(data, (i, item) => {
                item.time = libft.unix_time_format(item.unix_time);
                libft.preprocess_item(item);
                item.symbols = Object.keys(item.symbols)
                    .map((key) => item.symbols[key])
                    .sort(compare)
                    .map((e) => e.name)
                    .join(", ");
                item.time = {
                    value: libft.unix_time_format(item.unix_time),
                    options: {
                        sortValue: item.unix_time
                    }
                };

                items.push(item);
            });

            return {items: items};
        }

        function columns_legacy() {
            return [{
                name: "id",
                title: "ID",
                style: {
                    width: 300,
                    maxWidth: 300,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    wordBreak: "keep-all",
                    whiteSpace: "nowrap"
                }
            }, {
                name: "ip",
                title: "IP address",
                breakpoints: "sm",
                style: {width: 150, maxWidth: 150}
            }, {
                name: "action",
                title: "Action",
                style: {width: 110, maxWidth: 110}
            }, {
                name: "score",
                title: "Score",
                style: {maxWidth: 110},
                sortValue: function (val) { return Number(val.options.sortValue); }
            }, {
                name: "symbols",
                title: "Symbols",
                breakpoints: "all",
                style: {width: 550, maxWidth: 550}
            }, {
                name: "size",
                title: "Message size",
                breakpoints: "sm",
                style: {width: 120, maxWidth: 120},
                formatter: libft.formatBytesIEC
            }, {
                name: "scan_time",
                title: "Scan time",
                breakpoints: "sm",
                style: {maxWidth: 80},
                sortValue: function (val) { return Number(val); }
            }, {
                sorted: true,
                direction: "DESC",
                name: "time",
                title: "Time",
                sortValue: function (val) { return Number(val.options.sortValue); }
            }, {
                name: "user",
                title: "Authenticated user",
                breakpoints: "sm",
                style: {width: 200, maxWidth: 200}
            }];
        }

        const columns = {
            2: libft.columns_v2("history"),
            legacy: columns_legacy()
        };

        function process_history_data(data) {
            const process_functions = {
                2: libft.process_history_v2,
                legacy: process_history_legacy
            };
            let pf = process_functions.legacy;

            if (data.version) {
                const strkey = data.version.toString();
                if (process_functions[strkey]) {
                    pf = process_functions[strkey];
                }
            }

            return pf(data, "history");
        }

        function get_history_columns(data) {
            let func = columns.legacy;

            if (data.version) {
                const strkey = data.version.toString();
                if (columns[strkey]) {
                    func = columns[strkey];
                }
            }

            return func;
        }

        ui.getHistory = function () {
            $("#refresh, #updateHistory").attr("disabled", true);
            common.query("history", {
                success: function (req_data) {
                    function differentVersions(neighbours_data) {
                        const dv = neighbours_data.some((e) => e.version !== neighbours_data[0].version);
                        if (dv) {
                            common.alertMessage("alert-error",
                                "Neighbours history backend versions do not match. Cannot display history.");
                            return true;
                        }
                        return false;
                    }

                    const neighbours_data = req_data
                        .filter((d) => d.status) // filter out unavailable neighbours
                        .map((d) => d.data);
                    if (neighbours_data.length && !differentVersions(neighbours_data)) {
                        let data = {};
                        const [{version}] = neighbours_data;
                        if (version) {
                            data.rows = [].concat.apply([], neighbours_data
                                .map((e) => e.rows));
                            data.version = version;
                            $("#legacy-history-badge").hide();
                        } else {
                            // Legacy version
                            data = [].concat.apply([], neighbours_data);
                            $("#legacy-history-badge").show();
                        }
                        const o = process_history_data(data);
                        const {items} = o;
                        common.symbols.history = o.symbols;

                        if (Object.prototype.hasOwnProperty.call(common.tables, "history") &&
                            version === prevVersion) {
                            common.tables.history.rows.load(items);
                        } else {
                            libft.destroyTable("history");
                            // Is there a way to get an event when the table is destroyed?
                            setTimeout(() => {
                                libft.initHistoryTable(data, items, "history", get_history_columns(data), false,
                                    () => $("#refresh, #updateHistory, #history .ft-columns-dropdown .btn-dropdown-apply")
                                        .removeAttr("disabled"));
                            }, 200);
                        }
                        prevVersion = version;
                    } else {
                        libft.destroyTable("history");
                    }
                },
                error: () => $("#refresh, #updateHistory").removeAttr("disabled"),
                errorMessage: "Cannot receive history",
            });
        };

        function initErrorsTable(rows) {
            common.tables.errors = FooTable.init("#errorsLog", {
                cascade: true,
                columns: [
                    {sorted: true,
                        direction: "DESC",
                        name: "ts",
                        title: "Time",
                        style: {width: 300, maxWidth: 300},
                        sortValue: function (val) { return Number(val.options.sortValue); }},
                    {name: "type",
                        title: "Worker type",
                        breakpoints: "sm",
                        style: {width: 150, maxWidth: 150}},
                    {name: "pid",
                        title: "PID",
                        breakpoints: "sm",
                        style: {width: 110, maxWidth: 110}},
                    {name: "module", title: "Module"},
                    {name: "id", title: "Internal ID"},
                    {name: "message", title: "Message", breakpoints: "sm"},
                ],
                rows: rows,
                paging: {
                    enabled: true,
                    limit: 5,
                    size: common.page_size.errors
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

        ui.getErrors = function () {
            if (common.read_only) return;

            common.query("errors", {
                success: function (data) {
                    const neighbours_data = data
                        .filter((d) => d.status) // filter out unavailable neighbours
                        .map((d) => d.data);
                    const rows = [].concat.apply([], neighbours_data);
                    $.each(rows, (i, item) => {
                        item.ts = {
                            value: libft.unix_time_format(item.ts),
                            options: {
                                sortValue: item.ts
                            }
                        };
                    });
                    if (Object.prototype.hasOwnProperty.call(common.tables, "errors")) {
                        common.tables.errors.rows.load(rows);
                    } else {
                        initErrorsTable(rows);
                    }
                }
            });

            $("#updateErrors").off("click");
            $("#updateErrors").on("click", (e) => {
                e.preventDefault();
                ui.getErrors();
            });
        };


        libft.set_page_size("history", $("#history_page_size").val());
        libft.bindHistoryTableEventHandlers("history", 8);

        $("#updateHistory").off("click");
        $("#updateHistory").on("click", (e) => {
            e.preventDefault();
            ui.getHistory();
        });

        // @reset history log
        $("#resetHistory").off("click");
        $("#resetHistory").on("click", (e) => {
            e.preventDefault();
            if (!confirm("Are you sure you want to reset history log?")) { // eslint-disable-line no-alert
                return;
            }
            libft.destroyTable("history");
            libft.destroyTable("errors");

            common.query("historyreset", {
                success: function () {
                    ui.getHistory();
                    ui.getErrors();
                },
                errorMessage: "Cannot reset history log"
            });
        });

        return ui;
    });
