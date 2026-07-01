/*
 * Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>
 */

define(["jquery", "app/common", "app/libft", "app/tab-utils", "tabulator"],
    ($, common, libft, tabUtils, Tabulator) => {
        "use strict";
        const ui = {};
        let prevVersion = null;

        // History range: offset and count
        const histFromDef = 0;
        const historyCountDef = 1000;
        let histFrom = histFromDef;
        let histCount = parseInt(localStorage.getItem("historyCount"), 10) || historyCountDef;

        function process_history_legacy(data) {
            const items = [];

            function compare(e1, e2) { return e1.name.localeCompare(e2.name); }

            common.hide("#selSymOrder_history, label[for='selSymOrder_history']");

            $.each(data, (i, item) => {
                libft.preprocess_item(item);
                item.symbols = Object.keys(item.symbols)
                    .map((key) => item.symbols[key])
                    .sort(compare)
                    .map((e) => e.name)
                    .join(", ");
                item.time = item.unix_time;

                items.push(item);
            });

            return {items: items};
        }

        function columns_legacy() {
            return [{
                formatter: "responsiveCollapse",
                width: 23,
                minWidth: 23,
                responsive: 0,
                hozAlign: "center",
                resizable: false,
                headerSort: false,
            }, {
                title: "ID",
                field: "id",
                responsive: 0,
                minWidth: 300,
            }, {
                title: "IP address",
                field: "ip",
                responsive: 2,
                minWidth: 98,
                width: 98,
            }, {
                title: "Action",
                field: "action",
                responsive: 0,
                minWidth: 110,
                width: 110,
            }, {
                title: "Score",
                field: "score",
                responsive: 0,
                sorter: "number",
                minWidth: 110,
                width: 110,
            }, {
                title: "Symbols",
                field: "symbols",
                formatter: "html",
                // responsive:100 collapses first; the large minWidth forces
                // overflow at any realistic width so symbols always renders in
                // the detail row.
                responsive: 100,
                minWidth: 4000,
            }, {
                title: "Message size",
                field: "size",
                responsive: 2,
                sorter: "number",
                formatter: (cell) => libft.formatBytesIEC(cell.getValue()),
                minWidth: 120,
                width: 120,
            }, {
                title: "Scan time",
                field: "scan_time",
                responsive: 2,
                sorter: "number",
                minWidth: 80,
                width: 80,
            }, {
                title: "Time",
                field: "time",
                responsive: 0,
                sorter: "number",
                formatter: (cell) => libft.unix_time_format(cell.getValue()),
                minWidth: 130,
                width: 130,
            }, {
                title: "Authenticated user",
                field: "user",
                responsive: 2,
                minWidth: 200,
                width: 200,
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
            const histTo = histFrom - 1 + histCount;
            common.query(`history?from=${histFrom}&to=${histTo}`, {
                success: function (req_data) {
                    function differentVersions(neighbours_data) {
                        const dv = neighbours_data.some((e) => e.version !== neighbours_data[0].version);
                        if (dv) {
                            common.logError({
                                server: "Multi-server",
                                endpoint: "history",
                                message: "Neighbours history backend versions do not match. Cannot display history.",
                                errorType: "data_inconsistency"
                            });
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
                            common.hide("#legacy-history-badge");
                        } else {
                            // Legacy version
                            data = [].concat.apply([], neighbours_data);
                            common.show("#legacy-history-badge");
                        }
                        const o = process_history_data(data);
                        const {items} = o;
                        common.symbols.history = o.symbols;

                        if (Object.prototype.hasOwnProperty.call(common.tables, "history") &&
                            version === prevVersion) {
                            common.tables.history.setData(items);
                        } else {
                            libft.destroyTable("history");
                            libft.initHistoryTable(data, items, "history", get_history_columns(data), false,
                                () => {
                                    $("#history .ft-columns-dropdown .btn-dropdown-apply").removeAttr("disabled");
                                    ui.updateHistoryControlsState();
                                    if (version) libft.bindFuzzyHashButtons("history");
                                });
                        }
                        prevVersion = version;
                    } else {
                        libft.destroyTable("history");
                    }
                },
                error: () => ui.updateHistoryControlsState(),
                errorMessage: "Cannot receive history",
            });
        };

        function initErrorsTable(rows) {
            common.tables.errors = new Tabulator("#errorsLog", {
                layout: "fitColumns",
                responsiveLayout: "collapse",
                responsiveLayoutCollapseStartOpen: false,
                // Values are HTML-escaped upstream (getErrors); render as HTML so
                // entities decode instead of showing literally via "plaintext".
                columnDefaults: {formatter: "html"},
                selectable: false,
                pagination: "local",
                paginationSize: common.page_size.errors,
                paginationButtonCount: 5,
                data: rows,
                initialSort: [{column: "ts", dir: "desc"}],
                columns: [
                    {
                        // Toggle to expand collapsed (responsive) columns
                        formatter: "responsiveCollapse",
                        width: 23,
                        minWidth: 23,
                        responsive: 0,
                        hozAlign: "center",
                        resizable: false,
                        headerSort: false,
                    },
                    {
                        title: "Time",
                        field: "ts",
                        sorter: "number",
                        minWidth: 105,
                        width: 130,
                        formatter: (cell) => libft.unix_time_format(cell.getValue()),
                    },
                    {
                        title: "Worker type",
                        field: "type",
                        responsive: 4,
                        width: 110,
                        minWidth: 110,
                        headerFilter: "input",
                    },
                    {
                        title: "PID",
                        field: "pid",
                        sorter: "number",
                        responsive: 5,
                        width: 50,
                        minWidth: 50,
                        headerFilter: "input",
                    },
                    {title: "Module", field: "module", responsive: 4, width: 120, minWidth: 85, headerFilter: "input"},
                    {title: "Internal ID", field: "id", responsive: 3, width: 100, minWidth: 100, headerFilter: "input"},
                    {
                        title: "Message",
                        field: "message",
                        responsive: 0,
                        minWidth: 300,
                        widthGrow: 2,
                        headerFilter: "input",
                    },
                ],
            });

            // Common Tabulator UI setup (helpers in libft.js).
            tabUtils.hideFooterOnSinglePage("errors");
            tabUtils.stripTableholderTabindex("errors");
            tabUtils.bindRowClickToggle("errors");
            tabUtils.patchScrollIntoViewOnce();
            tabUtils.installScrollPreservation("errors", {
                armTriggers: [document.getElementById("updateErrors")].filter(Boolean),
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
                        for (const prop in item) {
                            if (!{}.hasOwnProperty.call(item, prop)) continue;
                            if (typeof item[prop] === "string") item[prop] = common.escapeHTML(item[prop]);
                        }
                    });
                    if (Object.prototype.hasOwnProperty.call(common.tables, "errors")) {
                        common.tables.errors.setData(rows);
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

        ui.updateHistoryControlsState = function () {
            const from = parseInt($("#history-from").val(), 10);
            const count = parseInt($("#history-count").val(), 10);
            const valid = !(isNaN(from) || from < 0 || isNaN(count) || count < 1);

            if (valid) {
                $("#refresh, #updateHistory").removeAttr("disabled").removeClass("disabled");
            } else {
                $("#refresh, #updateHistory").attr("disabled", true).addClass("disabled");
            }
        };

        function validateAndClampInput(el) {
            const min = el.id === "history-from" ? 0 : 1;
            let v = parseInt(el.value, 10);
            if (isNaN(v) || v < min) {
                v = min;
                $(el).addClass("is-invalid");
            } else {
                $(el).removeClass("is-invalid");
            }
            return v;
        }

        $("#history-from").val(histFrom);
        $("#history-count").val(histCount);
        $("#history-from, #history-count").on("input", (e) => {
            validateAndClampInput(e.currentTarget);
            ui.updateHistoryControlsState();
        });
        $("#history-from, #history-count").on("blur", (e) => {
            const el = e.currentTarget;
            const v = validateAndClampInput(el);
            $(el).val(v).removeClass("is-invalid");
            ui.updateHistoryControlsState();
        });
        $("#history-from,#history-count").on("change", () => {
            histFrom = parseInt($("#history-from").val(), 10) || histFromDef;
            histCount = parseInt($("#history-count").val(), 10) || historyCountDef;
        });

        libft.set_page_size("history", $("#history_page_size").val());
        libft.bindHistoryTableEventHandlers("history", 9);

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
