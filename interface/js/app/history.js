/*
 * Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>
 */

define(["jquery", "app/common", "app/libft", "tabulator"],
    ($, common, libft, Tabulator) => {
        "use strict";
        const ui = {};
        let prevVersion = null;
        let scrollIntoViewPatched = false;

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
                breakpoints: "md",
                style: {width: 150, maxWidth: 150}
            }, {
                name: "action",
                title: "Action",
                style: {width: 110, maxWidth: 110}
            }, {
                name: "score",
                title: "Score",
                style: {maxWidth: 110},
                sortValue: (val) => Number(val.options.sortValue)
            }, {
                name: "symbols",
                title: "Symbols",
                breakpoints: "all",
                style: {width: 550, maxWidth: 550}
            }, {
                name: "size",
                title: "Message size",
                breakpoints: "md",
                style: {width: 120, maxWidth: 120},
                formatter: libft.formatBytesIEC
            }, {
                name: "scan_time",
                title: "Scan time",
                breakpoints: "md",
                style: {maxWidth: 80},
                sortValue: (val) => Number(val)
            }, {
                sorted: true,
                direction: "DESC",
                name: "time",
                title: "Time",
                sortValue: (val) => Number(val.options.sortValue)
            }, {
                name: "user",
                title: "Authenticated user",
                breakpoints: "md",
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
                            common.tables.history.rows.load(items);
                        } else {
                            libft.destroyTable("history").then(() => {
                                libft.initHistoryTable(data, items, "history", get_history_columns(data), false,
                                    () => {
                                        $("#history .ft-columns-dropdown .btn-dropdown-apply").removeAttr("disabled");
                                        ui.updateHistoryControlsState();
                                        if (version) libft.bindFuzzyHashButtons("history");
                                    });
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
                        width: 36,
                        minWidth: 36,
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

            // Scroll-prevention state (shared by the click/renderStarted/scroll
            // handlers below).
            let preserveY = 0;
            let preserveUntil = 0;
            let clickArmed = false;

            // FooTable parity: hide the pagination footer when only one page.
            // renderComplete fires after data load, filtering and sorting,
            // when getPageMax() is up to date. Also clears clickArmed so that
            // non-click renders (initial load, filter) don't extend the scroll-
            // prevention window with a stale preserveY.
            common.tables.errors.on("renderComplete", () => {
                const footer = common.tables.errors.element.querySelector(".tabulator-footer");
                if (footer) footer.style.display = common.tables.errors.getPageMax() > 1 ? "" : "none";
                clickArmed = false;
            });

            // Clicking a body cell focuses the tableholder (tabindex=0), and the
            // browser scrolls it into view — for a tall table that shifts the page
            // ~one viewport (the "expand flicker"). The tiny toggle icon is
            // in-view so out-of-the-box it never happened; clicking anywhere on
            // the row exposes it. Strip the tableholder's tabindex and keep it
            // stripped (Tabulator may re-add it).
            const errorsHolder = common.tables.errors.element.querySelector(".tabulator-tableholder");
            if (errorsHolder) {
                errorsHolder.removeAttribute("tabindex");
                new MutationObserver(() => errorsHolder.removeAttribute("tabindex"))
                    .observe(errorsHolder, {attributes: true, attributeFilter: ["tabindex"]});
            }

            // Toggle responsive-collapse by clicking anywhere on the row (not
            // just the tiny toggle icon). The toggle's own handler calls
            // stopImmediatePropagation, so clicks on the icon don't bubble here
            // (no double-toggle). Skip while selecting/copying text.
            common.tables.errors.element.addEventListener("click", (e) => {
                const row = e.target.closest(".tabulator-row");
                if (!row) return;
                const sel = window.getSelection && window.getSelection();
                if (sel && sel.toString()) return;
                const toggle = row.querySelector(".tabulator-responsive-collapse-toggle");
                // Only toggle when collapse is active (toggle column is visible).
                // On a wide screen there are no collapsed columns and the toggle
                // is hidden — clicking it would otherwise pre-mark the row as
                // expanded, so it shows open when the screen is later narrowed.
                if (toggle && toggle.offsetParent) toggle.click();
            });

            // Neutralize scrollIntoView for elements in the errors table.
            // Tabulator smooth-scrolls the focused/expanded element into view
            // (scrollIntoView {behavior:"smooth"}); a smooth animation spans many
            // frames, so it can't be countered before paint without flickering.
            // No-op it for elements inside the current errors table. Guarded so
            // it patches the prototype only once (even if initErrorsTable runs
            // again); uses common.tables.errors.element (live) so a re-created
            // table is picked up without re-patching.
            if (!scrollIntoViewPatched) {
                const nativeScrollIntoView = Element.prototype.scrollIntoView;
                Element.prototype.scrollIntoView = function (...args) {
                    const el = common.tables.errors && common.tables.errors.element;
                    if (!(el && el.contains(this))) {
                        nativeScrollIntoView.apply(this, args);
                    }
                };
                scrollIntoViewPatched = true;
            }

            // Tabulator scrolls the page on clicks/sort/expand and after Update.
            // Restore the position synchronously in the scroll handler (capture,
            // before paint) so the jump is never painted. Both clicks use a 250ms
            // window for sync scrolls; async renders (Update's fetch → setData)
            // are covered by renderStarted, which extends the window — no fixed
            // timeout, so even a slow response is handled.
            function arm(ms) {
                return () => {
                    const y = window.scrollY;
                    preserveY = y;
                    preserveUntil = performance.now() + ms;
                    clickArmed = true;
                    Promise.resolve().then(() => {
                        // Microtask (after sync handlers, before paint): catch
                        // synchronous scrolls.
                        if (window.scrollY !== y) window.scrollTo(0, y);
                        // This rAF is queued from the microtask, so it lands AFTER
                        // Tabulator's render rAF (queued during the click). It
                        // runs in the same frame, after the render-scroll but
                        // before paint — catching the async expand-scroll without
                        // the 1-frame flicker that the scroll-event handler (one
                        // frame later) would cause.
                        requestAnimationFrame(() => {
                            if (window.scrollY !== y) window.scrollTo(0, y);
                        });
                    });
                };
            }
            common.tables.errors.element.addEventListener("click", arm(250), true);
            const updateBtn = document.getElementById("updateErrors");
            if (updateBtn) updateBtn.addEventListener("click", arm(250), true);
            // Async renders (e.g., Update's fetch → setData) fire renderStarted
            // after the click's window expires. Extend it (if a click recently
            // armed) to catch the render-scroll. clickArmed is cleared on
            // renderComplete (above) so non-click renders don't extend with a
            // stale preserveY.
            common.tables.errors.on("renderStarted", () => {
                if (clickArmed) preserveUntil = performance.now() + 400;
            });
            window.addEventListener("scroll", () => {
                if (performance.now() >= preserveUntil) return;
                if (window.scrollY !== preserveY) window.scrollTo(0, preserveY);
            }, true);
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
