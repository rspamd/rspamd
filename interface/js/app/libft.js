define(["app/common", "bootstrap", "app/tab-utils", "tabulator"],
    (common, bootstrap, tabUtils, Tabulator) => {
        "use strict";
        const ui = {};
        const columnsCustom = JSON.parse(localStorage.getItem("columns")) || {};

        // responsive:100 alone only collapses a column when the table already
        // overflows the viewport; pairing it with a very large minWidth forces
        // the overflow, so the column always renders in the detail row ("Row"
        // mode). Same trick the symbols/rcpt_mime columns use by default.
        const FORCE_COLLAPSE_MIN_WIDTH = 4000;

        let pageSizeTimerId = null;

        // Per-selector cleanups for the delegated fuzzy-hash button handlers,
        // so rebinding (on every scan/history render) removes the previous
        // listener. Keys are selectors embedding the table name, which assumes
        // table names are unique (two tables cannot share a DOM id anyway).
        const fuzzyCleanups = new Map();

        // bindHistoryTableEventHandlers binds to static elements that survive
        // table rebuilds, so it must run at most once per table — a repeat call
        // would stack change/click listeners. (The original .unbind() only
        // deduped selSymOrder; this guard covers all three bindings.)
        const boundSymOrderTables = new Set();

        function get_compare_function(table) {
            const compare_functions = {
                magnitude: function (e1, e2) {
                    return Math.abs(e2.score) - Math.abs(e1.score);
                },
                name: function (e1, e2) {
                    return e1.name.localeCompare(e2.name);
                },
                score: function (e1, e2) {
                    return e2.score - e1.score;
                }
            };

            return compare_functions[common.getSelector("selSymOrder_" + table)];
        }

        function sort_symbols(o, compare_function) {
            return Object.keys(o)
                .map((key) => o[key])
                .sort(compare_function)
                .map((e) => e.str)
                .join("<br>\n");
        }

        // Highlight the active symbol-order button for a table. The buttons are
        // part of the symbols column title, which is rendered inside each row's
        // collapsed detail, so they are recreated on every render — call this
        // after each build/render, not at handler bind time.
        function setActiveSymOrderButton(table, order) {
            const active = order || common.getSelector("selSymOrder_" + table);
            if (!active) return;
            // The buttons are rendered inside each row's collapsed detail, so
            // there are many instances — set active on all of them.
            document.querySelectorAll(".btn-sym-" + table + "-" + active).forEach((btn) => {
                btn.classList.add("active");
                Array.from(btn.parentElement.children).forEach((sib) => {
                    if (sib !== btn) sib.classList.remove("active");
                });
            });
        }

        function ipSorter(a, b) {
            function norm(ip) {
                return (typeof ip === "string" ? ip.split(".").map((x) => x.padStart(3, "0")).join("") : "0");
            }
            return norm(a).localeCompare(norm(b));
        }

        // ── Action filter for history/scan tables ─────────────────────────────

        const actionValues = ["reject", "add header", "greylist", "no action", "soft reject", "rewrite subject"];

        function actionHeaderFilter(cell, onRendered, success) {
            const container = document.createElement("div");
            container.style.display = "flex";
            container.style.gap = "4px";
            container.style.alignItems = "center";

            const select = document.createElement("select");
            select.className = "form-select form-select-sm";
            select.appendChild(new Option("Any action", ""));
            actionValues.forEach((a) => select.appendChild(new Option(a, a)));

            const notLabel = document.createElement("label");
            notLabel.style.whiteSpace = "nowrap";
            notLabel.title = "Invert action match";
            const not = document.createElement("input");
            not.type = "checkbox";
            notLabel.append(not, " not");

            container.append(notLabel, select);

            function onChange() {
                if (!select.value) {
                    success(false);
                } else {
                    success({action: select.value, not: not.checked});
                }
            }
            select.addEventListener("change", onChange);
            not.addEventListener("change", onChange);

            return container;
        }

        function actionFilterFunc(filterVal, cellVal) {
            if (!filterVal || !filterVal.action) return true;
            const match = cellVal === filterVal.action;
            return filterVal.not ? !match : match;
        }

        // ── Column formatters ────────────────────────────────────────────────

        function actionFormatter(cell) {
            const action = cell.getValue();
            const cls = {
                "clean": "success",
                "no action": "success",
                "rewrite subject": "warning",
                "add header": "warning",
                "probable spam": "warning",
                "spam": "danger",
                "reject": "danger"
            }[action] || "info";
            return `<div style="font-size:11px" class="badge text-bg-${cls}">${action}</div>`;
        }

        function scoreFormatter(cell) {
            const data = cell.getData();
            const score = cell.getValue();
            const required = data.required_score;
            const cls = score < required ? "text-success" : "text-danger";
            return `<span class="${cls}">${score.toFixed(2)} / ${required}</span>`;
        }

        function symOrderTitle(table) {
            return "Symbols" +
                '<div class="sym-order-toggle">' +
                    '<br><span style="font-weight:normal;">Sort by:</span><br>' +
                    '<div class="btn-group btn-group-xs btn-sym-order-' + table + '">' +
                        '<label type="button" class="btn btn-outline-secondary btn-sym-' + table + '-magnitude">' +
                            '<input type="radio" class="btn-check" value="magnitude">Magnitude</label>' +
                        '<label type="button" class="btn btn-outline-secondary btn-sym-' + table + '-score">' +
                            '<input type="radio" class="btn-check" value="score">Value</label>' +
                        '<label type="button" class="btn btn-outline-secondary btn-sym-' + table + '-name">' +
                            '<input type="radio" class="btn-check" value="name">Name</label>' +
                    "</div>" +
                "</div>";
        }

        // ── Public functions ─────────────────────────────────────────────────

        ui.formatBytesIEC = function (bytes) {
            if (!Number.isInteger(Number(bytes)) || bytes < 0) return "NaN";

            const base = 1024;
            const exponent = Math.floor(Math.log(bytes) / Math.log(base));

            if (exponent > 8) return "∞";

            const value = parseFloat((bytes / (base ** exponent)).toPrecision(3));
            let unit = "BKMGTPEZY"[exponent];
            if (exponent) unit += "iB";

            return value + " " + unit;
        };

        // ── Global (boolean) query filter ─────────────────────────────────
        // A single search box per table driving a Tabulator setFilter(). The
        // query language:
        //   `foo bar`        → foo AND bar            (whitespace is AND)
        //   `foo OR bar`     → foo OR bar
        //   `foo -bar`       → foo AND NOT bar        (leading "-" negates)
        //   `"soft reject"`  → exact contiguous phrase
        //   `foo bar OR baz` → (foo AND bar) OR baz
        // Matching is case-insensitive substring. Quotes are honoured when
        // splitting on AND/OR, so a phrase may itself contain those words.
        // The setFilter() predicate ANDs with the per-column header filters.
        const SEARCH_FIELDS = ["id", "ip", "sender_mime", "rcpt_mime", "rcpt_mime_short",
            "subject", "user", "passthrough_module", "file", "action"];
        // Haystack cache keyed by row data object (see buildSearchHaystack).
        const haystackCache = new WeakMap();

        function decodeEntities(str) {
            // Values are HTML-escaped upstream (preprocess_item); decode so a
            // literal "&" or "<" typed in the box still matches. &amp; last to
            // avoid double-decoding entities like &amp;lt;.
            return str.replace(/&lt;/g, "<").replace(/&gt;/g, ">")
                .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
        }

        // The visible To/Cc/Bcc column shows a truncated recipient list
        // (rcpt_mime_short); match against the full rcpt_mime so recipients
        // hidden behind "… (N)" are still found. (scan rows keep it as an array.)
        function rcptFilterFunc(filterVal, _cellVal, rowData) {
            if (!filterVal) return true;
            const raw = rowData.rcpt_mime;
            const hay = Array.isArray(raw) ? raw.join(", ") : (raw || "");
            return decodeEntities(hay).toLowerCase().includes(filterVal.toLowerCase());
        }

        // Compile a query string into a {test(haystack)} predicate, or null when
        // the query is blank (meaning "no filter"). Tokenize keeping quoted
        // phrases intact; "AND"/"OR" are operators; a leading "-" negates the
        // following term or phrase.
        function compileFilterQuery(input) {
            if (!input || !input.trim()) return null;
            const tokens = input.match(/"[^"]*"|\S+/g) || [];
            const groups = [[]]; // OR of AND-groups
            tokens.forEach((token) => {
                if (token.toUpperCase() === "OR") {
                    groups.push([]);
                    return;
                }
                if (token.toUpperCase() === "AND") return;
                let term = token;
                const negate = term.charAt(0) === "-";
                if (negate) term = term.slice(1);
                const quoted = term.length >= 2 && term.charAt(0) === '"' && term.slice(-1) === '"';
                if (quoted) term = term.slice(1, -1);
                if (!term) return;
                groups[groups.length - 1].push({q: term.toLowerCase(), negate});
            });
            // Drop groups left empty by dangling/leading/doubled operators
            // (e.g. "foo OR", "OR foo", "foo OR OR bar") so they don't match all
            // rows via [].every() vacuous truth.
            const orGroups = groups.filter((g) => g.length);
            if (!orGroups.length) return null;
            return {
                test(haystack) {
                    return orGroups.some((group) => group.every((t) => {
                        const found = haystack.indexOf(t.q) !== -1;
                        return t.negate ? !found : found;
                    }));
                }
            };
        }

        // Lowercased searchable text for a row. Numeric/formatted columns (time,
        // time_real, size, score) are excluded — their raw values are useless for
        // free-text search, and the per-column header filters cover them. Memoized
        // in a WeakMap keyed by the data object so it is built once per row, not
        // on every keystroke; entries are GC'd when the row data is replaced.
        function buildSearchHaystack(data) {
            if (haystackCache.has(data)) return haystackCache.get(data);
            let s = SEARCH_FIELDS.map((f) => (typeof data[f] === "string" ? data[f] : "")).join(" ");
            if (data.symbols_obj) {
                s += " " + Object.values(data.symbols_obj)
                    .map((sym) => sym.name + " " + (sym.description || ""))
                    .join(" ");
            }
            s = decodeEntities(s).toLowerCase();
            haystackCache.set(data, s);
            return s;
        }

        // Apply the current filter box value to the table, or clear it. Reads the
        // Tabulator instance lazily so it works across a destroy+re-init.
        function applyGlobalFilter(table) {
            const tab = common.tables[table];
            if (!tab) return;
            const input = document.getElementById("filter_" + table);
            const compiled = compileFilterQuery(input ? input.value : null);
            if (!compiled) {
                tab.clearFilter();
                return;
            }
            tab.setFilter((data) => compiled.test(buildSearchHaystack(data)));
        }

        // Bind the filter box: live, debounced. Bound once per table; the handler
        // resolves the current instance at fire time, so it survives rebuilds.
        function bindGlobalFilter(table) {
            const input = document.getElementById("filter_" + table);
            if (!input) return;
            input.title = "Search syntax: match all rows containing\n\n" +
                '"exact phrase" — exact string (including spaces)\n' +
                "term1 OR term2 — either term\n" +
                "term1 AND term2 — both terms\n" +
                "term1 term2 — both terms (same as AND)\n" +
                "term1 -term2 — term1 but exclude rows with term2";
            let timer = null;
            input.addEventListener("input", () => {
                clearTimeout(timer);
                timer = setTimeout(() => applyGlobalFilter(table), 250);
            });
        }

        ui.columns_v2 = function (table) {
            const cols = [{
                // Toggle to expand collapsed (responsive) columns
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
                headerFilter: "input",
                responsive: 0,
                minWidth: 130,
                widthGrow: 2,
            }, {
                title: "File name",
                field: "file",
                headerFilter: "input",
                responsive: 1,
                minWidth: 260,
                widthGrow: 4,
            }, {
                title: "IP address",
                field: "ip",
                headerFilter: "input",
                responsive: 3,
                minWidth: 98,
                width: 98,
                sorter: ipSorter,
            }, {
                title: "[Envelope From] From",
                field: "sender_mime",
                headerFilter: "input",
                responsive: 3,
                minWidth: 100,
                maxWidth: 200,
            }, {
                title: "[Envelope To] To/Cc/Bcc",
                field: "rcpt_mime_short",
                responsive: 3,
                headerFilter: "input",
                headerFilterFunc: rcptFilterFunc,
                minWidth: 100,
                maxWidth: 200,
            }, {
                title: "[Envelope To] To/Cc/Bcc",
                field: "rcpt_mime",
                responsive: 100,
                minWidth: FORCE_COLLAPSE_MIN_WIDTH,
            }, {
                title: "Subject",
                field: "subject",
                headerFilter: "input",
                responsive: 3,
                minWidth: 150,
                widthGrow: 2,
            }, {
                title: "Action",
                field: "action",
                responsive: 0,
                minWidth: 108,
                width: 108,
                formatter: actionFormatter,
                headerFilter: actionHeaderFilter,
                headerFilterFunc: actionFilterFunc,
            }, {
                title: '<div title="The module that has set the pre-result"><nobr>Pass-through</nobr> module</div>',
                field: "passthrough_module",
                headerFilter: "input",
                minWidth: 98,
                width: 98,
            }, {
                title: "Score",
                field: "score",
                responsive: 0,
                sorter: "number",
                minWidth: 64,
                width: 64,
                formatter: scoreFormatter,
            }, {
                title: symOrderTitle(table),
                field: "symbols",
                formatter: "html",
                headerSort: false,
                // Highest responsive priority, so symbols collapses first. The
                // large minWidth forces overflow at any realistic width, so the
                // column always renders in the detail row (Tabulator has no native
                // "always collapse" mode).
                responsive: 100,
                minWidth: FORCE_COLLAPSE_MIN_WIDTH,
            }, {
                title: "Msg size",
                field: "size",
                responsive: 3,
                sorter: "number",
                formatter: (cell) => ui.formatBytesIEC(cell.getValue()),
                minWidth: 56,
                width: 56,
            }, {
                title: "Scan time",
                field: "time_real",
                responsive: 3,
                sorter: "number",
                minWidth: 60,
                width: 60,
            }, {
                title: "Time",
                field: "time",
                responsive: 0,
                sorter: "number",
                formatter: (cell) => ui.unix_time_format(cell.getValue()),
                minWidth: 72,
                width: 72,
            }, {
                title: "Authenticated user",
                field: "user",
                headerFilter: "input",
                responsive: 3,
                minWidth: 100,
                maxWidth: 130,
            }];

            return cols.filter((col) => {
                if (!col.field) return true; // Toggle column
                switch (table) {
                    case "history":
                        return (col.field !== "file");
                    case "scan":
                        return ["ip", "sender_mime", "rcpt_mime_short", "rcpt_mime", "subject", "size", "user"]
                            .every((name) => col.field !== name);
                    default:
                        return null;
                }
            });
        };

        ui.set_page_size = function (table, page_size, changeTablePageSize) {
            const n = parseInt(page_size, 10);
            if (n > 0) {
                common.page_size[table] = n;

                if (changeTablePageSize && common.tables[table]) {
                    clearTimeout(pageSizeTimerId);
                    pageSizeTimerId = setTimeout(() => {
                        common.tables[table]?.setPageSize(n);
                    }, 1000);
                }
            }
        };

        ui.bindHistoryTableEventHandlers = function (table) {
            if (boundSymOrderTables.has(table)) return;
            boundSymOrderTables.add(table);
            function change_symbols_order(order) {
                const compare_function = get_compare_function(table);
                common.tables[table].getRows().forEach((row) => {
                    const cell_val = sort_symbols(row.getData().symbols_obj, compare_function);
                    // row.update (not cell.setValue) so the responsive-collapse
                    // detail row is regenerated; setValue only re-renders the
                    // hidden cell element and never refreshes the collapsed view.
                    row.update({symbols: cell_val});
                });
                // row.update recreates each detail's buttons (without active);
                // re-apply the active state to the fresh elements.
                setActiveSymOrderButton(table, order);
            }

            document.getElementById("selSymOrder_" + table).addEventListener("change", function () {
                change_symbols_order(this.value);
            });
            document.getElementById(table + "_page_size")
                .addEventListener("change", (e) => ui.set_page_size(table, e.target.value, true));
            common.delegate(document, "click", ".btn-sym-order-" + table + " input", (event, target) => {
                const order = target.value;
                document.getElementById("selSymOrder_" + table).value = order;
                change_symbols_order(order);
            });

            bindGlobalFilter(table);
        };

        ui.destroyTable = function (table) {
            const openColumnsBtn = document.querySelector("#" + table + " .tab-columns-btn.show");
            if (openColumnsBtn) {
                bootstrap.Dropdown.getOrCreateInstance(openColumnsBtn).hide();
            }
            document.querySelectorAll("#" + table + " .tab-columns-btn").forEach((el) => { el.disabled = true; });
            if (common.tables[table]) {
                common.tables[table].destroy();
                delete common.tables[table];
            }
        };

        ui.initHistoryTable = function (data, items, table, columnsDefault, expandFirst, postdrawCallback) {
            // A persisted "Row" column is stored as responsive:100; it must also
            // receive the force-collapse minWidth so it renders in the detail row.
            const baseColumns = (table in columnsCustom)
                ? columnsDefault.map((column) => ({...column, ...(columnsCustom[table][column.field] || {})}))
                : columnsDefault.map((column) => column);
            const columns = baseColumns.map((column) => (column.responsive === 100
                ? {...column, minWidth: FORCE_COLLAPSE_MIN_WIDTH}
                : column));

            common.tables[table] = new Tabulator("#historyTable_" + table, {
                layout: "fitColumns",
                responsiveLayout: "collapse",
                responsiveLayoutCollapseStartOpen: expandFirst,
                // Cell values are HTML-escaped upstream (preprocess_item); render
                // them as HTML so entities decode. The default "plaintext"
                // formatter re-escapes and would show &quot;/&amp; literally.
                // Explicit column formatters override this.
                columnDefaults: {formatter: "html"},
                selectable: false,
                pagination: "local",
                paginationSize: common.page_size[table],
                paginationButtonCount: 5,
                data: items,
                initialSort: [{column: "time", dir: "desc"}],
                columns: columns,
            });

            tabUtils.hideFooterOnSinglePage(table);
            tabUtils.stripTableholderTabindex(table);
            tabUtils.bindRowClickToggle(table);
            tabUtils.patchScrollIntoViewOnce();
            tabUtils.installScrollPreservation(table);

            common.tables[table].on("tableBuilt", () => {
                setActiveSymOrderButton(table);
                // Re-apply a global filter in place when the table was rebuilt
                // (e.g. via the column-options dropdown): a fresh Tabulator
                // instance starts unfiltered, but the search box keeps its value.
                const filterBox = document.getElementById("filter_" + table);
                if (filterBox && filterBox.value.trim()) applyGlobalFilter(table);
            });
            if (postdrawCallback) common.tables[table].on("renderComplete", postdrawCallback);
            // The "Sort by:" buttons are rendered inside each row's collapsed
            // detail (via the column title), so they are recreated on every
            // render — re-apply the active state each time.
            common.tables[table].on("renderComplete", () => setActiveSymOrderButton(table));

            // Column options dropdown
            (() => {
                // Changes the ResponsiveLayout module owns — "Row" toggles and
                // visibility on always-collapsed (responsive:100) columns — can't be
                // applied incrementally, so they're deferred to dropdown close / Save.
                // This keeps the dropdown open while toggling several at once.
                let rebuildPending = false;

                // Column visibility and the emulated "Row" mode (responsive:100) both
                // depend on ResponsiveLayout's collapse pointer, which is set once at
                // construction and never reconciled after a runtime definition change —
                // the root cause of the erratic collapse/expand behaviour (columns that
                // expand but never collapse back, neighbours collapsing in sympathy).
                // Rather than poke at the module's private state, rebuild the whole
                // table: a fresh instance converges to the correct collapse set, exactly
                // as on first load. The current data is preserved; the initial-render
                // callback is skipped (buttons/fuzzy are already wired and delegated).
                function rebuild() {
                    const rows = common.tables[table].getData();
                    ui.destroyTable(table);
                    ui.initHistoryTable(data, rows, table, columnsDefault, expandFirst);
                }

                // Apply deferred "Row" changes (if any) and clear the dirty flag.
                function applyPendingRebuild() {
                    if (!rebuildPending) return;
                    rebuildPending = false;
                    rebuild();
                }

                const tbody = common.el("tbody", {class: "table-group-divider"});
                const dropdown = document.querySelector("#" + table + " .tab-columns-dropdown");
                dropdown.replaceChildren(
                    common.el("table", {class: "table table-sm table-striped text-center"},
                        common.el("thead", null,
                            common.el("tr", null,
                                common.el("th", {text: "Row", title: "Display column cells in a detail row"}),
                                common.el("th", {text: "Hidden", title: "Hide column completely"}),
                                common.el("th", {text: "Column name", class: "text-start"})
                            )
                        ),
                        tbody
                    ),
                    common.el("button", {
                        type: "button",
                        class: "btn btn-xs btn-secondary float-start",
                        text: "Reset to default",
                        click: () => {
                            const custom = columnsCustom[table] || {};
                            // A reset needs a rebuild whenever the live table is in a
                            // state ResponsiveLayout owns: a "Row" override, or a hidden
                            // always-collapsed (responsive:100) column. Plain hidden
                            // columns restore via showColumn with no rebuild.
                            const needsRebuild = rebuildPending || columnsDefault.some((c) => {
                                if (!c.field) return false;
                                const cfg = custom[c.field];
                                return cfg && ((cfg.responsive === 100 && c.responsive !== 100) ||
                                    (c.responsive === 100 && cfg.visible === false));
                            });
                            // Only plain (non-responsive:100) hidden columns can be
                            // restored without a rebuild; responsive ones are rebuilt.
                            const hiddenFields = columnsDefault
                                .filter((c) => c.field && c.responsive !== 100 &&
                                    custom[c.field]?.visible === false)
                                .map((c) => c.field);
                            delete columnsCustom[table];
                            localStorage.setItem("columns", JSON.stringify(columnsCustom));
                            // Clear before rebuild: the rebuild closes this open dropdown,
                            // whose close handler (applyPendingRebuild) must see nothing
                            // pending — otherwise it re-inits again.
                            rebuildPending = false;
                            if (needsRebuild) {
                                rebuild();
                            } else {
                                const tab = common.tables[table];
                                hiddenFields.forEach((f) => {
                                    tab.showColumn(f);
                                    const cb = tbody.querySelector('input[data-name="' + f + '"][data-option="visible"]');
                                    if (cb) cb.checked = false;
                                });
                            }
                        }
                    }),
                    common.el("button", {
                        type: "button",
                        class: "btn btn-xs btn-primary float-end btn-dropdown-apply",
                        text: "Save",
                        title: "Save column settings to browser storage",
                        click: () => {
                            localStorage.setItem("columns", JSON.stringify(columnsCustom));
                            applyPendingRebuild();
                        }
                    })
                );

                function columnLabel(column) {
                    switch (column.field) {
                        case "passthrough_module": return "Pass-through module";
                        case "symbols": return "Symbols";
                        default: return (column.title || "").replace(/<[^>]*>/g, "");
                    }
                }

                function checkbox(i, column, cellIdx) {
                    const option = ["responsive", "visible"][cellIdx];
                    const isRow = option === "responsive";
                    return common.el("td", null,
                        common.el("input", {
                            type: "checkbox",
                            class: "form-check-input",
                            dataset: {table, name: column.field, option},
                            checked: (isRow && column.responsive === 100) ||
                                (!isRow && column.visible === false),
                            disabled: isRow && columnsDefault[i].responsive === 100,
                            change: (e) => {
                                const {checked} = e.target;
                                columnsCustom[table] = columnsCustom[table] || {};
                                columnsCustom[table][column.field] = columnsCustom[table][column.field] || {};
                                // Columns currently in "Row" mode (responsive:100) are owned by
                                // ResponsiveLayout: hiding them no-ops and showing them pops them
                                // out of the detail row, because the module can't reconcile at
                                // runtime. So both "Row" and visibility changes on such columns
                                // are deferred to a rebuild; plain columns toggle in place.
                                if (isRow || column.responsive === 100) {
                                    if (isRow) {
                                        if (checked) {
                                            columnsCustom[table][column.field].responsive = 100;
                                        } else {
                                            delete columnsCustom[table][column.field].responsive;
                                        }
                                    } else {
                                        columnsCustom[table][column.field].visible = !checked;
                                    }
                                    rebuildPending = true;
                                } else {
                                    columnsCustom[table][column.field].visible = !checked;
                                    const tab = common.tables[table];
                                    if (checked) tab.hideColumn(column.field); else tab.showColumn(column.field);
                                }
                            }
                        })
                    );
                }

                columns.forEach((column, i) => {
                    if (!column.field) return; // responsiveCollapse toggle is a control, not a column
                    tbody.append(
                        common.el("tr", null,
                            checkbox(i, column, 0),
                            checkbox(i, column, 1),
                            common.el("td", {class: "text-start", text: columnLabel(column)})
                        )
                    );
                });

                // Apply deferred "Row" changes when the dropdown closes. The trigger
                // element survives rebuilds, so track the handler and re-bind it each
                // build to avoid stacking.
                const columnsBtn = document.querySelector("#" + table + " .tab-columns-btn");
                const prevHandler = common.data(columnsBtn, "dropdownHandler");
                if (prevHandler) columnsBtn.removeEventListener("hidden.bs.dropdown", prevHandler);
                columnsBtn.addEventListener("hidden.bs.dropdown", applyPendingRebuild);
                common.data(columnsBtn, "dropdownHandler", applyPendingRebuild);
                columnsBtn.disabled = false;
            })();
        };

        ui.preprocess_item = function (item) {
            function escape_HTML_array(arr) {
                arr.forEach((d, i) => { arr[i] = common.escapeHTML(d); });
            }

            for (const prop in item) {
                if (!{}.hasOwnProperty.call(item, prop)) continue;
                switch (prop) {
                    case "rcpt_mime":
                    case "rcpt_smtp":
                        escape_HTML_array(item[prop]);
                        break;
                    case "symbols":
                        Object.keys(item.symbols).forEach((key) => {
                            const sym = item.symbols[key];
                            if (!sym.name) {
                                sym.name = key;
                            }
                            sym.name = common.escapeHTML(sym.name);
                            if (sym.description) {
                                sym.description = common.escapeHTML(sym.description);
                            }

                            if (sym.options) {
                                escape_HTML_array(sym.options);
                            }
                        });
                        break;
                    default:
                        if (typeof item[prop] === "string") item[prop] = common.escapeHTML(item[prop]);
                }
            }
        };

        ui.unix_time_format = function (tm) {
            const date = new Date(tm ? tm * 1000 : 0);
            return (common.locale)
                ? date.toLocaleString(common.locale)
                : date.toLocaleString();
        };

        function isFuzzySymbol(sym) {
            if (!sym.options) return false;
            return sym.options.some((opt) => (/^\d+:[a-f0-9]+:[\d.]+:/).test(opt));
        }

        function attachFuzzyIndices(sym, fuzzyHashesArray, fuzzyHashIndex) {
            sym.fuzzyHashIndices = [];

            if (!fuzzyHashesArray || Object.keys(fuzzyHashIndex).length === 0) return;

            const foundIndices = new Set();
            sym.options.forEach((opt) => {
                const match = opt.match(/^\d+:([a-f0-9]+):[\d.]+:/);
                if (match) {
                    const [,shortHash] = match;
                    const indices = fuzzyHashIndex[shortHash];
                    if (Array.isArray(indices)) indices.forEach((i) => foundIndices.add(i));
                }
            });

            sym.fuzzyHashIndices = Array.from(foundIndices).sort((a, b) => a - b);
        }

        function generateFuzzySearchData(sym, fuzzyHashesArray) {
            if (!sym.fuzzyHashIndices?.length) return "";

            const fullHashes = sym.fuzzyHashIndices
                .filter((i) => i >= 0 && i < fuzzyHashesArray.length)
                .map((i) => fuzzyHashesArray[i]);
            return `<span class="visually-hidden">${common.escapeHTML(fullHashes.join(" "))}</span>`;
        }

        function generateFuzzyActions(sym, table, item) {
            const hasHashes = sym.fuzzyHashIndices?.length > 0;

            // eslint-disable-next-line init-declarations
            let copyTitle, delistTitle;
            if (hasHashes) {
                copyTitle = "Copy full hashes to clipboard";
                delistTitle = "Open bl.rspamd.com delisting page";
            } else if (table === "history") {
                copyTitle = "Full fuzzy hashes are not available for this message";
                delistTitle = copyTitle;
            } else {
                copyTitle = "Full fuzzy hashes are not available. Enable milter_headers module with 'fuzzy-hashes' routine";
                delistTitle = copyTitle;
            }

            function makeButton(cssClass, action, icon, label, title) {
                const dataAttrs = hasHashes
                    ? `data-indices='${common.escapeHTML(JSON.stringify(sym.fuzzyHashIndices))}' ` +
                      `data-hashes='${common.escapeHTML(JSON.stringify(item.fuzzy_hashes))}' data-table="${table}"`
                    : `data-table="${table}"`;
                const disabled = hasHashes ? "" : " disabled";
                const button = `<button class="btn btn-xs ${cssClass} ${action}${disabled}" ${dataAttrs}${disabled} ` +
                    `title="${title}"><i class="fas ${icon}"></i> ${label}</button>`;
                return hasHashes ? button : `<span title="${title}">${button}</span>`;
            }

            const copyBtn = makeButton("btn-outline-secondary", "fuzzy-copy", "fa-copy", "Copy", copyTitle);
            const delistBtn = makeButton("btn-outline-primary", "fuzzy-delist", "fa-external-link", "Delist", delistTitle);

            return `<span class="fuzzy-hash-actions d-inline-flex gap-1 ms-1 align-baseline">${copyBtn}${delistBtn}</span>`;
        }

        ui.process_history_v2 = function (data, table) {
            // Display no more than rcpt_lim recipients
            const rcpt_lim = 3;
            const items = [];
            const unsorted_symbols = [];
            const compare_function = get_compare_function(table);

            common.show("#selSymOrder_" + table + ", label[for='selSymOrder_" + table + "']");

            data.rows.forEach(
                (item) => {
                    function more(p) {
                        const l = item[p].length;
                        return (l > rcpt_lim) ? " … (" + l + ")" : "";
                    }
                    function format_rcpt(smtp, mime) {
                        let full = "";
                        let shrt = "";
                        if (smtp) {
                            full = "[" + item.rcpt_smtp.join(", ") + "] ";
                            shrt = "[" + item.rcpt_smtp.slice(0, rcpt_lim).join(",&#8203;") + more("rcpt_smtp") + "]";
                            if (mime) {
                                full += " ";
                                shrt += " ";
                            }
                        }
                        if (mime) {
                            full += item.rcpt_mime.join(", ");
                            shrt += item.rcpt_mime.slice(0, rcpt_lim).join(",&#8203;") + more("rcpt_mime");
                        }
                        return {full: full, shrt: shrt};
                    }

                    function get_symbol_class(name, score) {
                        if (name.match(/^GREYLIST$/)) {
                            return "symbol-special";
                        }

                        if (score < 0) {
                            return "symbol-negative";
                        } else if (score > 0) {
                            return "symbol-positive";
                        }
                        return null;
                    }

                    ui.preprocess_item(item);

                    // Build fuzzy hash index for this item
                    const fuzzyHashIndex = {};
                    if (Array.isArray(item.fuzzy_hashes)) {
                        item.fuzzy_hashes.forEach((fullHash, idx) => {
                            const shortHash = fullHash.substring(0, 10);
                            if (!fuzzyHashIndex[shortHash]) fuzzyHashIndex[shortHash] = [];
                            fuzzyHashIndex[shortHash].push(idx);
                        });
                    }

                    Object.values(item.symbols).forEach((sym) => {
                        sym.str = `
<span class="symbol-default ${get_symbol_class(sym.name, sym.score)} ${sym.description ? "has-description" : ""}" tabindex="0">
    <strong>${sym.name}</strong>
    ${sym.description ? `<span class="symbol-description"> • ${sym.description}</span>` : ""}
    (${sym.score})
</span>`;

                        if (sym.options) {
                            sym.str += ` [${sym.options.join(",")}]`;

                            if (isFuzzySymbol(sym)) {
                                attachFuzzyIndices(sym, item.fuzzy_hashes, fuzzyHashIndex);
                                sym.str += generateFuzzySearchData(sym, item.fuzzy_hashes);
                                sym.str += generateFuzzyActions(sym, table, item);
                            }
                        }
                    });
                    unsorted_symbols.push(item.symbols);
                    item.symbols_obj = item.symbols;
                    item.symbols = sort_symbols(item.symbols, compare_function);
                    if (table === "scan") {
                        item.unix_time = (new Date()).getTime() / 1000;
                    }
                    item.time = item.unix_time;
                    item.time_real = item.time_real.toFixed(3);
                    item.id = item["message-id"];

                    if (table === "history") {
                        // eslint-disable-next-line no-useless-assignment
                        let rcpt = {};
                        if (!item.rcpt_mime.length) {
                            rcpt = format_rcpt(true, false);
                        } else if (
                            item.rcpt_mime.some((x) => !item.rcpt_smtp.includes(x)) ||
                            item.rcpt_smtp.some((x) => !item.rcpt_mime.includes(x))
                        ) {
                            rcpt = format_rcpt(true, true);
                        } else {
                            rcpt = format_rcpt(false, true);
                        }
                        item.rcpt_mime_short = rcpt.shrt;
                        item.rcpt_mime = rcpt.full;

                        if (item.sender_mime !== item.sender_smtp) {
                            item.sender_mime = "[" + item.sender_smtp + "] " + item.sender_mime;
                        }
                    }
                    items.push(item);
                });

            return {items: items, symbols: unsorted_symbols};
        };

        ui.bindFuzzyHashButtons = function (table) {
            function bindAction(action, handler) {
                const selector = `.fuzzy-${action}[data-table="${table}"]:not(:disabled)`;
                const prevCleanup = fuzzyCleanups.get(selector);
                if (prevCleanup) prevCleanup();
                fuzzyCleanups.set(selector, common.delegate(document, "click", selector, (event, target) => {
                    event.preventDefault();
                    event.stopPropagation();

                    // eslint-disable-next-line init-declarations
                    let hashes, indices;
                    try {
                        indices = JSON.parse(target.getAttribute("data-indices") || "[]");
                        hashes = JSON.parse(target.getAttribute("data-hashes") || "[]");
                    } catch (err) {
                        common.alertMessage("alert-danger", "Invalid hash data: " + err.message);
                        return;
                    }

                    if (indices.length === 0 || hashes.length === 0) {
                        common.alertMessage("alert-warning", "No full hashes available");
                        return;
                    }

                    const fullHashes = [...new Set(indices.map((i) => hashes[i]))];
                    handler(target, fullHashes);
                }));
            }

            bindAction("copy", (btn, fullHashes) => {
                const textToCopy = fullHashes.join("\n");
                common.copyToClipboard(textToCopy)
                    .then(() => {
                        const originalHtml = btn.innerHTML;
                        btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                        setTimeout(() => { btn.innerHTML = originalHtml; }, 2000);
                    })
                    .catch((err) => {
                        common.alertMessage("alert-danger", "Copy failed: " + err.message);
                    });
            });

            bindAction("delist", (_btn, fullHashes) => {
                const url = "https://bl.rspamd.com/removal?type=fuzzy&hash=" + encodeURIComponent(fullHashes.join(","));
                window.open(url, "_blank");
            });
        };

        return ui;
    });
