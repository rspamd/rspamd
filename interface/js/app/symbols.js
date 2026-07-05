/*
 * Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>
 */

define(["jquery", "app/common", "app/tab-utils", "tabulator"],
    ($, common, tabUtils, Tabulator) => {
        "use strict";
        const ui = {};
        let altered = {};
        let groupSelectEl = null;

        function clear_altered() {
            $("#save-alert").addClass("d-none");
            altered = {};
        }

        function saveSymbols(server) {
            $("#save-alert button").attr("disabled", true);

            const values = [];
            Object.entries(altered).forEach(([key, value]) => values.push({name: key, value: value}));

            common.query("./savesymbols", {
                success: function () {
                    clear_altered();
                    common.alertMessage("alert-modal alert-success", "Symbols successfully saved");
                },
                complete: () => $("#save-alert button").removeAttr("disabled"),
                errorMessage: "Save symbols error",
                method: "POST",
                params: {
                    data: JSON.stringify(values),
                    dataType: "json",
                },
                server: server
            });
        }

        function process_symbols_data(data) {
            const items = [];
            const lookup = {};
            const freqs = [];
            const stddevs = [];
            const distinct_groups = [];

            data.forEach((group) => {
                group.rules.forEach((item) => {
                    const formatter = new Intl.NumberFormat("en", {
                        minimumFractionDigits: 2,
                        maximumFractionDigits: 6,
                        useGrouping: false
                    });
                    item.group = group.group;
                    let label_class = "";
                    if (item.weight < 0) {
                        label_class = "scorebar-ham";
                    } else if (item.weight > 0) {
                        label_class = "scorebar-spam";
                    }
                    item.weight = '<input class="form-control input-sm mb-disabled scorebar ' + label_class +
                        '" autocomplete="off" type="number" step="0.01" tabindex="1" ' +
                        'value="' + formatter.format(item.weight) + '" id="_sym_' + item.symbol + '"></input>';
                    if (!item.time) {
                        item.time = 0;
                    }
                    item.time = Number(item.time).toFixed(2);

                    // Normalize frequency values for scaling
                    ["frequency", "frequency_stddev"].forEach((p) => (item[p] = Number(item[p] || 0)));

                    freqs.push(item.frequency);
                    stddevs.push(item.frequency_stddev);
                    if (!(item.group in lookup)) {
                        lookup[item.group] = 1;
                        distinct_groups.push(item.group);
                    }
                    items.push(item);
                });
            });

            // For better mean calculations - use only non-zero values
            const nonzero_freqs = freqs.filter((f) => Number(f) > 0.0);
            const avg_freq = nonzero_freqs.length > 0
                ? nonzero_freqs.reduce((acc, f) => acc + Number(f), 0.0) / nonzero_freqs.length
                : 0.0;
            let mult = 1.0;
            let exp = 0.0;

            if (avg_freq > 0.0) {
                while (mult * avg_freq < 1.0) {
                    mult *= 10;
                    exp++;
                }
            }

            return [items, distinct_groups, {mult, exp}];
        }
        // Populate a native <select> with distinct sorted groups from the
        // table data, plus an empty option to clear the filter.
        function formatFreq(value, params) {
            return (value * params.mult).toFixed(2) + ((params.exp > 0) ? "e-" + params.exp : "");
        }

        function populateGroupSelect(select, rows) {
            const current = select.value;
            select.innerHTML = "";
            select.appendChild(new Option("Any group", ""));
            const data = rows || (common.tables.symbols && common.tables.symbols.getData()) || [];
            [...new Set(data.map((r) => r.group))]
                .sort((a, b) => a.localeCompare(b))
                .forEach((g) => select.appendChild(new Option(g, g)));
            select.value = current;
        }

        // @get symbols into modal form
        ui.getSymbols = function () {
            $("#refresh, #updateSymbols").attr("disabled", true);
            clear_altered();
            common.query("symbols", {
                success: function (json) {
                    const [{data}] = json;
                    const [rows, , freqParams] = process_symbols_data(data);

                    common.tables.symbols = new Tabulator("#symbolsTable", {
                        layout: "fitColumns",
                        responsiveLayout: "collapse",
                        responsiveLayoutCollapseStartOpen: false,
                        selectable: false,
                        pagination: "local",
                        paginationSize: 25,
                        paginationButtonCount: 5,
                        data: rows,
                        initialSort: [{column: "group", dir: "asc"}],
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
                                title: "Group",
                                field: "group",
                                headerFilter: (cell, onRendered, success) => {
                                    const select = document.createElement("select");
                                    select.className = "form-select";
                                    populateGroupSelect(select, rows);
                                    select.refreshGroups = () => populateGroupSelect(select);
                                    select.addEventListener("change", () => success(select.value));
                                    groupSelectEl = select;
                                    return select;
                                },
                                headerFilterFunc: (filterVal, cellVal) => !filterVal || filterVal === cellVal,
                                minWidth: 110,
                                width: 205,
                                responsive: 0,
                            },
                            {
                                title: "Symbol",
                                field: "symbol",
                                headerFilter: "input",
                                minWidth: 270,
                                responsive: 0,
                                widthGrow: 2,
                            },
                            {
                                title: "Description",
                                field: "description",
                                headerFilter: "input",
                                minWidth: 105,
                                responsive: 2,
                                widthGrow: 4,
                            },
                            {
                                title: "Score",
                                field: "weight",
                                formatter: "html",
                                minWidth: 75,
                                width: 90,
                                responsive: 0,
                            },
                            {
                                title: "Frequency, <nobr>hits/s</nobr>",
                                field: "frequency",
                                sorter: "number",
                                formatter: (cell, params) => formatFreq(cell.getValue(), params),
                                formatterParams: freqParams,
                                minWidth: 140,
                            },
                            {
                                title: "Stddev, <nobr>hits/s</nobr>",
                                field: "frequency_stddev",
                                sorter: "number",
                                formatter: (cell, params) => formatFreq(cell.getValue(), params),
                                formatterParams: freqParams,
                                minWidth: 120,
                                responsive: 3,
                            },
                            {title: "Avg. time, s", field: "time", sorter: "number", minWidth: 110},
                        ],
                    });

                    tabUtils.hideFooterOnSinglePage("symbols");
                    tabUtils.stripTableholderTabindex("symbols");
                    tabUtils.bindRowClickToggle("symbols");
                    tabUtils.patchScrollIntoViewOnce();
                    tabUtils.installScrollPreservation("symbols", {
                        armTriggers: [document.getElementById("updateSymbols")].filter(Boolean),
                    });

                    common.tables.symbols.on("tableBuilt", () => {
                        if (common.read_only) {
                            $(".mb-disabled").attr("disabled", true);
                        }
                        $("#refresh, #updateSymbols").removeAttr("disabled");
                    });
                    common.tables.symbols.on("renderComplete", () => {
                        $("#refresh, #updateSymbols").removeAttr("disabled");
                    });
                },
                error: () => $("#refresh, #updateSymbols").removeAttr("disabled"),
                server: common.getServer()
            });
        };


        $("#updateSymbols").on("click", (e) => {
            e.preventDefault();
            $("#refresh, #updateSymbols").attr("disabled", true);
            clear_altered();
            common.query("symbols", {
                success: function (data) {
                    const [rows, , freqParams] = process_symbols_data(data[0].data);

                    common.tables.symbols.setData(rows);
                    if (groupSelectEl) populateGroupSelect(groupSelectEl);
                    common.tables.symbols.updateColumnDefinition("frequency", {formatterParams: freqParams});
                    common.tables.symbols.updateColumnDefinition("frequency_stddev", {formatterParams: freqParams});
                },
                error: () => $("#refresh, #updateSymbols").removeAttr("disabled"),
                server: common.getServer()
            });
        });

        $("#symbolsTable")
            .on("input", ".scorebar", ({target}) => {
                const t = $(target);
                t.removeClass("scorebar-ham scorebar-spam");
                if (target.value < 0) {
                    t.addClass("scorebar-ham");
                } else if (target.value > 0) {
                    t.addClass("scorebar-spam");
                }
            })
            .on("change", ".scorebar", ({target}) => {
                altered[$(target).attr("id").substring(5)] = parseFloat(target.value);
                $("#save-alert").removeClass("d-none");
            });

        $("#save-alert button")
            .on("click", ({target}) => saveSymbols($(target).data("save")));

        return ui;
    });
