/* global FooTable */

define(["jquery", "app/common", "footable"],
    ($, common) => {
        "use strict";
        const ui = {};

        let pageSizeTimerId = null;
        let pageSizeInvocationCounter = 0;

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


        // Public functions

        ui.set_page_size = function (table, page_size, changeTablePageSize) {
            const n = parseInt(page_size, 10); // HTML Input elements return string representing a number
            if (n > 0) {
                common.page_size[table] = n;

                if (changeTablePageSize &&
                    $("#historyTable_" + table + " tbody").is(":parent")) { // Table is not empty
                    clearTimeout(pageSizeTimerId);
                    const t = FooTable.get("#historyTable_" + table);
                    if (t) {
                        pageSizeInvocationCounter = 0;
                        // Wait for input finish
                        pageSizeTimerId = setTimeout(() => t.pageSize(n), 1000);
                    } else if (++pageSizeInvocationCounter < 10) {
                        // Wait for FooTable instance ready
                        pageSizeTimerId = setTimeout(() => ui.set_page_size(table, n, true), 1000);
                    }
                }
            }
        };

        ui.bindHistoryTableEventHandlers = function (table, symbolsCol) {
            function change_symbols_order(order) {
                $(".btn-sym-" + table + "-" + order).addClass("active").siblings().removeClass("active");
                const compare_function = get_compare_function(table);
                $.each(common.tables[table].rows.all, (i, row) => {
                    const cell_val = sort_symbols(common.symbols[table][i], compare_function);
                    row.cells[symbolsCol].val(cell_val, false, true);
                });
            }

            $("#selSymOrder_" + table).unbind().change(function () {
                const order = this.value;
                change_symbols_order(order);
            });
            $("#" + table + "_page_size").change((e) => ui.set_page_size(table, e.target.value, true));
            $(document).on("click", ".btn-sym-order-" + table + " input", function () {
                const order = this.value;
                $("#selSymOrder_" + table).val(order);
                change_symbols_order(order);
            });
        };

        ui.destroyTable = function (table) {
            if (common.tables[table]) {
                common.tables[table].destroy();
                delete common.tables[table];
            }
        };

        ui.initHistoryTable = function (data, items, table, columns, expandFirst) {
            /* eslint-disable no-underscore-dangle */
            FooTable.Cell.extend("collapse", function () {
                // call the original method
                this._super();
                // Copy cell classes to detail row tr element
                this._setClasses(this.$detail);
            });
            /* eslint-enable no-underscore-dangle */

            /* eslint-disable consistent-this, no-underscore-dangle, one-var-declaration-per-line */
            FooTable.actionFilter = FooTable.Filtering.extend({
                construct: function (instance) {
                    this._super(instance);
                    this.actions = ["reject", "add header", "greylist",
                        "no action", "soft reject", "rewrite subject"];
                    this.def = "Any action";
                    this.$action = null;
                },
                $create: function () {
                    this._super();
                    const self = this;
                    const $form_grp = $("<div/>", {
                        class: "form-group d-inline-flex align-items-center"
                    }).append($("<label/>", {
                        class: "sr-only",
                        text: "Action"
                    })).prependTo(self.$form);

                    $("<div/>", {
                        class: "form-check form-check-inline",
                        title: "Invert action match."
                    }).append(
                        self.$not = $("<input/>", {
                            type: "checkbox",
                            class: "form-check-input",
                            id: "not_" + table
                        }).on("change", {self: self}, self._onStatusDropdownChanged),
                        $("<label/>", {
                            class: "form-check-label",
                            for: "not_" + table,
                            text: "not"
                        })
                    ).appendTo($form_grp);

                    self.$action = $("<select/>", {
                        class: "form-select"
                    }).on("change", {
                        self: self
                    }, self._onStatusDropdownChanged).append(
                        $("<option/>", {
                            text: self.def
                        })).appendTo($form_grp);

                    $.each(self.actions, (i, action) => {
                        self.$action.append($("<option/>").text(action));
                    });
                },
                _onStatusDropdownChanged: function (e) {
                    const {self} = e.data;
                    const selected = self.$action.val();
                    if (selected !== self.def) {
                        const not = self.$not.is(":checked");
                        let query = null;

                        if (selected === "reject") {
                            query = not ? "-reject OR soft" : "reject -soft";
                        } else {
                            query = not ? selected.replace(/(\b\w+\b)/g, "-$1") : selected;
                        }

                        self.addFilter("action", query, ["action"]);
                    } else {
                        self.removeFilter("action");
                    }
                    self.filter();
                }
            });
            /* eslint-enable consistent-this, no-underscore-dangle, one-var-declaration-per-line */

            common.tables[table] = FooTable.init("#historyTable_" + table, {
                columns: columns,
                rows: items,
                expandFirst: expandFirst,
                paging: {
                    enabled: true,
                    limit: 5,
                    size: common.page_size[table]
                },
                filtering: {
                    enabled: true,
                    position: "left",
                    connectors: false
                },
                sorting: {
                    enabled: true
                },
                components: {
                    filtering: FooTable.actionFilter
                },
                on: {
                    "expand.ft.row": function (e, ft, row) {
                        setTimeout(() => {
                            const detail_row = row.$el.next();
                            const order = common.getSelector("selSymOrder_" + table);
                            detail_row.find(".btn-sym-" + table + "-" + order)
                                .addClass("active").siblings().removeClass("active");
                        }, 5);
                    }
                }
            });
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
                        if (typeof item[prop] === "string") {
                            item[prop] = common.escapeHTML(item[prop]);
                        }
                }
            }

            if (item.action === "clean" || item.action === "no action") {
                item.action = "<div style='font-size:11px' class='badge text-bg-success'>" + item.action + "</div>";
            } else if (item.action === "rewrite subject" || item.action === "add header" || item.action === "probable spam") {
                item.action = "<div style='font-size:11px' class='badge text-bg-warning'>" + item.action + "</div>";
            } else if (item.action === "spam" || item.action === "reject") {
                item.action = "<div style='font-size:11px' class='badge text-bg-danger'>" + item.action + "</div>";
            } else {
                item.action = "<div style='font-size:11px' class='badge text-bg-info'>" + item.action + "</div>";
            }

            const score_content = (item.score < item.required_score)
                ? "<span class='text-success'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>"
                : "<span class='text-danger'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>";

            item.score = {
                options: {
                    sortValue: item.score
                },
                value: score_content
            };
        };

        ui.unix_time_format = function (tm) {
            const date = new Date(tm ? tm * 1000 : 0);
            return (common.locale)
                ? date.toLocaleString(common.locale)
                : date.toLocaleString();
        };

        ui.process_history_v2 = function (data, table) {
            // Display no more than rcpt_lim recipients
            const rcpt_lim = 3;
            const items = [];
            const unsorted_symbols = [];
            const compare_function = get_compare_function(table);

            $("#selSymOrder_" + table + ", label[for='selSymOrder_" + table + "']").show();

            $.each(data.rows,
                (i, item) => {
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
                    Object.values(item.symbols).forEach((sym) => {
                        sym.str = '<span class="symbol-default ' + get_symbol_class(sym.name, sym.score) + '"><strong>';

                        if (sym.description) {
                            sym.str += '<abbr title="' + sym.description + '">' + sym.name + "</abbr>";
                        } else {
                            sym.str += sym.name;
                        }
                        sym.str += "</strong> (" + sym.score + ")</span>";

                        if (sym.options) {
                            sym.str += " [" + sym.options.join(",") + "]";
                        }
                    });
                    unsorted_symbols.push(item.symbols);
                    item.symbols = sort_symbols(item.symbols, compare_function);
                    if (table === "scan") {
                        item.unix_time = (new Date()).getTime() / 1000;
                    }
                    item.time = {
                        value: ui.unix_time_format(item.unix_time),
                        options: {
                            sortValue: item.unix_time
                        }
                    };
                    item.time_real = item.time_real.toFixed(3);
                    item.id = item["message-id"];

                    if (table === "history") {
                        let rcpt = {};
                        if (!item.rcpt_mime.length) {
                            rcpt = format_rcpt(true, false);
                        } else if (
                            $(item.rcpt_mime).not(item.rcpt_smtp).length !== 0 ||
                            $(item.rcpt_smtp).not(item.rcpt_mime).length !== 0
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

        ui.waitForRowsDisplayed = function (table, rows_total, callback, iteration) {
            let i = (typeof iteration === "undefined") ? 10 : iteration;
            const num_rows = $("#historyTable_" + table + " > tbody > tr:not(.footable-detail-row)").length;
            if (num_rows === common.page_size[table] ||
                num_rows === rows_total) {
                return callback();
            } else if (--i) {
                setTimeout(() => {
                    ui.waitForRowsDisplayed(table, rows_total, callback, i);
                }, 500);
            }
            return null;
        };

        return ui;
    });
