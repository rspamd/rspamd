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

/* global FooTable:false */

define(["jquery", "footable", "humanize"],
    function ($, _, Humanize) {
        "use strict";
        var page_size = {
            errors: 25,
            history: 25
        };

        function set_page_size(n, callback) {
            if (n !== page_size.history && n > 0) {
                page_size.history = n;
                if (callback) {
                    return callback(n);
                }
            }
            return null;
        }

        set_page_size($("#history_page_size").val());

        var ui = {};
        var prevVersion = null;
        var htmlEscapes = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            "\"": "&quot;",
            "'": "&#39;",
            "/": "&#x2F;",
            "`": "&#x60;",
            "=": "&#x3D;"
        };
        var htmlEscaper = /[&<>"'/`=]/g;
        var symbols = [];
        var symbolDescriptions = {};

        var escapeHTML = function (string) {
            return String(string).replace(htmlEscaper, function (match) {
                return htmlEscapes[match];
            });
        };

        var escape_HTML_array = function (arr) {
            arr.forEach(function (d, i) { arr[i] = escapeHTML(d); });
        };

        function unix_time_format(tm) {
            var date = new Date(tm ? tm * 1000 : 0);
            return date.toLocaleString();
        }

        function preprocess_item(item) {
            for (var prop in item) {
                if (!{}.hasOwnProperty.call(item, prop)) continue;
                switch (prop) {
                    case "rcpt_mime":
                    case "rcpt_smtp":
                        escape_HTML_array(item[prop]);
                        break;
                    case "symbols":
                        Object.keys(item.symbols).forEach(function (key) {
                            var sym = item.symbols[key];
                            if (!sym.name) {
                                sym.name = key;
                            }
                            sym.name = escapeHTML(sym.name);
                            if (sym.description) {
                                sym.description = escapeHTML(sym.description);
                            }

                            if (sym.options) {
                                escape_HTML_array(sym.options);
                            }
                        });
                        break;
                    default:
                        if (typeof item[prop] === "string") {
                            item[prop] = escapeHTML(item[prop]);
                        }
                }
            }

            if (item.action === "clean" || item.action === "no action") {
                item.action = "<div style='font-size:11px' class='label label-success'>" + item.action + "</div>";
            } else if (item.action === "rewrite subject" || item.action === "add header" || item.action === "probable spam") {
                item.action = "<div style='font-size:11px' class='label label-warning'>" + item.action + "</div>";
            } else if (item.action === "spam" || item.action === "reject") {
                item.action = "<div style='font-size:11px' class='label label-danger'>" + item.action + "</div>";
            } else {
                item.action = "<div style='font-size:11px' class='label label-info'>" + item.action + "</div>";
            }

            var score_content = (item.score < item.required_score)
                ? "<span class='text-success'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>"
                : "<span class='text-danger'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>";

            item.score = {
                options: {
                    sortValue: item.score
                },
                value: score_content
            };
        }

        function getSelector(id) {
            var e = document.getElementById(id);
            return e.options[e.selectedIndex].value;
        }

        function get_compare_function() {
            var compare_functions = {
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

            return compare_functions[getSelector("selSymOrder")];
        }

        function sort_symbols(o, compare_function) {
            return Object.keys(o)
                .map(function (key) {
                    return o[key];
                })
                .sort(compare_function)
                .map(function (e) { return e.str; })
                .join("<br>\n");
        }

        function process_history_v2(data) {
            // Display no more than rcpt_lim recipients
            var rcpt_lim = 3;
            var items = [];
            var unsorted_symbols = [];
            var compare_function = get_compare_function();

            $("#selSymOrder, label[for='selSymOrder']").show();

            $.each(data.rows,
                function (i, item) {
                    function more(p) {
                        var l = item[p].length;
                        return (l > rcpt_lim) ? " … (" + l + ")" : "";
                    }
                    function format_rcpt(smtp, mime) {
                        var full = "";
                        var shrt = "";
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
                        return {full:full, shrt:shrt};
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

                    preprocess_item(item);
                    Object.keys(item.symbols).forEach(function (key) {
                        var sym = item.symbols[key];
                        sym.str = '<span class="symbol-default ' + get_symbol_class(sym.name, sym.score) + '"><strong>';

                        if (sym.description) {
                            sym.str += '<abbr data-sym-key="' + key + '">' +
                                sym.name + "</abbr></strong> (" + sym.score + ")</span>";
                            // Store description for tooltip
                            symbolDescriptions[key] = sym.description;
                        } else {
                            sym.str += sym.name + "</strong> (" + sym.score + ")</span>";
                        }

                        if (sym.options) {
                            sym.str += " [" + sym.options.join(",") + "]";
                        }
                    });
                    unsorted_symbols.push(item.symbols);
                    item.symbols = sort_symbols(item.symbols, compare_function);
                    item.time = {
                        value: unix_time_format(item.unix_time),
                        options: {
                            sortValue: item.unix_time
                        }
                    };
                    var scan_time = item.time_real.toFixed(3) + " / " + item.time_virtual.toFixed(3);
                    item.scan_time = {
                        options: {
                            sortValue: item.time_real
                        },
                        value: scan_time
                    };
                    item.id = item["message-id"];

                    var rcpt = {};
                    if (!item.rcpt_mime.length) {
                        rcpt = format_rcpt(true, false);
                    } else if ($(item.rcpt_mime).not(item.rcpt_smtp).length !== 0 || $(item.rcpt_smtp).not(item.rcpt_mime).length !== 0) {
                        rcpt = format_rcpt(true, true);
                    } else {
                        rcpt = format_rcpt(false, true);
                    }
                    item.rcpt_mime_short = rcpt.shrt;
                    item.rcpt_mime = rcpt.full;

                    if (item.sender_mime !== item.sender_smtp) {
                        item.sender_mime = "[" + item.sender_smtp + "] " + item.sender_mime;
                    }
                    items.push(item);
                });

            return {items:items, symbols:unsorted_symbols};
        }

        function process_history_legacy(data) {
            var items = [];

            var compare = function (e1, e2) {
                return e1.name.localeCompare(e2.name);
            };

            $("#selSymOrder, label[for='selSymOrder']").hide();

            $.each(data, function (i, item) {
                item.time = unix_time_format(item.unix_time);
                preprocess_item(item);
                item.scan_time = {
                    options: {
                        sortValue: item.scan_time
                    },
                    value: item.scan_time
                };
                item.symbols = Object.keys(item.symbols)
                    .map(function (key) {
                        return item.symbols[key];
                    })
                    .sort(compare)
                    .map(function (e) { return e.name; })
                    .join(", ");
                item.time = {
                    value: unix_time_format(item.unix_time),
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
                    "minWidth": 88
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
                        '<div class="btn-group btn-group-xs btn-sym-order" data-toggle="buttons">' +
                            '<button type="button" class="btn btn-default btn-sym-magnitude" value="magnitude">Magnitude</button>' +
                            '<button type="button" class="btn btn-default btn-sym-score" value="score">Value</button>' +
                            '<button type="button" class="btn btn-default btn-sym-name" value="name">Name</button>' +
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
                formatter: Humanize.compactInteger
            }, {
                name: "scan_time",
                title: '<span title="real / virtual">Scan time</span>',
                breakpoints: "xs sm md",
                style: {
                    "font-size": "11px",
                    "maxWidth": 72
                },
                sortValue: function (val) { return Number(val.options.sortValue); }
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
                formatter: Humanize.compactInteger
            }, {
                name: "scan_time",
                title: '<span title="real / virtual">Scan time</span>',
                breakpoints: "xs sm",
                style: {
                    "font-size": "11px",
                    "maxWidth": 80
                },
                sortValue: function (val) { return Number(val.options.sortValue); }
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

        var process_functions = {
            2: process_history_v2,
            legacy: process_history_legacy
        };

        var columns = {
            2: columns_v2,
            legacy: columns_legacy
        };

        function process_history_data(data) {
            var pf = process_functions.legacy;

            if (data.version) {
                var strkey = data.version.toString();
                if (process_functions[strkey]) {
                    pf = process_functions[strkey];
                }
            }

            return pf(data);
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

        function drawTooltips() {
            // Update symbol description tooltips
            $.each(symbolDescriptions, function (key, description) {
                $("abbr[data-sym-key=" + key + "]").tooltip({
                    placement: "bottom",
                    html: true,
                    title: description
                });
            });
        }

        function initHistoryTable(rspamd, tables, data, items) {
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
                    var self = this, $form_grp = $("<div/>", {
                        class: "form-group"
                    }).append($("<label/>", {
                        class: "sr-only",
                        text: "Action"
                    })).prependTo(self.$form);

                    self.$action = $("<select/>", {
                        class: "form-control"
                    }).on("change", {
                        self: self
                    }, self._onStatusDropdownChanged).append(
                        $("<option/>", {
                            text: self.def
                        })).appendTo($form_grp);

                    $.each(self.actions, function (i, action) {
                        self.$action.append($("<option/>").text(action));
                    });
                },
                _onStatusDropdownChanged: function (e) {
                    var self = e.data.self, selected = $(this).val();
                    if (selected !== self.def) {
                        if (selected === "reject") {
                            self.addFilter("action", "reject -soft", ["action"]);
                        } else {
                            self.addFilter("action", selected, ["action"]);
                        }
                    } else {
                        self.removeFilter("action");
                    }
                    self.filter();
                },
                draw: function () {
                    this._super();
                    var action = this.find("action");
                    if (action instanceof FooTable.Filter) {
                        if (action.query.val() === "reject -soft") {
                            this.$action.val("reject");
                        } else {
                            this.$action.val(action.query.val());
                        }
                    } else {
                        this.$action.val(this.def);
                    }
                }
            });
            /* eslint-enable consistent-this, no-underscore-dangle, one-var-declaration-per-line */

            tables.history = FooTable.init("#historyTable", {
                columns: get_history_columns(data),
                rows: items,
                paging: {
                    enabled: true,
                    limit: 5,
                    size: page_size.history
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
                    "ready.ft.table": drawTooltips,
                    "after.ft.sorting": drawTooltips,
                    "after.ft.paging": drawTooltips,
                    "after.ft.filtering": drawTooltips,
                    "expand.ft.row": function (e, ft, row) {
                        setTimeout(function () {
                            var detail_row = row.$el.next();
                            var order = getSelector("selSymOrder");
                            detail_row.find(".btn-sym-" + order)
                                .addClass("active").siblings().removeClass("active");
                        }, 5);
                    }
                }
            });
        }

        function destroyTable(tables, table) {
            if (tables[table]) {
                tables[table].destroy();
                delete tables[table];
            }
        }

        ui.getHistory = function (rspamd, tables) {
            function waitForRowsDisplayed(rows_total, callback, iteration) {
                var i = (typeof iteration === "undefined") ? 10 : iteration;
                var num_rows = $("#historyTable > tbody > tr").length;
                if (num_rows === page_size.history ||
                    num_rows === rows_total) {
                    return callback();
                } else if (--i) {
                    setTimeout(function () {
                        waitForRowsDisplayed(rows_total, callback, i);
                    }, 500);
                }
                return null;
            }

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
                        var o = process_history_data(data);
                        var items = o.items;
                        symbols = o.symbols;

                        if (Object.prototype.hasOwnProperty.call(tables, "history") &&
                            version === prevVersion) {
                            tables.history.rows.load(items);
                            if (version) { // Non-legacy
                                // Is there a way to get an event when all rows are loaded?
                                waitForRowsDisplayed(items.length, function () {
                                    drawTooltips();
                                });
                            }
                        } else {
                            destroyTable(tables, "history");
                            // Is there a way to get an event when the table is destroyed?
                            setTimeout(function () {
                                initHistoryTable(rspamd, tables, data, items);
                            }, 200);
                        }
                        prevVersion = version;
                    } else {
                        destroyTable(tables, "history");
                    }
                },
                errorMessage: "Cannot receive history",
            });
        };

        ui.setup = function (rspamd, tables) {
            function change_symbols_order(order) {
                $(".btn-sym-" + order).addClass("active").siblings().removeClass("active");
                var compare_function = get_compare_function();
                $.each(tables.history.rows.all, function (i, row) {
                    var cell_val = sort_symbols(symbols[i], compare_function);
                    row.cells[8].val(cell_val, false, true);
                });
                drawTooltips();
            }

            $("#updateHistory").off("click");
            $("#updateHistory").on("click", function (e) {
                e.preventDefault();
                ui.getHistory(rspamd, tables);
            });
            $("#selSymOrder").unbind().change(function () {
                var order = this.value;
                change_symbols_order(order);
            });
            $("#history_page_size").change(function () {
                set_page_size(this.value, function (n) { tables.history.pageSize(n); });
            });
            $(document).on("click", ".btn-sym-order button", function () {
                var order = this.value;
                $("#selSymOrder").val(order);
                change_symbols_order(order);
            });

            // @reset history log
            $("#resetHistory").off("click");
            $("#resetHistory").on("click", function (e) {
                e.preventDefault();
                if (!confirm("Are you sure you want to reset history log?")) { // eslint-disable-line no-alert
                    return;
                }
                destroyTable(tables, "history");
                destroyTable(tables, "errors");

                rspamd.query("historyreset", {
                    success: function () {
                        ui.getHistory(rspamd, tables);
                        ui.getErrors(rspamd, tables);
                    },
                    errorMessage: "Cannot reset history log"
                });
            });
        };

        function initErrorsTable(tables, rows) {
            tables.errors = FooTable.init("#errorsLog", {
                columns: [
                    {sorted:true, direction:"DESC", name:"ts", title:"Time", style:{"font-size":"11px", "width":300, "maxWidth":300}},
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
                    size: page_size.errors
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
                            value: unix_time_format(item.ts),
                            options: {
                                sortValue: item.ts
                            }
                        };
                    });
                    if (Object.prototype.hasOwnProperty.call(tables, "errors")) {
                        tables.errors.rows.load(rows);
                    } else {
                        initErrorsTable(tables, rows);
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
