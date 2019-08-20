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

define(["jquery", "footable"],
    function ($) {
        "use strict";
        var ui = {};

        function saveSymbols(rspamd, action, id, server) {
            var inputs = $("#" + id + " :input[data-role=\"numerictextbox\"]");
            var url = action;
            var values = [];
            $(inputs).each(function () {
                values.push({
                    name: $(this).attr("id").substring(5),
                    value: parseFloat($(this).val())
                });
            });

            rspamd.query(url, {
                success: function () {
                    rspamd.alertMessage("alert-modal alert-success", "Symbols successfully saved");
                },
                errorMessage: "Save symbols error",
                method: "POST",
                params: {
                    data: JSON.stringify(values),
                    dataType: "json",
                },
                server: server
            });
        }
        function decimalStep(number) {
            var digits = Number(number).toFixed(20).replace(/^-?\d*\.?|0+$/g, "").length;
            return (digits === 0 || digits > 4) ? 0.1 : 1.0 / Math.pow(10, digits);
        }
        function process_symbols_data(rspamd, data) {
            var items = [];
            var lookup = {};
            var freqs = [];
            var distinct_groups = [];
            var selected_server = rspamd.getSelector("selSrv");

            data.forEach(function (group) {
                group.rules.forEach(function (item) {
                    var max = 20;
                    var min = -20;
                    if (item.weight > max) {
                        max = item.weight * 2;
                    }
                    item.group = group.group;
                    if (item.weight < min) {
                        min = item.weight * 2;
                    }
                    var label_class = "";
                    if (item.weight < 0) {
                        label_class = "scorebar-ham";
                    } else if (item.weight > 0) {
                        label_class = "scorebar-spam";
                    }
                    item.weight = "<input class=\"form-control input-sm mb-disabled " + label_class +
                    "\" data-role=\"numerictextbox\" autocomplete=\"off\" type=\"number\" class=\"input\" min=\"" +
                    min + "\" max=\"" +
                    max + "\" step=\"" + decimalStep(item.weight) +
                    "\" tabindex=\"1\" value=\"" + Number(item.weight).toFixed(3) +
                    "\" id=\"_sym_" + item.symbol + "\"></input>";
                    if (!item.time) {
                        item.time = 0;
                    }
                    item.time = Number(item.time).toFixed(2) + "s";
                    if (!item.frequency) {
                        item.frequency = 0;
                    }
                    freqs.push(item.frequency);
                    item.frequency = Number(item.frequency).toFixed(2);
                    if (!(item.group in lookup)) {
                        lookup[item.group] = 1;
                        distinct_groups.push(item.group);
                    }
                    item.save =
                        "<button data-save=\"" + selected_server +
                        "\" title=\"Save changes to the selected server\" " +
                        "type=\"button\" class=\"btn btn-primary btn-sm mb-disabled\">Save</button>&nbsp;" +
                        "<button data-save=\"All SERVERS" +
                        "\" title=\"Save changes to all servers\" " +
                        "type=\"button\" class=\"btn btn-primary btn-sm mb-disabled\">Save in cluster</button>";
                    items.push(item);
                });
            });

            // For better mean calculations
            var avg_freq = freqs.sort(function (a, b) {
                return Number(a) < Number(b);
            }).reduce(function (f1, acc) {
                return f1 + acc;
            }) / (freqs.length !== 0 ? freqs.length : 1.0);
            var mult = 1.0;
            var exp = 0.0;

            if (avg_freq > 0.0) {
                while (mult * avg_freq < 1.0) {
                    mult *= 10;
                    exp++;
                }
            }
            $.each(items, function (i, item) {
                item.frequency = Number(item.frequency) * mult;

                if (exp > 0) {
                    item.frequency = item.frequency.toFixed(2) + "e-" + exp;
                } else {
                    item.frequency = item.frequency.toFixed(2);
                }
            });
            return [items, distinct_groups];
        }
        // @get symbols into modal form
        ui.getSymbols = function (rspamd, tables, checked_server) {
            rspamd.query("symbols", {
                success: function (json) {
                    var data = json[0].data;
                    var items = process_symbols_data(rspamd, data);

                    /* eslint-disable consistent-this, no-underscore-dangle, one-var-declaration-per-line */
                    FooTable.groupFilter = FooTable.Filtering.extend({
                        construct: function (instance) {
                            this._super(instance);
                            this.groups = items[1];
                            this.def = "Any group";
                            this.$group = null;
                        },
                        $create: function () {
                            this._super();
                            var self = this, $form_grp = $("<div/>", {
                                class: "form-group"
                            }).append($("<label/>", {
                                class: "sr-only",
                                text: "Group"
                            })).prependTo(self.$form);

                            self.$group = $("<select/>", {
                                class: "form-control"
                            }).on("change", {
                                self: self
                            }, self._onStatusDropdownChanged).append(
                                $("<option/>", {
                                    text: self.def
                                })).appendTo($form_grp);

                            $.each(self.groups, function (i, group) {
                                self.$group.append($("<option/>").text(group));
                            });
                        },
                        _onStatusDropdownChanged: function (e) {
                            var self = e.data.self, selected = $(this).val();
                            if (selected !== self.def) {
                                self.addFilter("group", selected, ["group"]);
                            } else {
                                self.removeFilter("group");
                            }
                            self.filter();
                        },
                        draw: function () {
                            this._super();
                            var group = this.find("group");
                            if (group instanceof FooTable.Filter) {
                                this.$group.val(group.query.val());
                            } else {
                                this.$group.val(this.def);
                            }
                        }
                    });
                    /* eslint-enable consistent-this, no-underscore-dangle, one-var-declaration-per-line */

                    tables.symbols = FooTable.init("#symbolsTable", {
                        columns: [
                            {sorted:true, direction:"ASC", name:"group", title:"Group", style:{"font-size":"11px"}},
                            {name:"symbol", title:"Symbol", style:{"font-size":"11px"}},
                            {name:"description", title:"Description", breakpoints:"xs sm", style:{"font-size":"11px"}},
                            {name:"weight", title:"Score", style:{"font-size":"11px"}},
                            {name:"frequency", title:"Frequency", breakpoints:"xs sm", style:{"font-size":"11px"}, sortValue:function (value) { return Number(value).toFixed(2); }},
                            {name:"time", title:"Avg. time", breakpoints:"xs sm", style:{"font-size":"11px"}},
                            {name:"save", title:"Save", style:{"font-size":"11px"}},
                        ],
                        rows: items[0],
                        paging: {
                            enabled: true,
                            limit: 5,
                            size: 25
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
                            filtering: FooTable.groupFilter
                        },
                        on: {
                            "ready.ft.table": function () {
                                if (rspamd.read_only) {
                                    $(".mb-disabled").attr("disabled", true);
                                }
                            }
                        }
                    });
                },
                server: (checked_server === "All SERVERS") ? "local" : checked_server
            });
            $("#symbolsTable")
                .off("click", ":button")
                .on("click", ":button", function () {
                    var value = $(this).data("save");
                    if (!value) return;
                    saveSymbols(rspamd, "./savesymbols", "symbolsTable", value);
                });
        };

        ui.setup = function (rspamd, tables) {
            $("#updateSymbols").on("click", function (e) {
                e.preventDefault();
                var checked_server = rspamd.getSelector("selSrv");
                rspamd.query("symbols", {
                    success: function (data) {
                        var items = process_symbols_data(rspamd, data[0].data)[0];
                        tables.symbols.rows.load(items);
                    },
                    server: (checked_server === "All SERVERS") ? "local" : checked_server
                });
            });
        };

        return ui;
    });
