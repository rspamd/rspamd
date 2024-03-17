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

define(["jquery", "app/common", "footable"],
    ($, common) => {
        "use strict";
        const ui = {};
        let altered = {};

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
                    items.push(item);
                });
            });

            // For better mean calculations
            const avg_freq = freqs
                .sort((a, b) => Number(a) < Number(b))
                .reduce((f1, acc) => f1 + acc) / (freqs.length !== 0 ? freqs.length : 1.0);
            let mult = 1.0;
            let exp = 0.0;

            if (avg_freq > 0.0) {
                while (mult * avg_freq < 1.0) {
                    mult *= 10;
                    exp++;
                }
            }
            $.each(items, (i, item) => {
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
        ui.getSymbols = function () {
            $("#refresh, #updateSymbols").attr("disabled", true);
            clear_altered();
            common.query("symbols", {
                success: function (json) {
                    const [{data}] = json;
                    const items = process_symbols_data(data);

                    /* eslint-disable consistent-this, no-underscore-dangle, one-var-declaration-per-line */
                    FooTable.groupFilter = FooTable.Filtering.extend({
                        construct: function (instance) {
                            this._super(instance);
                            [,this.groups] = items;
                            this.def = "Any group";
                            this.$group = null;
                        },
                        $create: function () {
                            this._super();
                            const self = this;
                            const $form_grp = $("<div/>", {
                                class: "form-group"
                            }).append($("<label/>", {
                                class: "sr-only",
                                text: "Group"
                            })).prependTo(self.$form);

                            self.$group = $("<select/>", {
                                class: "form-select"
                            }).on("change", {
                                self: self
                            }, self._onStatusDropdownChanged).append(
                                $("<option/>", {
                                    text: self.def
                                })).appendTo($form_grp);

                            $.each(self.groups, (i, group) => {
                                self.$group.append($("<option/>").text(group));
                            });

                            common.appendButtonsToFtFilterDropdown(self);
                        },
                        _onStatusDropdownChanged: function (e) {
                            const {self} = e.data;
                            const selected = $(this).val();
                            if (selected !== self.def) {
                                self.addFilter("group", selected, ["group"]);
                            } else {
                                self.removeFilter("group");
                            }
                            self.filter();
                        },
                        draw: function () {
                            this._super();
                            const group = this.find("group");
                            if (group instanceof FooTable.Filter) {
                                this.$group.val(group.query.val());
                            } else {
                                this.$group.val(this.def);
                            }
                        }
                    });
                    /* eslint-enable consistent-this, no-underscore-dangle, one-var-declaration-per-line */

                    common.tables.symbols = FooTable.init("#symbolsTable", {
                        breakpoints: common.breakpoints,
                        cascade: true,
                        columns: [
                            {sorted: true, direction: "ASC", name: "group", title: "Group"},
                            {name: "symbol", title: "Symbol"},
                            {name: "description", title: "Description", breakpoints: "md"},
                            {name: "weight", title: "Score"},
                            {name: "frequency",
                                title: "Frequency",
                                breakpoints: "md",
                                sortValue: function (value) { return Number(value).toFixed(2); }},
                            {name: "time", title: "Avg. time", breakpoints: "md"},
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
                                if (common.read_only) {
                                    $(".mb-disabled").attr("disabled", true);
                                }
                            },
                            "postdraw.ft.table":
                                () => $("#refresh, #updateSymbols").removeAttr("disabled")
                        }
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
                    const [items] = process_symbols_data(data[0].data);
                    common.tables.symbols.rows.load(items);
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
