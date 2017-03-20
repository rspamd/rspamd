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

define(['jquery', 'footable'],
function($) {
    var interface = {}

    function saveSymbols(rspamd, action, id, is_cluster) {
        var inputs = $('#' + id + ' :input[data-role="numerictextbox"]');
        var url = action;
        var values = [];
        $(inputs).each(function () {
            values.push({
                name: $(this).attr('id').substring(5),
                value: parseFloat($(this).val())
            });
        });

        if (is_cluster) {
            rspamd.queryNeighbours(url, function () {
                rspamd.alertMessage('alert-modal alert-success', 'Symbols successfully saved');
            }, function (serv, qXHR, textStatus, errorThrown) {
                rspamd.alertMessage('alert-modal alert-error',
                        'Save symbols error on ' +
                        serv.name + ': ' + errorThrown);
            }, "POST", {}, {
                data: JSON.stringify(values),
                dataType: "json",
            });
        }
        else {
            $.ajax({
                data: JSON.stringify(values),
                dataType: 'json',
                type: 'POST',
                url: url,
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', rspamd.getPassword());
                },
                success: function () {
                    rspamd.alertMessage('alert-modal alert-success', 'Symbols successfully saved');
                },
                error: function (data) {
                    rspamd.alertMessage('alert-modal alert-error', data.statusText);
                }
            });
        }
    }
    function decimalStep(number) {
        var digits = ((+number).toFixed(20)).replace(/^-?\d*\.?|0+$/g, '').length;
        if (digits === 0 || digits > 4) {
            return 0.1;
        } else {
            return 1.0 / (Math.pow(10, digits));
        }
    }
    // @get symbols into modal form
    interface.getSymbols = function(rspamd, tables, checked_server) {
        var symbols = tables.symbols
        if (symbols) {
            symbols.destroy();
            tables.symbols = undefined;
            $('#symbolsTable').children('tbody').remove();
        }

        var items = [];
        $.ajax({
            dataType: 'json',
            type: 'GET',
            url: 'symbols',
            jsonp: false,
            beforeSend: function (xhr) {
                xhr.setRequestHeader('Password', rspamd.getPassword());
            },
            success: function (data) {
                var distinct_groups = [];
                var lookup = {};
                $.each(data, function (i, group) {
                    $.each(group.rules, function (i, item) {
                        var max = 20;
                        var min = -20;
                        if (item.weight > max) {
                            max = item.weight * 2;
                        }
                        item.group = group.group
                        if (item.weight < min) {
                            min = item.weight * 2;
                        }
                        var label_class = '';
                        if (item.weight < 0) {
                            label_class = 'scorebar-ham';
                        } else {
                            label_class = 'scorebar-spam';
                        }
                        item.weight = '<input class="form-control input-sm mb-disabled ' + label_class +
                            '" data-role="numerictextbox" autocomplete="off" "type="number" class="input" min="' +
                            min + '" max="' +
                            max + '" step="' + decimalStep(item.weight) +
                            '" tabindex="1" value="' + Number(item.weight).toFixed(3) +
                            '" id="_sym_' + item.symbol + '"></input>'
                        if (!item.time) {
                            item.time = 0;
                        }
                        item.time = Number(item.time).toFixed(2) + 's'
                        if (!item.frequency) {
                            item.frequency = 0;
                        }
                        item.frequency = Number(item.frequency).toFixed(2)
                        if (!(item.group in lookup)) {
                          lookup[item.group] = 1;
                          distinct_groups.push(item.group);
                        }
                        item.save = '<button type="button" data-save="local" class="btn btn-primary btn-sm mb-disabled">Save</button>' +
                        '&nbsp;<button data-save="cluster" type="button" class="btn btn-primary btn-sm mb-disabled">Save in cluster</button>';
                        items.push(item)
                    });
                });
                FooTable.groupFilter = FooTable.Filtering.extend({
                construct : function(instance) {
                    this._super(instance);
                    this.groups = distinct_groups;
                    this.def = 'Any group';
                    this.$group = null;
                },
                $create : function() {
                    this._super();
                    var self = this, $form_grp = $('<div/>', {
                        'class' : 'form-group'
                    }).append($('<label/>', {
                        'class' : 'sr-only',
                        text : 'Group'
                    })).prependTo(self.$form);

                    self.$group = $('<select/>', {
                        'class' : 'form-control'
                    }).on('change', {
                        self : self
                    }, self._onStatusDropdownChanged).append(
                            $('<option/>', {
                                text : self.def
                            })).appendTo($form_grp);

                    $.each(self.groups, function(i, group) {
                        self.$group.append($('<option/>').text(group));
                    });
                },
                _onStatusDropdownChanged : function(e) {
                    var self = e.data.self, selected = $(this).val();
                    if (selected !== self.def) {
                        self.addFilter('group', selected, [ 'group' ]);
                    } else {
                        self.removeFilter('group');
                    }
                    self.filter();
                },
                draw : function() {
                    this._super();
                    var group = this.find('group');
                    if (group instanceof FooTable.Filter) {
                        this.$group.val(group.query.val());
                    } else {
                        this.$group.val(this.def);
                    }
                }
                });

                $('#symbolsTable').footable({
                    "columns": [
                      {"sorted": true,"direction": "ASC", "name":"group","title":"Group","style":{"font-size":"11px"}},
                      {"name":"symbol","title":"Symbol","style":{"font-size":"11px"}},
                      {"name":"description","title":"Description","breakpoints":"xs sm","style":{"font-size":"11px"}},
                      {"name":"weight","title":"Score","style":{"font-size":"11px"}},
                      {"name":"frequency","title":"Frequency","breakpoints":"xs sm","style":{"font-size":"11px"}},
                      {"name":"time","title":"Avg. time","breakpoints":"xs sm","style":{"font-size":"11px"}},
                      {"name":"save","title":"Save","style":{"font-size":"11px"}},
                    ],
                    "rows": items,
                    "paging": {
                      "enabled": true,
                      "limit": 5,
                      "size": 25
                    },
                    "filtering": {
                      "enabled": true,
                      "position": "left"
                    },
                    "sorting": {
                      "enabled": true
                    },
                    components: {
                      filtering: FooTable.groupFilter
                    }
                }, function tableHook() {
                  $('#symbolsTable :button').on('click', function() {
                    var value = $(this).data('save');
                    if (!value) return
                    saveSymbols(rspamd, "./savesymbols", "symbolsTable", value == 'cluster');
                  });
                });
                if (rspamd.read_only) {
                    $( ".mb-disabled" ).attr('disabled', true);
                }
            },
            error: function (data) {
                rspamd.alertMessage('alert-modal alert-error', data.statusText);
            }
        });
    };

    interface.setup = function(rspamd, tables) {
        $('#updateSymbols').on('click', function () {
            interface.getSymbols(rspamd, tables);
        });
    };

    return interface;
});