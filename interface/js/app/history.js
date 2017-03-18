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

define(['jquery', 'datatables', 'footable'],
function($) {
    var interface = {};

    function unix_time_format(tm) {
        var date = new Date(tm ? tm * 1000 : 0);

        return date.toLocaleString();
    }

    function process_history_v2(data) {
        var items = [];

        $.each(data.rows.map(function(elt) { return JSON.parse(elt);}),
          function (i, item) {
            if (item.action === 'clean' || item.action === 'no action') {
                item.action = "<div style='font-size:11px' class='label label-success'>" + item.action + "</div>";
            } else if (item.action === 'rewrite subject' || item.action === 'add header' || item.action === 'probable spam') {
                item.action = "<div style='font-size:11px' class='label label-warning'>" + item.action + "</div>";
            } else if (item.action === 'spam' || item.action === 'reject') {
                item.action = "<div style='font-size:11px' class='label label-danger'>" + item.action + "</div>";
            } else {
                item.action = "<div style='font-size:11px' class='label label-info'>" + item.action + "</div>";
            }

            if (item.score < item.required_score) {
                item.score = "<span class='text-success'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>";
            } else {
                item.score = "<span class='text-danger'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>";
            }

            if (item.user == null) {
                item.user = "none";
            }

            var symbols = Object.keys(item.symbols);
            item.symbols = symbols
            item.time = unix_time_format(item.unix_time);
            item.scan_time = item.time_real.toFixed(3) + '/' +
                item.time_virtual.toFixed(3);
            item.id = item['message-id'];
            items.push(item);
        });

        return items;
    }

    function process_history_legacy(data) {
        var items = [];

        $.each(data, function (i, item) {
            if (item.action === 'clean' || item.action === 'no action') {
                item.action = "<div style='font-size:11px' class='label label-success'>" + item.action + "</div>";
            } else if (item.action === 'rewrite subject' || item.action === 'add header' || item.action === 'probable spam') {
                item.action = "<div style='font-size:11px' class='label label-warning'>" + item.action + "</div>";
            } else if (item.action === 'spam' || item.action === 'reject') {
                item.action = "<div style='font-size:11px' class='label label-danger'>" + item.action + "</div>";
            } else {
                item.action = "<div style='font-size:11px' class='label label-info'>" + item.action + "</div>";
            }

            if (item.score < item.required_score) {
                item.score = "<span class='text-success'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>";
            } else {
                item.score = "<span class='text-danger'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>";
            }

            if (item.user == null) {
                item.user = "none";
            }

            items.push(item)
        });

        return items;
    }

    var process_functions = {
       "2": process_history_v2,
       "legacy": process_history_legacy
    }

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

    interface.getHistory = function (rspamd, tables) {
        if (tables.history !== undefined) {
            var history_length = document.getElementsByName('historyLog_length')[0];
            if (history_length !== undefined) {
                history_length = parseInt(history_length.value);
            } else {
                history_length = 10;
            }
            tables.history.destroy();
            tables.history = undefined;
            $('#historyLog').children('tbody').remove();
        }


        FooTable.actionFilter = FooTable.Filtering.extend({
        construct : function(instance) {
            this._super(instance);
            this.actions = [ 'reject', 'add_header', 'greylist',
                    'no action', 'soft reject' ];
            this.def = 'Any action';
            this.$action = null;
        },
        $create : function() {
            this._super();
            var self = this, $form_grp = $('<div/>', {
                'class' : 'form-group'
            }).append($('<label/>', {
                'class' : 'sr-only',
                text : 'Action'
            })).prependTo(self.$form);

            self.$action = $('<select/>', {
                'class' : 'form-control'
            }).on('change', {
                self : self
            }, self._onStatusDropdownChanged).append(
                    $('<option/>', {
                        text : self.def
                    })).appendTo($form_grp);

            $.each(self.actions, function(i, action) {
                self.$action.append($('<option/>').text(action));
            });
        },
        _onStatusDropdownChanged : function(e) {
            var self = e.data.self, selected = $(this).val();
            if (selected !== self.def) {
                self.addFilter('action', selected, [ 'action' ]);
            } else {
                self.removeFilter('action');
            }
            self.filter();
        },
        draw : function() {
            this._super();
            var action = this.find('action');
            if (action instanceof FooTable.Filter) {
                this.$action.val(action.query.val());
            } else {
                this.$action.val(this.def);
            }
        }
        });

        $.ajax({
            dataType: 'json',
            url: 'history',
            jsonp: false,
            beforeSend: function (xhr) {
                xhr.setRequestHeader('Password', rspamd.getPassword());
            },
            error: function () {
                rspamd.alertMessage('alert-error', 'Cannot receive history');
            },
            success: function (data) {
                var items = process_history_data(data);

                $('#historyTable').footable({
                    "columns": [
                      {"name":"id","title":"ID","style":{"font-size":"11px","width":300,"maxWidth":300,"overflow":"hidden","textOverflow":"ellipsis","wordBreak":"keep-all","whiteSpace":"nowrap"}},
                      {"name":"ip","title":"IP address","breakpoints":"xs sm","style":{"font-size":"11px","width":150,"maxWidth":150}},
                      {"name":"action","title":"Action","style":{"font-size":"11px","width":110,"maxWidth":110}},
                      {"name":"score","title":"Score","style":{"font-size":"11px","maxWidth":110}},
                      {"name":"symbols","title":"Symbols","breakpoints":"all","style":{"font-size":"11px","width":550,"maxWidth":550}},
                      {"name":"size","title":"Message size","breakpoints":"xs sm","style":{"font-size":"11px","width":120,"maxWidth":120}},
                      {"name":"scan_time","title":"Scan time","breakpoints":"xs sm","style":{"font-size":"11px","maxWidth":80}},
                      {"sorted": true,"direction": "DESC","name":"time","title":"Time","style":{"font-size":"11px"}},
                      {"name":"user","title":"Authenticated user","breakpoints":"xs sm","style":{"font-size":"11px","width":200,"maxWidth":200}}
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
                      filtering: FooTable.actionFilter
                    }
                });
            }
        });
    };

    interface.getErrors = function(rspamd, tables) {
        if (rspamd.read_only) return;

        if (tables.errors) {
            tables.errors.destroy();
            $('#errorsLog').children('tbody').remove();
            tables.errors = undefined;
        }

        var items = [];
        $.ajax({
            dataType: 'json',
            url: 'errors',
            jsonp: false,
            beforeSend: function (xhr) {
                xhr.setRequestHeader('Password', rspamd.getPassword());
            },
            error: function () {
                rspamd.alertMessage('alert-error', 'Cannot receive errors');
            },
            success: function (data) {
                $.each(data, function (i, item) {

                    items.push(
                        '<tr><td data-order="' + item.ts + '">' + new Date(item.ts * 1000) + '</td>' +
                        '<td data-order="' + item.type + '">' + item.type + '</td>' +
                        '<td data-order="' + item.pid + '">' + item.pid + '</td>' +
                        '<td data-order="' + item.module + '">' + item.module + '</td>' +
                        '<td data-order="' + item.id + '">' + item.id + '</td>' +
                        '<td data-order="' + item.message + '"><div class="cell-overflow" tabindex="1" title="' + item.message + '">' + item.message + '</div></td></tr>'
                    );
                });
                $('<tbody/>', {
                    html: items.join('')
                }).insertAfter('#errorsLog thead');
                tables.errors = $('#errorsLog').DataTable({
                    "paging": true,
                    "orderMulti": false,
                    "order": [
                        [0, "desc"],
                    ],
                    "info": false,
                    "columns": [
                        {"width": "15%", "searchable": true, "orderable": true, "type": "num"},
                        {"width": "5%", "searchable": true, "orderable": true},
                        {"width": "5%", "searchable": true, "orderable": true},
                        {"width": "3%", "searchable": true, "orderable": true},
                        {"width": "3%", "searchable": true, "orderable": true},
                        {"width": "65%", "searchable": true, "orderable": true},
                    ],
                });
                tables.errors.columns.adjust().draw();
            }
        });
    };

    interface.setup = function(rspamd, tables) {
        $('#updateHistory').on('click', function () {
            interface.getHistory(rspamd, tables);
        });
        $('#updateErrors').on('click', function () {
            interface.getErrors(rspamd, tables);
        });
                // @reset history log
        $('#resetHistory').on('click', function () {
            if (!confirm("Are you sure you want to reset history log?")) {
                return;
            }
            if (tables.history) {
                tables.history.destroy();
                tables.history = undefined;
                $('#historyLog').children('tbody').remove();
            }
            $.ajax({
                dataType: 'json',
                type: 'GET',
                jsonp: false,
                url: 'historyreset',
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', rspamd.getPassword());
                },
                success: function () {
                    interface.getHistory(rspamd, tables);
                    interface.getErrors(rspamd, tables);
                },
                error: function (data) {
                    rspamd.alertMessage('alert-modal alert-error', data.statusText);
                }
            });
        });
    };
    return interface;
});