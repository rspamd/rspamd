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

define(['jquery', 'datatables'],
function($) {
    var interface = {};

    function unix_time_format(tm) {
        var date = new Date(tm*1000);

        return date.toLocaleString();
    }

    function process_history_v2(data) {
        var items = [];

        $.each(data.rows.map(function(elt) { return JSON.parse(elt);}),
          function (i, item) {
            var action;

            if (item.action === 'clean' || item.action === 'no action') {
                action = 'label-success';
            } else if (item.action === 'rewrite subject' || item.action === 'add header' || item.action === 'probable spam') {
                action = 'label-warning';
            } else if (item.action === 'spam' || item.action === 'reject') {
                action = 'label-danger';
            } else {
                action = 'label-info';
            }

            var score;
            if (item.score < item.required_score) {
                score = 'label-success';
            } else {
                score = 'label-danger';
            }

            console.log(item)

            items.push(
                    '<tr><td data-order="' + item.unix_time + '">' + unix_time_format(item.unix_time) + '</td>' +
                    '<td data-order="' + item.id + '"><div class="cell-overflow" tabindex="1" title="' + item.id + '">' + item.id + '</div></td>' +
                    '<td data-order="' + item.ip + '"><div class="cell-overflow" tabindex="1" title="' + item.ip + '">' + item.ip + '</div></td>' +
                    '<td data-order="' + item.action + '"><span class="label ' + action + '">' + item.action + '</span></td>' +
                    '<td data-order="' + item.score + '"><span class="label ' + score + '">' + item.score.toFixed(2) + ' / ' + item.required_score.toFixed(2) + '</span></td>' +
                    '<td data-order="' + item.symbols + '"><div class="cell-overflow" tabindex="1" title="' + item.symbols + '">' + item.symbols + '</div></td>' +
                    '<td data-order="' + item.size + '">' + item.size + '</td>' +
                    '<td data-order="' + item['time-real'] + '">' + item['time-real'].toFixed(3) + '/' + item['time-virtual'].toFixed(3) + '</td>' +
                    '<td data-order="' + item.user + '"><div class="cell-overflow" tabindex="1" "title="' + item.user + '">' + item.user + '</div></td></tr>');
        });

        return items;
    }

    function process_history_legacy(data) {
        var items = [];

        $.each(data, function (i, item) {
            var action;

            if (item.action === 'clean' || item.action === 'no action') {
                action = 'label-success';
            } else if (item.action === 'rewrite subject' || item.action === 'add header' || item.action === 'probable spam') {
                action = 'label-warning';
            } else if (item.action === 'spam' || item.action === 'reject') {
                action = 'label-danger';
            } else {
                action = 'label-info';
            }

            var score;
            if (item.score < item.required_score) {
                score = 'label-success';
            } else {
                score = 'label-danger';
            }

            items.push(
                    '<tr><td data-order="' + item.unix_time + '">' + item.time + '</td>' +
                    '<td data-order="' + item.id + '"><div class="cell-overflow" tabindex="1" title="' + item.id + '">' + item.id + '</div></td>' +
                    '<td data-order="' + item.ip + '"><div class="cell-overflow" tabindex="1" title="' + item.ip + '">' + item.ip + '</div></td>' +
                    '<td data-order="' + item.action + '"><span class="label ' + action + '">' + item.action + '</span></td>' +
                    '<td data-order="' + item.score + '"><span class="label ' + score + '">' + item.score.toFixed(2) + ' / ' + item.required_score.toFixed(2) + '</span></td>' +
                    '<td data-order="' + item.symbols + '"><div class="cell-overflow" tabindex="1" title="' + item.symbols + '">' + item.symbols + '</div></td>' +
                    '<td data-order="' + item.size + '">' + item.size + '</td>' +
                    '<td data-order="' + item.scan_time + '">' + item.scan_time.toFixed(3) + '</td>' +
                    '<td data-order="' + item.user + '"><div class="cell-overflow" tabindex="1" "title="' + item.user + '">' + item.user + '</div></td></tr>');
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

                $('<tbody/>', {
                    html: items.join('')
                }).insertAfter('#historyLog thead');
                tables.history = $('#historyLog').DataTable({
                    "aLengthMenu": [
                        [100, 200, -1],
                        [100, 200, "All"]
                    ],
                    "bStateSave": true,
                    "order": [
                        [0, "desc"]
                    ],
                    "pageLength": history_length
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