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
    var interface = {}

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
                $.each(data, function (i, group) {
                    $.each(group.rules, function (i, item) {
                        var max = 20;
                        var min = -20;
                        if (item.weight > max) {
                            max = item.weight * 2;
                        }
                        if (item.weight < min) {
                            min = item.weight * 2;
                        }
                        var label_class = '';
                        if (item.weight < 0) {
                            label_class = 'scorebar-ham';
                        } else {
                            label_class = 'scorebar-spam';
                        }

                        if (!item.time) {
                            item.time = 0;
                        }
                        if (!item.frequency) {
                            item.frequency = 0;
                        }
                        items.push('<tr>' +
                            '<td data-order="' + group.group + '"><div class="cell-overflow" tabindex="1" title="' + group.group + '">' + group.group + '</div></td>' +
                            '<td data-order="' + item.symbol + '"><strong>' + item.symbol + '</strong></td>' +
                            '<td data-order="' + item.description + '"><div class="cell-overflow" tabindex="1" title="' + item.description + '">' + item.description + '</div></td>' +
                            '<td data-order="' + item.weight + '"><input class="numeric mb-disabled ' + label_class +
                            '" data-role="numerictextbox" autocomplete="off" "type="number" class="input" min="' +
                            min + '" max="' +
                            max + '" step="' + decimalStep(item.weight) +
                            '" tabindex="1" value="' + Number(item.weight).toFixed(3) +
                            '" id="_sym_' + item.symbol + '"></span></td>' +
                            '<td data-order="' + item.frequency + '">' + item.frequency + '</td>' +
                            '<td data-order="' + item.time + '">' + Number(item.time).toFixed(2) + 'ms</td>' +
                            '<td><button type="button" class="btn btn-primary btn-sm mb-disabled">Save</button></td>' +
                            '<td><button type="button" class="btn btn-primary btn-sm mb-disabled">Save cluster</button></td></tr>');
                    });
                });
                $('<tbody/>', {
                    html: items.join('')
                }).insertAfter('#symbolsTable thead');
                tables.symbols = $('#symbolsTable').DataTable({
                    "paging": false,
                    "orderMulti": true,
                    "order": [
                        [0, "asc"],
                        [1, "asc"],
                        [3, "desc"]
                    ],
                    "info": false,
                    "columns": [
                        {"width": "7%", "searchable": true, "orderable": true},
                        {"width": "20%", "searchable": true, "orderable": true},
                        {"width": "30%", "searchable": false, "orderable": false},
                        {"width": "7%", "searchable": false, "orderable": true, "type": "num"},
                        {"searchable": false, "orderable": true, "type": "num"},
                        {"searchable": false, "orderable": true, "type": "num"},
                        {"width": "5%", "searchable": false, "orderable": false, "type": "html"},
                        {"width": "7%", "searchable": false, "orderable": false, "type": "html"}
                    ],
                });
                tables.symbols.columns.adjust().draw();
                $('#symbolsTable :button').on('click', function() {
                    var value = $(this).attr("value");
                    saveSymbols(rspamd, "./savesymbols", "symbolsTable",
                            value == 'Save cluster');
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