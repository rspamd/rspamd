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

define(['jquery'],
function($) {
    var interface = {}

    function save_map_success(rspamd) {
        rspamd.alertMessage('alert-modal alert-success', 'Map data successfully saved');
        $('#modalDialog').modal('hide');
    }
    function save_map_error(rspamd, serv, jqXHR, textStatus, errorThrown) {
        rspamd.alertMessage('alert-modal alert-error', 'Save map error on ' +
                serv.name + ': ' + errorThrown);
    }
     // @upload map from modal
    function saveMap(rspamd, action, id) {
        var data = $('#' + id).find('textarea').val();
        $.ajax({
            data: data,
            dataType: 'text',
            type: 'POST',
            jsonp: false,
            url: action,
            beforeSend: function (xhr) {
                xhr.setRequestHeader('Password', rspamd.getPassword());
                xhr.setRequestHeader('Map', id);
                xhr.setRequestHeader('Debug', true);
            },
            error: function (data) {
                save_map_error(rspamd, 'local', null, null, data.statusText);
            },
            success: function() {save_map_success(rspamd)},
        });
    }

    // @get maps id
    function getMaps(rspamd) {
        var items = [];
        $('#listMaps').closest('.widget-box').hide();
        $.ajax({
            dataType: 'json',
            url: 'maps',
            jsonp: false,
            beforeSend: function (xhr) {
                xhr.setRequestHeader('Password', rspamd.getPassword());
            },
            error: function (data) {
                rspamd.alertMessage('alert-modal alert-error', data.statusText);
            },
            success: function (data) {
                $('#listMaps').empty();
                $('#modalBody').empty();

                $.each(data, function (i, item) {
                    var caption;
                    var label;
                    getMapById(rspamd, item);
                    if ((item.editable === false || rspamd.read_only)) {
                        caption = 'View';
                        label = '<span class="label label-default">Read</span>';
                    } else {
                        caption = 'Edit';
                        label = '<span class="label label-default">Read</span>&nbsp;<span class="label label-success">Write</span>';
                    }
                    items.push('<tr>' +
                        '<td class="col-md-2 maps-cell">' + label + '</td>' +
                        '<td>' +
                        '<span class="map-link" ' +
                        'data-source="#' + item.map + '" ' +
                        'data-editable="' + item.editable + '" ' +
                        'data-target="#modalDialog" ' +
                        'data-title="' + item.uri +
                        '" data-toggle="modal">' + item.uri + '</span>' +
                        '</td>' +
                        '<td>' +
                        item.description +
                        '</td>' +
                        '</tr>');
                });
                $('<tbody/>', {
                    html: items.join('')
                }).appendTo('#listMaps');
                $('#listMaps').closest('.widget-box').show();
            }
        });
    }
    // @get map by id
    function getMapById(rspamd, item) {
        $.ajax({
            dataType: 'text',
            url: 'getmap',
            jsonp: false,
            beforeSend: function (xhr) {
                xhr.setRequestHeader('Password', rspamd.getPassword());
                xhr.setRequestHeader('Map', item.map);
            },
            error: function () {
                rspamd.alertMessage('alert-error', 'Cannot receive maps data');
            },
            success: function (text) {
                var disabled = '';
                if ((item.editable === false || rspamd.read_only)) {
                    disabled = 'disabled="disabled"';
                }

                $('<form class="form-horizontal form-map" method="post "action="/savemap" data-type="map" id="' +
                    item.map + '" style="display:none">' +
                    '<textarea class="list-textarea"' + disabled + '>' + text +
                    '</textarea>' +
                    '</form').appendTo('#modalBody');
            }
        });
    }

    function loadActionsFromForm() {
        var values = [];
        var inputs = $('#actionsForm :input[data-id="action"]');
        // Rspamd order: [spam,probable_spam,greylist]
        values[0] = parseFloat(inputs[2].value);
        values[1] = parseFloat(inputs[1].value);
        values[2] = parseFloat(inputs[0].value);

        return JSON.stringify(values);
    }

    function getActions(rspamd) {
        $.ajax({
            dataType: 'json',
            type: 'GET',
            url: 'actions',
            jsonp: false,
            beforeSend: function (xhr) {
                xhr.setRequestHeader('Password', rspamd.getPassword());
            },
            success: function (data) {
                // Order of sliders greylist -> probable spam -> spam
                $('#actionsBody').empty();
                $('#actionsForm').empty();
                var items = [];
                var min = 0;
                var max = Number.MIN_VALUE;
                $.each(data, function (i, item) {
                    var idx = -1;
                    var label;
                    if (item.action === 'add header') {
                        label = 'Probably Spam';
                        idx = 1;
                    } else if (item.action === 'greylist') {
                        label = 'Greylist';
                        idx = 0;
                    } else if (item.action === 'rewrite subject') {
                        label = 'Rewrite subject';
                        idx = 2;
                    } else if (item.action === 'reject') {
                        label = 'Spam';
                        idx = 3;
                    }
                    if (idx >= 0) {
                        items.push({
                            idx: idx,
                            html: '<div class="form-group">' +
                                '<label class="control-label col-sm-2">' + label + '</label>' +
                                '<div class="controls slider-controls col-sm-10">' +
                                '<input class="action-scores form-control" data-id="action" type="number" value="' + item.value + '">' +
                                '</div>' +
                                '</div>'
                        });
                    }
                    if (item.value > max) {
                        max = item.value * 2;
                    }
                    if (item.value < min) {
                        min = item.value;
                    }
                });

                items.sort(function (a, b) {
                    return a.idx - b.idx;
                });

                $('#actionsBody').html('<form id="actionsForm"><fieldset id="actionsFormField">' +
                    items.map(function (e) {
                        return e.html;
                    }).join('') +
                    '<br><div class="form-group">' +
                    '<div class="btn-group">' +
                    '<button class="btn btn-primary" type="button" id="saveActionsBtn">Save actions</button>' +
                    '<button class="btn btn-primary" type="button" id="saveActionsClusterBtn">Save cluster</button>' +
                    '</div></div></fieldset></form>');
                if (rspamd.read_only) {
                    $('#saveActionsClusterBtn').attr('disabled', true);
                    $('#saveActionsBtn').attr('disabled', true);
                    $('#actionsFormField').attr('disabled', true);
                }

                $('#saveActionsClusterBtn').on('click', function() {
                    var elts = loadActionsFromForm();
                    rspamd.queryNeighbours('saveactions', null, null, "POST", {}, {
                        data: elts,
                        dataType: "json",
                    });
                });
                $('#saveActionsBtn').on('click', function() {
                    var elts = loadActionsFromForm();
                    rspamd.queryLocal('saveactions', null, null, "POST", {}, {
                        data: elts,
                        dataType: "json",
                    });
                });
            },
        });
    }

    // @upload edited actions
    interface.setup = function(rspamd) {
        // Modal form for maps
        $(document).on('click', '[data-toggle="modal"]', function () {
            var source = $(this).data('source');
            var editable = $(this).data('editable');
            var title = $(this).data('title');
            $('#modalTitle').html(title);
            $('#modalBody ' + source).show();
            var target = $(this).data('target');
            $(target + ' .progress').hide();
            $(target).modal(show = true, backdrop = true, keyboard = show);
            if (editable === false) {
                $('#modalSave').hide();
                $('#modalSaveAll').hide();
            } else {
                $('#modalSave').show();
                $('#modalSaveAll').show();
            }
            return false;
        });
        // close modal without saving
        $('[data-dismiss="modal"]').on('click', function () {
            $('#modalBody form').hide();
        });
        // @save forms from modal
        $('#modalSave').on('click', function () {
            var form = $('#modalBody').children().filter(':visible');
            // var map = $(form).data('map');
            // var type = $(form).data('type');
            var action = $(form).attr('action');
            var id = $(form).attr('id');
            saveMap(rspamd, action, id);
        });
        $('#modalSaveAll').on('click', function () {
            var form = $('#modalBody').children().filter(':visible');
            // var map = $(form).data('map');
            // var type = $(form).data('type');
            var action = $(form).attr('action');
            var id = $(form).attr('id');
            var data = $('#' + id).find('textarea').val();
            rspamd.queryNeighbours(action, save_map_success, save_map_error, "POST", {
                "Map": id,
            }, {
                data: data,
                dataType: "text",
            });
        });
    }

    interface.getActions = getActions;
    interface.getMaps = getMaps;

    return interface;
});
