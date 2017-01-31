/*
 The MIT License (MIT)

 Copyright (C) 2012-2013 Anton Simonov <untone@gmail.com>
 Copyright (C) 2014-2017 Vsevolod Stakhov <vsevolod@highsecure.ru>

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
define(['jquery', 'd3pie', 'visibility', 'bootstrap'],
    function ($, d3pie, visibility, DataTable) {
        // begin
        var graphs = {};
        var tables = {};
        var read_only = false;
        var neighbours = []; //list of clusters
        var checked_server = "All SERVERS";
        var interface = {};

        var timer_id = [];
        var selData; // Graph's dataset selector state

        function stopTimers() {
            for (var key in timer_id) {
                Visibility.stop(timer_id[key]);
            }
        }

        function disconnect() {
            if (graphs.chart) {
                graphs.chart.destroy();
                graphs.chart = undefined;
            }
            if (graphs.rrd_pie) {
                graphs.rrd_pie.destroy();
                graphs.rrd_pie = undefined;
            }
            if (graphs.graph) {
                graphs.graph.destroy();
                graphs.graph = undefined;
            }
            if (tables.history) {
                tables.history.destroy();
                tables.history = undefined;
            }
            if (tables.errors) {
                tables.errors.destroy();
                tables.errors = undefined;
            }
            if (tables.symbols) {
                tables.symbols.destroy();
                tables.symbols = undefined;
            }

            stopTimers();
            cleanCredentials();
            interface.connect();
        }

        function tabClick(tab_id) {
            if ($(tab_id).attr('disabled')) return;
            $(tab_id).attr('disabled', true);

            stopTimers();

            if (tab_id === "#refresh") {
                tab_id = "#" + $('.navbar-nav .active > a' ).attr('id');
            }

            switch (tab_id) {
                case "#status_nav":
                    require(['app/stats'], function(stats) {
                        stats.statWidgets(interface, graphs, checked_server);
                    });
                    timer_id.status = Visibility.every(10000, function () {
                        require(['app/stats'], function(stats) {
                            stats.statWidgets(interface, graphs, checked_server);
                        });
                    });
                    break;
                case "#throughput_nav":
                    require(['app/graph'], function(graph) {
                        graph.draw(interface, graphs, checked_server, selData);
                    });

                    var autoRefresh = {
                        hourly: 60000,
                        daily: 300000
                    };
                    timer_id.throughput = Visibility.every(autoRefresh[selData] || 3600000, function () {
                        require(['app/graph'], function(graph) {
                            graph.draw(interface, graphs, checked_server, selData);
                        });
                    });
                    break;
                case "#configuration_nav":
                    getActions();
                    $('#modalBody').empty();
                    getMaps();
                    break;
                case "#symbols_nav":
                    getSymbols();
                    break;
                case "#history_nav":
                    getHistory();
                    getErrors();
                    break;
                case "#disconnect":
                    disconnect();
                    break;
            }

            setTimeout(function () {
                $(tab_id).removeAttr('disabled');
                $('#refresh').removeAttr('disabled');
            }, 1000);
        }

        // @return password
        function getPassword() {
          return sessionStorage.getItem('Password');
        }

        // @save credentials
        function saveCredentials(password) {
          sessionStorage.setItem('Password', password);
        }

        // @clean credentials
        function cleanCredentials() {
            sessionStorage.clear();
            $('#statWidgets').empty();
            $('#listMaps').empty();
            $('#modalBody').empty();
            $('#historyLog tbody').remove();
            $('#errorsLog tbody').remove();
            $('#symbolsTable tbody').remove();
            password = '';
        }

        function isLogged() {
            if (sessionStorage.getItem('Credentials') !== null) {
                return true;
            }
            return false;
        }

        function displayUI() {
            // @toggle auth and main
            var disconnect = $('#navBar .pull-right');
            $('#mainUI').show();
            $('#progress').show();
            $(disconnect).show();
            tabClick("#refresh");
            $('#progress').hide();
        }

        // Public functions
        interface.setup = function() {
            // Bind event handlers to selectors
            $("#selData").change(function () {
                selData = this.value;
                tabClick("#throughput_nav");
            });
            $.ajaxSetup({
                timeout: 2000,
                jsonp: false
            });

            $(document).ajaxStart(function () {
                $('#navBar').addClass('loading');
            });
            $(document).ajaxComplete(function () {
                setTimeout(function () {
                    $('#navBar').removeClass('loading');
                }, 1000);
            });

            $('a[data-toggle="tab"]').on('click', function (e) {
                var tab_id = "#" + $(e.target).attr("id");
                tabClick(tab_id);
            });

            // Radio buttons
            $(document).on('click', 'input:radio[name="clusterName"]', function () {
                if (!this.disabled) {
                    checked_server = this.value;
                    tabClick("#status_nav");
                }
            });
        };

        interface.alertMessage = function (alertState, alertText) {
            if ($('.alert').is(':visible')) {
                $(alert).hide().remove();
            }
            var alert = $('<div class="alert ' + alertState + '" style="display:none">' +
                    '<button type="button" class="close" data-dismiss="alert" tutle="Dismiss">&times;</button>' +
                    '<strong>' + alertText + '</strong>')
                .prependTo('body');
            $(alert).show();
            setTimeout(function () {
                $(alert).remove();
            }, 3600);
        }

        interface.connect = function() {
            if (isLogged()) {
                var data = JSON.parse(sessionStorage.getItem('Credentials'));

                if (data && data[checked_server].read_only) {
                    read_only = true;
                    $('#learning_nav').hide();
                    $('#resetHistory').attr('disabled', true);
                    $('#errors-history').hide();
                }
                else {
                    read_only = false;
                    $('#learning_nav').show();
                    $('#resetHistory').removeAttr('disabled', true);
                }
                displayUI();
                return;
            }

            var ui = $('#mainUI');
            var dialog = $('#connectDialog');
            var backdrop = $('#backDrop');
            $(ui).hide();
            $(dialog).show();
            $(backdrop).show();
            $('#connectPassword').focus();
            $('#connectForm').off('submit');

            $('#connectForm').on('submit', function (e) {
                e.preventDefault();
                var password = $('#connectPassword').val();
                if (!/^[\u0000-\u007f]*$/.test(password)) {
                    alertMessage('alert-modal alert-error', 'Invalid characters in the password');
                    $('#connectPassword').focus();
                    return;
                }

                $.ajax({
                    global: false,
                    jsonp: false,
                    dataType: 'json',
                    type: 'GET',
                    url: 'auth',
                    beforeSend: function (xhr) {
                        xhr.setRequestHeader('Password', password);
                    },
                    success: function (data) {
                        $('#connectPassword').val('');
                        if (data.auth === 'failed') {
                            // Is actually never returned by Rspamd
                        } else {
                            if (data.read_only) {
                                read_only = true;
                                $('#learning_nav').hide();
                                $('#resetHistory').attr('disabled', true);
                                $('#errors-history').hide();
                            }
                            else {
                                read_only = false;
                                $('#learning_nav').show();
                                $('#resetHistory').removeAttr('disabled', true);
                            }

                            saveCredentials(password);
                            $(dialog).hide();
                            $(backdrop).hide();
                            displayUI();
                        }
                    },
                    error: function (data) {
                        interface.alertMessage('alert-modal alert-error', data.statusText);
                        $('#connectPassword').val('');
                        $('#connectPassword').focus();
                    }
                });
            });
        };

        interface.queryNeighbours = function(req_url, on_success, on_error, method, headers, params) {
            $.ajax({
                dataType: "json",
                type: "GET",
                url: "neighbours",
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader("Password", getPassword());
                },
                success: function (data) {
                    if (jQuery.isEmptyObject(data)) {
                        neighbours = {
                                local:  {
                                    host: window.location.host,
                                    url: window.location.href
                                }
                        };
                    }   else {
                        neighbours = data;
                    }
                    var neighbours_status = [];
                    $.each(neighbours, function (ind) {
                        neighbours_status.push({
                            name: ind,
                            url: neighbours[ind].url,
                            host: neighbours[ind].host,
                            checked: false,
                            data: {},
                            status: false,
                        });
                    });
                    $.each(neighbours_status, function (ind) {
                        "use strict";
                        method = typeof method !== 'undefined' ? method : "GET";
                        var req_params = {
                            type: method,
                            jsonp: false,
                            beforeSend: function (xhr) {
                                xhr.setRequestHeader("Password", getPassword());

                                if (headers) {
                                    $.each(headers, function(hname, hvalue){
                                        xhr.setRequestHeader(hname, hvalue);
                                    });
                                }
                            },
                            url: neighbours_status[ind].url + req_url,
                            success: function (data) {
                                neighbours_status[ind].checked = true;

                                if (jQuery.isEmptyObject(data)) {
                                    neighbours_status[ind].status = false; //serv does not work
                                } else {
                                    neighbours_status[ind].status = true; //serv does not work
                                    neighbours_status[ind].data = data;
                                }
                                if (neighbours_status.every(function (elt) {return elt.checked;})) {
                                    on_success(neighbours_status);
                                }
                            },
                            error: function(jqXHR, textStatus, errorThrown) {
                                neighbours_status[ind].status = false;
                                neighbours_status[ind].checked = true;
                                if (on_error) {
                                    on_error(neighbours_status[ind],
                                            jqXHR, textStatus, errorThrown);
                                }
                                if (neighbours_status.every(
                                        function (elt) {return elt.checked;})) {
                                    on_success(neighbours_status);
                                }
                            }
                            //error display
                        };
                        if (params) {
                            $.each(params, function(k, v) {
                                req_params[k] = v;
                            });
                        }
                        $.ajax(req_params);
                    });
                },
                error: function () {
                    interface.alertMessage('alert-error', 'Cannot receive neighbours data');
                },
            });
        };

        interface.drawPie = function(obj, id, data, conf) {
            if (obj) {
                obj.updateProp("data.content",
                    data.filter(function (elt) {
                        return elt.value > 0;
                    })
                );
            } else {
                obj = new d3pie(id,
                    $.extend({}, {
                        "header": {
                            "title": {
                                "text": "Rspamd filter stats",
                                "fontSize": 24,
                                "font": "open sans"
                            },
                            "subtitle": {
                                "color": "#999999",
                                "fontSize": 12,
                                "font": "open sans"
                            },
                            "titleSubtitlePadding": 9
                        },
                        "footer": {
                            "color": "#999999",
                            "fontSize": 10,
                            "font": "open sans",
                            "location": "bottom-left"
                        },
                        "size": {
                            "canvasWidth": 600,
                            "canvasHeight": 400,
                            "pieInnerRadius": "20%",
                            "pieOuterRadius": "85%"
                        },
                        "data": {
                            //"sortOrder": "value-desc",
                            "content": data.filter(function (elt) {
                                return elt.value > 0;
                            })
                        },
                        "labels": {
                            "outer": {
                                "hideWhenLessThanPercentage": 1,
                                "pieDistance": 30
                            },
                            "inner": {
                                "hideWhenLessThanPercentage": 4
                            },
                            "mainLabel": {
                                "fontSize": 14
                            },
                            "percentage": {
                                "color": "#eeeeee",
                                "fontSize": 14,
                                "decimalPlaces": 0
                            },
                            "lines": {
                                "enabled": true
                            },
                            "truncation": {
                                "enabled": true
                            }
                        },
                        "tooltips": {
                            "enabled": true,
                            "type": "placeholder",
                            "string": "{label}: {value}, {percentage}%"
                        },
                        "effects": {
                            "pullOutSegmentOnClick": {
                                "effect": "back",
                                "speed": 400,
                                "size": 8
                            },
                            "load": {
                                "effect": "none"
                            }
                        },
                        "misc": {
                            "gradient": {
                                "enabled": true,
                                "percentage": 100
                            }
                        }
                    }, conf));
            }
            return obj;
        };

        interface.getPassword = getPassword;

        return interface;

        // @alert popover

        // @get maps id
        function getMaps() {
            var items = [];
            $('#listMaps').closest('.widget-box').hide();
            $.ajax({
                dataType: 'json',
                url: 'maps',
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                error: function (data) {
                    alertMessage('alert-modal alert-error', data.statusText);
                },
                success: function (data) {
                    $('#listMaps').empty();
                    saveMaps(data);
                    getMapById();
                    $.each(data, function (i, item) {
                        var caption;
                        var label;
                        if ((item.editable === false || read_only)) {
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
        function getMapById() {
            var data = JSON.parse(sessionStorage.getItem('Maps'));
            $('#modalBody').empty();

            $.each(data, function (i, item) {
                $.ajax({
                    dataType: 'text',
                    url: 'getmap',
                    jsonp: false,
                    beforeSend: function (xhr) {
                        xhr.setRequestHeader('Password', getPassword());
                        xhr.setRequestHeader('Map', item.map);
                    },
                    error: function () {
                        alertMessage('alert-error', 'Cannot receive maps data');
                    },
                    success: function (text) {
                        var disabled = '';
                        if ((item.editable === false || read_only)) {
                            disabled = 'disabled="disabled"';
                        }

                        $('<form class="form-horizontal form-map" method="post "action="/savemap" data-type="map" id="' +
                            item.map + '" style="display:none">' +
                            '<textarea class="list-textarea"' + disabled + '>' + text +
                            '</textarea>' +
                            '</form').appendTo('#modalBody');
                    }
                });
            });
        }

        // @opem modal with target form enabled
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



        // @get history log
        // function getChart() {
        // //console.log(data)
        // $.ajax({
        // dataType: 'json',
        // url: './pie',
        // beforeSend: function(xhr) {
        // xhr.setRequestHeader('Password', getPassword())
        // },
        // error: function() {
        // alertMessage('alert-error', 'Cannot receive history');
        // },
        // success: function(data) {
        // console.log(data);
        // }
        // });
        // }
        // @get history log
        function getHistory() {

            if (history) {
                var history_length = document.getElementsByName('historyLog_length')[0];
                if (history_length !== undefined) {
                    history_length = parseInt(history_length.value);
                } else {
                    history_length = 10;
                }
                history.destroy();
                $('#historyLog').children('tbody').remove();
            }

            var items = [];
            $.ajax({
                dataType: 'json',
                url: 'history',
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                error: function () {
                    alertMessage('alert-error', 'Cannot receive history');
                },
                success: function (data) {
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
                    $('<tbody/>', {
                        html: items.join('')
                    }).insertAfter('#historyLog thead');
                    history = $('#historyLog').DataTable({
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
        }

        function getErrors() {
            if (read_only) return;

            if (errors) {
                errors.destroy();
                $('#errorsLog').children('tbody').remove();
            }

            var items = [];
            $.ajax({
                dataType: 'json',
                url: 'errors',
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                error: function () {
                    alertMessage('alert-error', 'Cannot receive errors');
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
                    errors = $('#errorsLog').DataTable({
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
                    errors.columns.adjust().draw();
                }
            });
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
        function getSymbols() {
            if (symbols) {
                symbols.destroy();
                symbols = null;
                $('#symbolsTable').children('tbody').remove();
            }
            var items = [];
            $.ajax({
                dataType: 'json',
                type: 'GET',
                url: 'symbols',
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
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
                    symbols = $('#symbolsTable').DataTable({
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
                    symbols.columns.adjust().draw();
                    $('#symbolsTable :button').on('click', function() {
                        var value = $(this).attr("value");
                        saveSymbols("./savesymbols", "symbolsTable",
                                value == 'Save cluster');
                    });
                  if (read_only) {
                    $( ".mb-disabled" ).attr('disabled', true);
                  }
                },
                error: function (data) {
                    alertMessage('alert-modal alert-error', data.statusText);
                }
            });
        }
        // @reset history log
        $('#resetHistory').on('click', function () {
            if (!confirm("Are you sure you want to reset history log?")) {
                return;
            }
            if (history) {
                history.destroy();
                $('#historyLog').children('tbody').remove();
            }
            $.ajax({
                dataType: 'json',
                type: 'GET',
                jsonp: false,
                url: 'historyreset',
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function () {
                    getHistory();
                    getErrors();
                },
                error: function (data) {
                    alertMessage('alert-modal alert-error', data.statusText);
                }
            });
        });

        // @update history log
        $('#updateHistory').on('click', function () {
            getHistory();
        });
        $('#updateErrors').on('click', function () {
            getErrors();
        });

        $('#updateSymbols').on('click', function () {
            getSymbols();
        });

        // @upload text
        function uploadText(data, source, headers) {
            var url;
            if (source === 'spam') {
                url = 'learnspam';
            } else if (source === 'ham') {
                url = 'learnham';
            } else if (source == 'fuzzy') {
                url = 'fuzzyadd';
            } else if (source === 'scan') {
                url = 'scan';
            }
            $.ajax({
                data: data,
                dataType: 'json',
                type: 'POST',
                url: url,
                processData: false,
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                    $.each(headers, function (name, value) {
                        xhr.setRequestHeader(name, value);
                    });
                },
                success: function (data) {
                    cleanTextUpload(source);
                    if (data.success) {
                        alertMessage('alert-success', 'Data successfully uploaded');
                    }
                },
                error: function (xhr, textStatus, errorThrown) {
                    var errorMsg;

                    try {
                        var json = $.parseJSON(xhr.responseText);
                        errorMsg = $('<a>').text(json.error).html();
                    } catch (err) {
                        errorMsg = $('<a>').text("Error: [" + textStatus + "] " + errorThrown).html();
                    }
                    alertMessage('alert-error', errorMsg);
                }
            });
        }
        // @upload text
        function scanText(data) {
            var url = 'scan';
            var items = [];
            $.ajax({
                data: data,
                dataType: 'json',
                type: 'POST',
                url: url,
                processData: false,
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (input) {
                    var data = input['default'];
                    if (data.action) {
                        alertMessage('alert-success', 'Data successfully scanned');
                        var action = '';

                        if (data.action === 'clean' || 'no action') {
                            action = 'label-success';
                        }
                        else if (data.action === 'rewrite subject' || 'add header' || 'probable spam') {
                            action = 'label-warning';
                        }
                        else if (data.action === 'spam') {
                            action = 'label-danger';
                        }

                        var score = '';
                        if (data.score <= data.required_score) {
                            score = 'label-success';
                        }
                        else if (data.score >= data.required_score) {
                            score = 'label-danger';
                        }
                        $('<tbody id="tmpBody"><tr>' +
                                '<td><span class="label ' + action + '">' + data.action + '</span></td>' +
                                '<td><span class="label ' + score + '">' + data.score.toFixed(2) + '/' + data.required_score.toFixed(2) + '</span></td>' +
                                '</tr></tbody>')
                            .insertAfter('#scanOutput thead');
                        var sym_desc = {};
                        var nsym = 0;

                        $.each(data, function (i, item) {
                            if (typeof item == 'object') {
                                var sym_id = "sym_" + nsym;
                                if (item.description) {
                                    sym_desc[sym_id] = item.description;
                                }
                                items.push('<div class="cell-overflow" tabindex="1"><abbr id="' + sym_id +
                                    '">' + item.name + '</abbr>: ' + item.score.toFixed(2) + '</div>');
                                nsym++;
                            }
                        });
                        $('<td/>', {
                            id: 'tmpSymbols',
                            html: items.join('')
                        }).appendTo('#scanResult');
                        $('#tmpSymbols').insertAfter('#tmpBody td:last').removeAttr('id');
                        $('#tmpBody').removeAttr('id');
                        $('#scanResult').show();
                        // Show tooltips
                        $.each(sym_desc, function (k, v) {
                            $('#' + k).tooltip({
                                "placement": "bottom",
                                "title": v
                            });
                        });
                        $('html, body').animate({
                            scrollTop: $('#scanResult').offset().top
                        }, 1000);
                    } else {
                        alertMessage('alert-error', 'Cannot scan data');
                    }
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    alertMessage('alert-error', 'Cannot upload data: ' +
                        textStatus + ", " + errorThrown);
                },
                statusCode: {
                    404: function () {
                        alertMessage('alert-error', 'Cannot upload data, no server found');
                    },
                    500: function () {
                        alertMessage('alert-error', 'Cannot tokenize message: no text data');
                    },
                    503: function () {
                        alertMessage('alert-error', 'Cannot tokenize message: no text data');
                    }
                }
            });
        }
        // @close scan output
        $('#scanClean').on('click', function () {
            $('#scanTextSource').val("");
            $('#scanResult').hide();
            $('#scanOutput tbody').remove();
            $('html, body').animate({scrollTop: 0}, 1000);
            return false;
        });
        // @init upload
        $('[data-upload]').on('click', function () {
            var source = $(this).data('upload');
            var data;
            var headers = {};
            data = $('#' + source + 'TextSource').val();
            if (source == 'fuzzy') {
                //To access the proper
                headers.flag = $('#fuzzyFlagText').val();
                headers.weigth = $('#fuzzyWeightText').val();
            } else {
                data = $('#' + source + 'TextSource').val();
            }
            if (data.length > 0) {
                if (source == 'scan') {
                    scanText(data);
                } else {
                    uploadText(data, source, headers);
                }
            }
            return false;
        });
        // @empty textarea on upload complete
        function cleanTextUpload(source) {
            $('#' + source + 'TextSource').val('');
        }
        // @get acions
        function getActions() {
            $.ajax({
                dataType: 'json',
                type: 'GET',
                url: 'actions',
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
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
                                    '<input class="slider" type="slider" value="' + item.value + '">' +
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
                        '<button class="btn btn-primary" type="submit">Save actions</button></div></fieldset></form>');
                    if (read_only) {
                      $('#actionsFormField').attr('disabled', true);
                    }
                }
            });
        }
        // @upload edited actions
        $('#actionsForm').on('submit', function () {
            var inputs = $('#actionsForm :input[type="slider"]');
            var url = 'saveactions';
            var values = [];
            // Rspamd order: [spam,probable_spam,greylist]
            values[0] = parseFloat(inputs[2].value);
            values[1] = parseFloat(inputs[1].value);
            values[2] = parseFloat(inputs[0].value);
            $.ajax({
                data: JSON.stringify(values),
                dataType: 'json',
                type: 'POST',
                url: url,
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function () {
                    alertMessage('alert-success', 'Actions successfully saved');
                },
                error: function (data) {
                    alertMessage('alert-modal alert-error', data.statusText);
                }
            });
            return false;
        });
        // @watch textarea changes
        $('textarea').change(function () {
            if ($(this).val().length !== '') {
                $(this).closest('form').find('button').removeAttr('disabled').removeClass('disabled');
            } else {
                $(this).closest('form').find('button').attr('disabled').addClass('disabled');
            }
        });
        function save_map_success() {
            alertMessage('alert-modal alert-success', 'Map data successfully saved');
            $('#modalDialog').modal('hide');
        }
        function save_map_error(serv, jqXHR, textStatus, errorThrown) {
            alertMessage('alert-modal alert-error', 'Save map error on ' +
                    serv.name + ': ' + errorThrown);
        }
        // @save forms from modal
        $('#modalSave').on('click', function () {
            var form = $('#modalBody').children().filter(':visible');
            // var map = $(form).data('map');
            // var type = $(form).data('type');
            var action = $(form).attr('action');
            var id = $(form).attr('id');
            saveMap(action, id);
        });
        $('#modalSaveAll').on('click', function () {
            var form = $('#modalBody').children().filter(':visible');
            // var map = $(form).data('map');
            // var type = $(form).data('type');
            var action = $(form).attr('action');
            var id = $(form).attr('id');
            var data = $('#' + id).find('textarea').val();
            interface.queryNeighbours(action, save_map_success, save_map_error, "POST", {
                "Map": id,
            }, {
                data: data,
                dataType: "text",
            });
        });
        // @upload map from modal
        function saveMap(action, id) {
            var data = $('#' + id).find('textarea').val();
            $.ajax({
                data: data,
                dataType: 'text',
                type: 'POST',
                jsonp: false,
                url: action,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                    xhr.setRequestHeader('Map', id);
                    xhr.setRequestHeader('Debug', true);
                },
                error: function (data) {
                    save_map_error('local', null, null, data.statusText);
                },
                success: save_map_success,
            });
        }

        // @upload symbols from modal
        function saveSymbols(action, id, is_cluster) {
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
                interface.queryNeighbours(url, function () {
                    alertMessage('alert-modal alert-success', 'Symbols successfully saved');
                }, function (serv, qXHR, textStatus, errorThrown) {
                    alertMessage('alert-modal alert-error',
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
                        xhr.setRequestHeader('Password', getPassword());
                    },
                    success: function () {
                        alertMessage('alert-modal alert-success', 'Symbols successfully saved');
                    },
                    error: function (data) {
                        alertMessage('alert-modal alert-error', data.statusText);
                    }
                });
            }
        }
        // @connect to server
});
