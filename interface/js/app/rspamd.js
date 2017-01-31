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
define(['jquery', 'd3pie', 'visibility', 'app/stats', 'app/graph', 'app/config',
    'app/symbols', 'app/history'],
    function ($, d3pie, visibility, tab_stat, tab_graph, tab_config,
        tab_symbols, tab_history) {
        // begin
        var graphs = {};
        var tables = {};
        var neighbours = []; //list of clusters
        var checked_server = "All SERVERS";
        var interface = {
            read_only: false,
        };

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
                    tab_stat.statWidgets(interface, graphs, checked_server);
                    timer_id.status = Visibility.every(10000, function () {
                        tab_stat.statWidgets(interface, graphs, checked_server);
                    });
                    break;
                case "#throughput_nav":
                    tab_graph.draw(interface, graphs, checked_server, selData);

                    var autoRefresh = {
                        hourly: 60000,
                        daily: 300000
                    };
                    timer_id.throughput = Visibility.every(autoRefresh[selData] || 3600000, function () {
                        tab_graph.draw(interface, graphs, checked_server, selData);
                    });
                    break;
                case "#configuration_nav":
                    tab_config.getActions(interface);
                    tab_config.getMaps(interface);
                    break;
                case "#symbols_nav":
                    tab_symbols.getSymbols(interface, tables, checked_server);
                    break;
                case "#history_nav":
                    tab_history.getHistory(interface, tables, checked_server);
                    tab_history.getErrors(interface, tables, checked_server);
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
            tab_config.setup(interface);
            tab_symbols.setup(interface, tables);
            tab_history.setup(interface, tables);
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
                    interface.read_only = true;
                    $('#learning_nav').hide();
                    $('#resetHistory').attr('disabled', true);
                    $('#errors-history').hide();
                }
                else {
                    interface.read_only = false;
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
                                interface.read_only = true;
                                $('#learning_nav').hide();
                                $('#resetHistory').attr('disabled', true);
                                $('#errors-history').hide();
                            }
                            else {
                                interface.read_only = false;
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

        // @watch textarea changes
        $('textarea').change(function () {
            if ($(this).val().length !== '') {
                $(this).closest('form').find('button').removeAttr('disabled').removeClass('disabled');
            } else {
                $(this).closest('form').find('button').attr('disabled').addClass('disabled');
            }
        });
});
