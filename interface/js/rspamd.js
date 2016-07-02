/*
 The MIT License (MIT)

 Copyright (C) 2012-2013 Anton Simonov <untone@gmail.com>
 Copyright (C) 2014-2015 Vsevolod Stakhov <vsevolod@highsecure.ru>

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
(function () {
    $(document).ready(function () {
        // begin
        //$.cookie.json = true;
        var pie;
        var history;
        var graph;

        var selected = []; // Keep graph selectors state

        // Bind event handlers to selectors
        $("#selData").change(function () {
            selected.selData = this.value;
            getGraphData(this.value);
        });
        $("#selType").change(function () {
            graph.type(this.value);
        });
        $("#selInterpolate").change(function () {
            graph.interpolate(this.value);
        });

        $('#disconnect').on('click', function (event) {
            if (pie) {
                pie.destroy();
            }
            if (graph) {
                graph.destroy();
                graph = undefined;
            }
            if (history) {
                history.destroy();
            }
            cleanCredentials();
            connectRSPAMD();
            // window.location.reload();
            return false;
        });
        $('#refresh').on('click', function (event) {
            statWidgets();
            getChart();
            getGraphData(selected.selData);
        });
        // @supports session storage
        function supportsSessionStorage() {
            return typeof(Storage) !== "undefined";
        }
        // @return password
        function getPassword() {
            if (sessionState()) {
                if (!supportsSessionStorage()) {
                    return password = $.cookie('rspamdpasswd');
                }
                else {
                    return password = sessionStorage.getItem('Password');
                }
            }
        }
        // @return session state
        function sessionState() {
            if ((supportsSessionStorage() && (sessionStorage.getItem('Password') !== null))
                || (!supportsSessionStorage() && ($.cookie('rspamdsession')) !== null)) {
                return true;
            }
            else {
                return false;
            }
        }

        // @detect session storate
        supportsSessionStorage();
        // @request credentials
        function requestCredentials() {
            $.ajax({
                dataType: 'json',
                type: 'GET',
                url: 'auth',
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (data) {
                    if (data.auth === 'failed') {
                        connectRSPAMD();
                    }
                }
            });
        }
        // @request credentials
        function updateCredentials() {
            $.ajax({
                dataType: 'json',
                type: 'GET',
                url: 'auth',
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (data) {
                    saveCredentials(data, password);
                }
            });
        }
        // @save credentials
        function saveCredentials(data, password) {
            if (!supportsSessionStorage()) {
                $.cookie('rspamdsession', data, { expires: 1 }, { path: '/' });
                $.cookie('rspamdpasswd', password, { expires: 1 }, { path: '/' });
            }
            else {
                sessionStorage.setItem('Password', password);
                sessionStorage.setItem('Credentials', JSON.stringify(data));
            }
        }
        // @update credentials
        function saveActions(data) {
            if (!supportsSessionStorage()) {
                $.cookie('rspamdactions', data);
            }
            else {
                sessionStorage.setItem('Actions', JSON.stringify(data));
            }
        }
        // @update credentials
        function saveMaps(data) {
            if (!supportsSessionStorage()) {
                $.cookie('rspamdmaps', data, { expires: 1 }, { path: '/' });
            }
            else {
                sessionStorage.setItem('Maps', JSON.stringify(data));
            }
        }
        // @clean credentials
        function cleanCredentials() {
            if (!supportsSessionStorage()) {
                $.removeCookie('rspamdlogged');
                $.removeCookie('rspamdsession');
                $.removeCookie('rspamdpasswd');
            }
            else {
                sessionStorage.clear();
            }
            $('#statWidgets').empty();
            $('#listMaps').empty();
            $('#historyLog tbody').remove();
            $('#modalBody').empty();
        }
        function isLogged() {
            if (!supportsSessionStorage()) {
                if ($.cookie('rspamdpasswd') != null) {
                    return true;
                }
            }
            else {
                if (sessionStorage.getItem('Password') != null) {
                    return true;
                }
            }
            return false;
        }
        // @alert popover
        function alertMessage(alertState, alertText) {
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
        // @get maps id
        function getMaps() {
            var items = [];
            $('#listMaps').closest('.widget-box').hide();
            $.ajax({
                dataType: 'json',
                url: 'maps',
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                error: function () {
                    alertMessage('alert-modal alert-error', data.statusText);
                },
                success: function (data) {
                    $('#listMaps').empty();
                    saveMaps(data);
                    getMapById();
                    $.each(data, function (i, item) {
                        var caption;
                        var label;
                        if ((item.editable == false)) {
                            caption = 'View';
                            label = '<span class="label label-default">Read</span>';
                        }
                        else {
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
        function getMapById(mode) {
            var data;
            if (!supportsSessionStorage()) {
                data = $.cookie('rspamdmaps', data, { expires: 1 }, { path: '/' });
            }
            else {
                data = JSON.parse(sessionStorage.getItem('Maps'));
            }
            if (mode === 'update') {
                $('#modalBody').empty();
                getSymbols();
            }
            $.each(data, function (i, item) {
                $.ajax({
                    dataType: 'text',
                    url: 'getmap',
                    beforeSend: function (xhr) {
                        xhr.setRequestHeader('Password', getPassword());
                        xhr.setRequestHeader('Map', item.map);
                    },
                    error: function () {
                        alertMessage('alert-error', 'Cannot receive maps data');
                    },
                    success: function (text) {
                        var disabled = '';
                        if ((item.editable == false)) {
                            disabled = 'disabled="disabled"';
                        }

                        $('<form class="form-horizontal form-map" method="post "action="/savemap" data-type="map" id="'
                            + item.map + '" style="display:none">' +
                            '<textarea class="list-textarea"' + disabled + '>' + text
                            + '</textarea>' +
                            '</form').appendTo('#modalBody');
                    }
                });
            });
        }
        // @ ms to date
        function msToTime(seconds) {
            minutes = parseInt(seconds / 60);
            hours = parseInt(seconds / 3600);
            days = parseInt(seconds / 3600 / 24);
            weeks = parseInt(seconds / 3600 / 24 / 7);
            years = parseInt(seconds / 3600 / 168 / 365);
            if (weeks > 0) {
                years = years >= 10 ? years : '0' + years;
                weeks -= years * 168;
                weeks = weeks >= 10 ? weeks : '0' + weeks;
                // Return in format X years and Y weeks
                return years + ' years ' + weeks + ' weeks';
            }
            seconds -= minutes * 60;
            minutes -= hours * 60;
            hours -= days * 24;
            days = days >= 10 ? days : '0' + days;
            hours = hours >= 10 ? hours : '0' + hours;
            minutes = minutes >= 10 ? minutes : '0' + minutes;
            seconds = seconds >= 10 ? seconds : '0' + seconds;
            if (days > 0) {
                return days + ' days, ' + hours + ':' + minutes + ':' + seconds;
            }
            else {
                return hours + ':' + minutes + ':' + seconds;
            }
        }
        // @show widgets
        function statWidgets() {
            var widgets = $('#statWidgets');
            updateCredentials();
            $(widgets).empty().hide();
            var data;
            if (!supportsSessionStorage()) {
                data = $.cookie('rspamdsession');
            }
            else {
                data = JSON.parse(sessionStorage.getItem('Credentials'));
            }
            var stat_w = [];
            $.each(data, function (i, item) {
                var widget = '';
                if (i == 'auth') {
                }
                else if (i == 'error') {
                }
                else if (i == 'version') {
                    widget = '<div class="left"><strong>' + item + '</strong>' +
                        i + '</div>';
                    $(widget).appendTo(widgets);
                }
                else if (i == 'uptime') {
                    widget = '<div class="right"><strong>' + msToTime(item) +
                        '</strong>' + i + '</div>';
                    $(widget).appendTo(widgets);
                }
                else {
                    widget = '<li class="stat-box"><div class="widget"><strong>' +
                        Humanize.compactInteger(item) + '</strong>' + i + '</div></li>';
                    if (i == 'scanned') {
                        stat_w[0] = widget;
                    }
                    else if (i == 'clean') {
                        stat_w[1] = widget;
                    }
                    else if (i == 'greylist') {
                        stat_w[2] = widget;
                    }
                    else if (i == 'probable') {
                        stat_w[3] = widget;
                    }
                    else if (i == 'reject') {
                        stat_w[4] = widget;
                    }
                    else if (i == 'learned') {
                        stat_w[5] = widget;
                    }
                }
            });
            $.each(stat_w, function (i, item) { $(item).appendTo(widgets); });
            $('#statWidgets .left,#statWidgets .right').wrapAll('<li class="stat-box pull-right"><div class="widget"></div></li>');
            $(widgets).show();
            window.setTimeout(statWidgets, 10000);
        }
        // @opem modal with target form enabled
        $(document).on('click', '[data-toggle="modal"]', function (e) {
            var source = $(this).data('source');
            var editable = $(this).data('editable');
            var title = $(this).data('title');
            var caption = $('#modalTitle').html(title);
            var body = $('#modalBody ' + source).show();
            var target = $(this).data('target');
            var progress = $(target + ' .progress').hide();
            $(target).modal(show = true, backdrop = true, keyboard = show);
            if (editable === false) {
                $('#modalSave').hide();
            }
            else {
                $('#modalSave').show();
            }
            return false;
        });
        // close modal without saving
        $(document).on('click', '[data-dismiss="modal"]', function (e) {
            $('#modalBody form').hide();
        });
        function getChart() {
            $.ajax({
                dataType: 'json',
                type: 'GET',
                url: 'pie',
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (data) {
                    if (pie) {
                        pie.destroy();
                    }
                    pie = new d3pie("chart", {
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
                            "content": data.filter(function(elt) {
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
                                "speed": 500
                            }
                        },
                        "misc": {
                            "gradient": {
                                "enabled": true,
                                "percentage": 100
                            }
                        }
                    });
                }
            });
        }

        function initGraph() {
            // Get selectors' current state
            var selIds = ["selData", "selType", "selInterpolate"];
            selIds.forEach(function (id) {
                var e = document.getElementById(id);
                selected[id] = e.options[e.selectedIndex].value;
            });

            var options = {
                title: "Rspamd throughput",
                width: 1060,
                height: 370,

                type: selected.selType,
                interpolate: selected.selInterpolate,

                legend: {
                    entries: [
                        {label: "Rejected",      color: "#FF0000"},
                        {label: "Probable spam", color: "#FFD700"},
                        {label: "Greylisted",    color: "#436EEE"},
                        {label: "Clean",         color: "#66cc00"}
                    ]
                }
            };
            graph = new D3Evolution("graph", options);
        }

        function getGraphData(type) {
            $.ajax({
                dataType: 'json',
                type: 'GET',
                url: 'graph',
                data: {"type": type},
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (data) {
                    graph.data(data);
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    alertMessage('alert-error', 'Cannot receive throughput data: ' +
                        textStatus + ' ' + jqXHR.status + ' ' + errorThrown);
                }
            });
        }

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
                history.destroy();
                $('#historyLog').children('tbody').remove();
            }

            var items = [];
            $.ajax({
                dataType: 'json',
                url: 'history',
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
                        }
                        else if (item.action === 'rewrite subject' || item.action === 'add header' || item.action === 'probable spam') {
                            action = 'label-warning';
                        }
                        else if (item.action === 'spam' || item.action === 'reject') {
                            action = 'label-danger';
                        }
                        else {
                            action = 'label-info';
                        }

                        var score;
                        if (item.score < item.required_score) {
                            score = 'label-success';
                        }
                        else {
                            score = 'label-danger';
                        }

                        items.push(
                            '<tr><td data-order="' + item.unix_time + '">' + item.time + '</td>' +
                            '<td data-order="' + item.id + '"><div class="cell-overflow" tabindex="1" title="' + item.id + '">' + item.id + '</td>' +
                            '<td data-order="' + item.ip + '"><div class="cell-overflow" tabindex="1" title="' + item.ip + '">' + item.ip + '</div></td>' +
                            '<td data-order="' + item.action + '"><span class="label ' + action + '">' + item.action + '</span></td>' +
                            '<td data-order="' + item.score + '"><span class="label ' + score + '">' + item.score.toFixed(2) + ' / ' + item.required_score.toFixed(2) + '</span></td>' +
                            '<td data-order="' + item.symbols + '"><div class="cell-overflow" tabindex="1" title="' + item.symbols + '">' + item.symbols + '</div></td>' +
                            '<td data-order="' + item.size + '">' + item.size + '</td>' +
                            '<td data-order="' + item.scan_time + '">' + item.scan_time.toFixed(3) + '</td>' +
                            '<td data-order="' + item.user + '"><div class="cell-overflow" tabindex="1" "title="' + item.user + '">' + item.user + '</div></td></tr>');
                    });
                    $('<tbody/>', { html: items.join('') }).insertAfter('#historyLog thead');
                    history = $('#historyLog').DataTable({
                        "order": [[ 0, "desc" ]]
                    });
                }
            });
        }
        function decimalStep(number) {
            var digits = ((+number).toFixed(20)).replace(/^-?\d*\.?|0+$/g, '').length;
            if (digits == 0 || digits > 4) {
                return 0.1;
            }
            else {
                return 1.0 / (Math.pow(10, digits));
            }
        }
        // @get symbols into modal form
        function getSymbols() {
            var items = [];
            $.ajax({
                dataType: 'json',
                type: 'GET',
                url: 'symbols',
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (data) {
                    $('#modalBody').empty();
                    data.sort(function(a, b) {
                        return a.group.localeCompare(b.group);
                    });
                    $.each(data, function (i, group) {
                        items.push('	<div class="row row-bordered" data-slider="hover">' +
                            '<h4>' + group.group + '</h4>' +
                            '</div>');
                        group.rules.sort(function(a, b) {
                            return a.symbol.localeCompare(b.symbol);
                        });
                        $.each(group.rules, function (i, item) {
                            var max = 20;
                            var min = -20;
                            if (item.weight > max) {
                                max = item.weight * 2;
                            }
                            if (item.weight < min) {
                                min = item.weight * 2;
                            }
                            items.push('	<div class="row row-bordered" data-slider="hover">' +
                                '<label class="col-md-7" for="' + item.symbol + '" title="' + item.description + '">' +
                                '<code>' + item.symbol + '</code><p class="symbol-description">' + item.description + '</p>' +
                                '</label>' +
                                '<div class="col-md-3 spin-cell">' +
                                '<input class="numeric" data-role="numerictextbox" autocomplete="off" "type="number" class="input-mini" min="' +
                                min + '" max="' +
                                max + '" step="' + decimalStep(item.weight) +
                                '" tabindex="1" value="' + Number(item.weight).toFixed(2) +
                                '" id="' + item.symbol + '">' +
                                '</div>' +
                                '</div>');
                        });
                    });
                    $('<form/>', {
                        id: 'symbolsForm',
                        method: 'post',
                        action: '/savesymbols',
                        'data-type': 'symbols',
                        style: 'display:none',
                        html: items.join('') }).appendTo('#modalBody');
                },
                error: function (data) {
                    alertMessage('alert-modal alert-error', data.statusText);
                }
            });
        }
        // @update history log
        $('#resetHistory').on('click', function () {
            if (history) {
                history.destroy();
                $('#historyLog').children('tbody').remove();
            }
            $.ajax({
                dataType: 'json',
                type: 'GET',
                url: 'historyreset',
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (data) {
                    getHistory();
                },
                error: function (data) {
                    alertMessage('alert-modal alert-error', data.statusText);
                }
            });
        });

        // @reset history log
        $('#updateHistory').on('click', function () {
            getHistory();
        });

        // @upload text
        function uploadText(data, source) {
            if (source === 'spam') {
                var url = 'learnspam';
            }
            else if (source === 'ham') {
                var url = 'learnham';
            }
            else if (source == 'fuzzy') {
                var url = 'learnfuzzy';
            }
            else if (source === 'scan') {
                var url = 'scan';
            }
            $.ajax({
                data: data,
                dataType: 'json',
                type: 'POST',
                url: url,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (data) {
                    cleanTextUpload(source);
                    if (data.success) {
                        alertMessage('alert-success', 'Data successfully uploaded');
                    }
                },
                // error: function() {
                // alertMessage('alert-error', 'Cannot upload data');
                // },
                statusCode: {
                    404: function () {
                        alertMessage('alert-error', 'Cannot upload data, no server found');
                    },
                    503: function () {
                        alertMessage('alert-error', 'Cannot tokenize message, no text data');
                    }
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
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (input) {
                    var data = input['default'];
                    if (data.action) {
                        alertMessage('alert-success', 'Data successfully scanned');
                        if (data.action === 'clean' || 'no action') {
                            var action = 'label-success';
                        }
                        if (data.action === 'rewrite subject' || 'add header' || 'probable spam') {
                            var action = 'label-warning';
                        }
                        if (data.action === 'spam') {
                            var action = 'label-danger';
                        }
                        if (data.score <= data.required_score) {
                            var score = 'label-success';
                        }
                        if (data.score >= data.required_score) {
                            var score = 'label-danger';
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
                                    nsym ++;
                            }
                        });
                        $('<td/>', { id: 'tmpSymbols', html: items.join('') }).appendTo('#scanResult');
                        $('#tmpSymbols').insertAfter('#tmpBody td:last').removeAttr('id');
                        $('#tmpBody').removeAttr('id');
                        $('#scanResult').show();
                        // Show tooltips
                        $.each(sym_desc, function(k, v) {
                            $('#' + k).tooltip({
                                "placement": "bottom",
                                "title": v
                            });
                        });
                        $('html, body').animate({
                            scrollTop: $('#scanResult').offset().top
                        }, 1000);
                    }
                    else {
                        alertMessage('alert-error', 'Cannot scan data');
                    }
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
            $('#scanTextSource').val('');
            $('#scanResult').hide();
            $('#scanOutput tbody').remove();
            $('html, body').animate({
                scrollTop: 0
            }, 1000);
        });
        // @init upload
        $('[data-upload]').on('click', function () {
            var source = $(this).data('upload');
            var data;
            if (source == 'fuzzy') {
                //To access the proper
                data = new String($('#' + source + 'TextSource').val());
                data.flag = $('#fuzzyFlagText').val();
                data.weigth = $('#fuzzyWeightText').val();
                data.string = data.toString();
            }
            else {
                data = $('#' + source + 'TextSource').val();
            }
            if (data.length > 0) {
                if (source == 'scan') {
                    scanText(data);
                }
                else {
                    uploadText(data, source);
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
            var items = [];
            $.ajax({
                dataType: 'json',
                type: 'GET',
                url: 'actions',
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (data) {
                    // Order of sliders greylist -> probable spam -> spam
                    $('#actionsBody').empty();
                    $('#actionsForm').empty();
                    items = [];
                    var min = 0;
                    var max = Number.MIN_VALUE;
                    $.each(data, function (i, item) {
                        var idx = -1;
                        var label;
                        if (item.action === 'add header') {
                            label = 'Probably Spam';
                            idx = 1;
                        }
                        else if (item.action === 'greylist') {
                            label = 'Greylist';
                            idx = 0;
                        }
                        else if (item.action === 'reject') {
                            label = 'Spam';
                            idx = 2;
                        }
                        if (idx >= 0) {
                            items[idx] =
                                '<div class="form-group">' +
                                    '<label class="control-label col-sm-2">' + label + '</label>' +
                                    '<div class="controls slider-controls col-sm-10">' +
                                    '<input class="slider" type="slider" value="' + item.value + '">' +
                                    '</div>' +
                                    '</div>';
                        }
                        if (item.value > max) {
                            max = item.value * 2;
                        }
                        if (item.value < min) {
                            min = item.value;
                        }
                    });

                    $('#actionsBody').html('<form id="actionsForm">' + items.join('') +
                        '<br><div class="form-group">' +
                        '<button class="btn btn-primary" ' +
                        'type="submit">Save actions</button></div></form>');
                }
            });
        }
        // @upload edited actions
        $(document).on('submit', '#actionsForm', function () {
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
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function () {
                    alertMessage('alert-success', 'Actions successfully saved');
                },
                error: function () {
                    alertMessage('alert-modal alert-error', data.statusText);
                }
            });
            getMapById('update');
            return false;
        });
        // @catch changes of file upload form
        $(window).resize(function (e) {
            var form = $(this).attr('id');
            var height = $(form).height();
        });
        // @watch textarea changes
        $('textarea').change(function () {
            if ($(this).val().length != '') {
                $(this).closest('form').find('button').removeAttr('disabled').removeClass('disabled');
            }
            else {
                $(this).closest('form').find('button').attr('disabled').addClass('disabled');
            }
        });
        // @save forms from modal
        $(document).on('click', '#modalSave', function () {
            var form = $('#modalBody').children().filter(':visible');
            // var map = $(form).data('map');
            // var type = $(form).data('type');
            var action = $(form).attr('action');
            var id = $(form).attr('id');
            var type = $(form).data('type');
            if (type === 'symbols') {
                saveSymbols(action, id);
            }
            else if (type === 'map') {
                saveMap(action, id);
            }
        });
        // @upload map from modal
        function saveMap(action, id) {
            var data = $('#' + id).find('textarea').val();
            $.ajax({
                data: data,
                dataType: 'text',
                type: 'POST',
                url: action,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                    xhr.setRequestHeader('Map', id);
                    xhr.setRequestHeader('Debug', true);
                },
                error: function (data) {
                    alertMessage('alert-modal alert-error', data.statusText);
                },
                success: function (data) {
                    alertMessage('alert-modal alert-success', 'Map data successfully saved');
                    $('#modalDialog').modal('hide');
                }
            });
        }
        // @upload symbols from modal
        function saveSymbols(action, id) {
            var inputs = $('#' + id + ' :input[data-role="numerictextbox"]');
            var url = action;
            var values = [];
            $(inputs).each(function () {
                values.push({ name: $(this).attr('id'), value: parseFloat($(this).val()) });
            });
            $.ajax({
                data: JSON.stringify(values),
                dataType: 'json',
                type: 'POST',
                url: url,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function () {
                    alertMessage('alert-modal alert-success', 'Symbols successfully saved');
                },
                error: function (data) {
                    alertMessage('alert-modal alert-error', data.statusText);
                } });
            $('#modalDialog').modal('hide');
            return false;
        }
        // @connect to server
        function connectRSPAMD() {
            if (isLogged()) {
                displayUI();
                return;
            }
            var nav = $('#navBar');
            var ui = $('#mainUI');
            var dialog = $('#connectDialog');
            var backdrop = $('#backDrop');
            var disconnect = $('#navBar .pull-right');
            $(ui).hide();
            $(dialog).show();
            $('#connectHost').focus();
            $(backdrop).show();
            $(document).on('submit', '#connectForm', function (e) {
                e.preventDefault();
                var password = $('#connectPassword').val();
                $.ajax({
                    global: false,
                    dataType: 'json',
                    type: 'GET',
                    url: 'auth',
                    beforeSend: function (xhr) {
                        xhr.setRequestHeader('Password', password);
                    },
                    success: function (data) {
                        if (data.auth === 'failed') {
                            $(form).each(function () {
                                $('.form-group').addClass('error');
                            });
                        }
                        else {
                            saveCredentials(data, password);
                            $(dialog).hide();
                            $(backdrop).hide();
                            displayUI();
                        }
                    },
                    error: function (data) {
                        alertMessage('alert-modal alert-error', data.statusText);
                    }
                });
            });
        }
        function displayUI() {
            // @toggle auth and main
            var disconnect = $('#navBar .pull-right');
            statWidgets();
            $('#mainUI').show();
            $('#progress').show();

            getChart();
            initGraph();
            $('#progress').hide();
            $(disconnect).show();
        }

        connectRSPAMD();

        $('#configuration_nav').bind('click', function (e) {
            getActions();
            getMaps();
            getSymbols();
        });

        $(document).ajaxStart(function () {
            $('#navBar').addClass('loading');
        });
        $(document).ajaxComplete(function () {
            $('#navBar').removeClass('loading');
        });
        $('#status_nav').bind('click', function (e) {
            getChart();
        });
        $('#throughput_nav').bind('click', function () {
            getGraphData(selected.selData);
        });
        $('#history_nav').bind('click', function() {
            getHistory();
        });
    });
})();
