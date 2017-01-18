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
(function () {
    $(document).ready(function () {
        // begin
        var pie;
        var rrd_pie;
        var history;
        var errors;
        var graph;
        var symbols;
        var read_only = false;
        var neighbours = []; //list of clusters
        var checked_server = "All SERVERS";

        var timer_id = [];
        var selData; // Graph's dataset selector state

        // Bind event handlers to selectors
        $("#selData").change(function () {
            selData = this.value;
            tabClick("#throughput_nav");
        });
        $("#selConvert").change(function () {
            graph.convert(this.value);
        });
        $("#selType").change(function () {
            graph.type(this.value);
        });
        $("#selInterpolate").change(function () {
            graph.interpolate(this.value);
        });

        function stopTimers() {
            for (var key in timer_id) {
                Visibility.stop(timer_id[key]);
            }
        }

        function disconnect() {
            if (pie) {
                pie.destroy();
            }
            if (rrd_pie) {
                rrd_pie.destroy();
            }
            if (graph) {
                graph.destroy();
                graph = undefined;
            }
            if (history) {
                history.destroy();
            }
            if (errors) {
                errors.destroy();
            }
            if (symbols) {
                symbols.destroy();
                symbols = null;
            }
            stopTimers();
            cleanCredentials();
            connectRSPAMD();
            // window.location.reload();
            return false;
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
                    statWidgets();
                    timer_id.status = Visibility.every(10000, function () {
                        statWidgets();
                    });
                    break;
                case "#throughput_nav":
                    getGraphData(selData);
                    const autoRefresh = {
                        hourly: 60000,
                        daily: 300000
                    };
                    timer_id.throughput = Visibility.every(autoRefresh[selData] || 3600000, function () {
                        getGraphData(selData);
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

        // @supports session storage
        function supportsSessionStorage() {
            return typeof (Storage) !== "undefined";
        }
        // @return password
        function getPassword() {
          return password = sessionStorage.getItem('Password');
        }

        // @detect session storate
        supportsSessionStorage();
        // @save credentials
        function saveCredentials(password) {
          sessionStorage.setItem('Password', password);
        }
        // @update credentials
        function saveActions(data) {
            sessionStorage.setItem('Actions', JSON.stringify(data));
        }
        // @update credentials
        function saveMaps(data) {
            sessionStorage.setItem('Maps', JSON.stringify(data));
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
            if (sessionStorage.getItem('Credentials') != null) {
                return true;
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
                        if ((item.editable == false || read_only)) {
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
        function getMapById(mode) {
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
                        if ((item.editable == false || read_only)) {
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

        // @ ms to date
        function msToTime(seconds) {
             years = seconds / 31536000 >> 0 // 3600*24*365
             months = seconds % 31536000 / 2628000 >> 0; //3600*24*365/12
             days = seconds % 31536000 % 2628000 / 86400 >> 0; //24*3600
             hours = seconds % 31536000 % 2628000 % 86400 / 3600 >> 0;
             minutes = seconds % 31536000 % 2628000 % 86400 % 3600 / 60 >> 0;
             if (years > 0) {
               if (months > 0) {
                 out = years + 'yr ' + months + 'mth';
               } else {
                 out = years + 'yr ' + days + 'd';
               }
             } else if (months > 0) {
               out = months + 'mth ' + days + 'd';
             } else if (days > 0) {
               out = days + 'd ' + hours + 'hr';
             } else if (hours > 0) {
               out = hours + 'hr ' + minutes + 'min';
             } else {
               out = minutes + 'min';
             }
             return out;
        }

        function displayStatWidgets() {
          var widgets = $('#statWidgets');
          $(widgets).empty().hide();
          var servers = JSON.parse(sessionStorage.getItem('Credentials'));

          var data = {}
          if (servers && servers[checked_server]) {
              data = servers[checked_server].data;
          }
          var stat_w = [];

          $.each(data, function (i, item) {
              var widget = '';
              if (i == 'auth') {}
              else if (i == 'error') {}
              else if (i == 'version') {
                  widget = '<div class="left"><strong>' + item + '</strong>' +
                      i + '</div>';
                  $(widget).appendTo(widgets);
              } else if (i == 'uptime') {
                  widget = '<div class="right"><strong>' + msToTime(item) +
                      '</strong>' + i + '</div>';
                  $(widget).appendTo(widgets);
              } else {
                  widget = '<li class="stat-box"><div class="widget"><strong>' +
                      Humanize.compactInteger(item) + '</strong>' + i + '</div></li>';
                  if (i == 'scanned') {
                      stat_w[0] = widget;
                  } else if (i == 'clean') {
                      stat_w[1] = widget;
                  } else if (i == 'greylist') {
                      stat_w[2] = widget;
                  } else if (i == 'probable') {
                      stat_w[3] = widget;
                  } else if (i == 'reject') {
                      stat_w[4] = widget;
                  } else if (i == 'learned') {
                      stat_w[5] = widget;
                  }
              }
          });
          $.each(stat_w, function (i, item) {
              $(item).appendTo(widgets);
          });
          $('#statWidgets .left,#statWidgets .right').wrapAll('<li class="stat-box pull-right"><div class="widget"></div></li>');
          $('#statWidgets').find('li.pull-right').appendTo('#statWidgets');

          $("#clusterTable tbody").empty();
          $.each(servers, function (key, val) {
              var glyph_status;
              if (val.status) {
                  glyph_status = "glyphicon glyphicon-ok-circle";
              }
              else {
                  glyph_status = "glyphicon glyphicon-remove-circle";
              }
              if (checked_server == key) {
                $('#clusterTable tbody').append('<tr>' +
                    '<td class="col1" title="Radio"><input type="radio" class="form-control radio" name="clusterName" value="' + key + '" checked></td>' +
                    '<td class="col2" title="SNAme">' + key + '</td>' +
                    '<td class="col3" title="SHost">' + val.host + '</td>' +
                    '<td class="col4" title="SStatus"><span class="icon"><i class="' + glyph_status + '"></i></span></td>' +
                    '<td class="col5" title="SId">' + val.data.config_id.substring(0, 8) + '</td></tr>');
              } else {
                if (val.status) {
                    $('#clusterTable tbody').append('<tr>' +
                        '<td class="col1" title="Radio"><input type="radio" class="form-control radio" name="clusterName" value="' + key + '"></td>' +
                        '<td class="col2" title="SNAme">' + key + '</td>' +
                        '<td class="col3" title="SHost">' + val.host + '</td>' +
                        '<td class="col4" title="SStatus"><span class="icon"><i class="' + glyph_status + '"></i></span></td>' +
                        '<td class="col5" title="SId">' + val.data.config_id.substring(0, 8) + '</td></tr>');
                }
                else {
                    $('#clusterTable tbody').append('<tr>' +
                            '<td class="col1" title="Radio"><input type="radio" class="form-control radio disabled" disabled="disabled" name="clusterName" value="' + key + '"></td>' +
                            '<td class="col2" title="SNAme">' + key + '</td>' +
                            '<td class="col3" title="SHost">' + val.host + '</td>' +
                            '<td class="col4" title="SStatus"><span class="icon"><i class="' + glyph_status + '"></i></span></td>' +
                            '<td class="col5" title="SId">???</td></tr>');
                }

              }
          });
          $(widgets).show();
        }

        // Query neighbours and call the specified function at the end,
        // Data received will be pushed inside object:
        // {server1: data, server2: data} and passed to a callback
        function queryNeighbours(req_url, on_success, on_error) {
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
                        $.ajax({
                            jsonp: false,
                            beforeSend: function (xhr) {
                                xhr.setRequestHeader("Password", getPassword());
                            },
                            url: neighbours_status[ind].url + req_url,
                            success: function (data) {
                                neighbours_status[ind].checked = true;

                                if (jQuery.isEmptyObject(data)) {
                                    neighbours_status[ind].status = false; //serv does not work
                                } else {
                                    neighbours_status[ind].status = true; //serv does not work
                                    neighbours_status[ind].data = data;
                                    if (!('config_id' in neighbours_status[ind].data)) {
                                        neighbours_status[ind].data.config_id = "";
                                    }
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
                        });
                    });
                },
                error: function () {
                    alertMessage('alert-error', 'Cannot receive neighbours data');
                },
            });
        }

        // @show widgets
        function statWidgets() {
            queryNeighbours("/auth", function(neighbours_status) {
                var neighbours_sum = {
                        version: neighbours_status[0].data.version,
                        auth: "ok",
                        uptime: 0,
                        clean: 0,
                        probable: 0,
                        greylist: 0,
                        reject: 0,
                        soft_reject: 0,
                        scanned: 0,
                        learned: 0,
                        read_only: neighbours_status[0].data.read_only,
                        config_id: ""
                };
                var status_count = 0;
                for(var e in neighbours_status) {
                    if(neighbours_status[e].status == true) {
                        // Remove alert status
                        localStorage.removeItem(e + '_alerted');
                        neighbours_sum.clean += neighbours_status[e].data.clean;
                        neighbours_sum.probable += neighbours_status[e].data.probable;
                        neighbours_sum.greylist += neighbours_status[e].data.greylist;
                        neighbours_sum.reject += neighbours_status[e].data.reject;
                        neighbours_sum.soft_reject += neighbours_status[e].data.soft_reject;
                        neighbours_sum.scanned += neighbours_status[e].data.scanned;
                        neighbours_sum.learned += neighbours_status[e].data.learned;
                        neighbours_sum.uptime += neighbours_status[e].data.uptime;
                        status_count++;
                    }
                }
                neighbours_sum.uptime = Math.floor(neighbours_sum.uptime / status_count);
                var to_Credentials = {};
                to_Credentials["All SERVERS"] = { name: "All SERVERS",
                        url: "",
                        host: "",
                        checked: true,
                        data: neighbours_sum,
                        status: true
                }
                neighbours_status.forEach(function (elmt) {
                    to_Credentials[elmt.name] = elmt;
                });
                sessionStorage.setItem("Credentials", JSON.stringify(to_Credentials));
                displayStatWidgets();
                getChart();
            },
            function (serv, jqXHR, textStatus, errorThrown) {
                var alert_status = serv.name + '_alerted';

                if (!(alert_status in sessionStorage)) {
                    sessionStorage.setItem(alert_status, true);
                    alertMessage('alert-error', 'Cannot receive stats data from: ' +
                        serv.name + ', error: ' + errorThrown);
                }
            });
        }

        $(document).on('click', 'input:radio[name="clusterName"]', function (e) {
            if (!this.disabled) {
                checked_server = this.value;
                tabClick("#status_nav");
            }
        });

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
            } else {
                $('#modalSave').show();
            }
            return false;
        });
        // close modal without saving
        $(document).on('click', '[data-dismiss="modal"]', function (e) {
            $('#modalBody form').hide();
        });

        function getChart() {
            var creds = JSON.parse(sessionStorage.getItem('Credentials'));
            if (creds && creds[checked_server]) {
                var data = creds[checked_server].data;
                var new_data = [ {
                    "color" : "#66cc00",
                    "label" : "Clean",
                    "data" : data.clean,
                    "value" : data.clean
                }, {
                    "color" : "#cc9966",
                    "label" : "Temporary rejected",
                    "data" : data.soft_reject,
                    "value" : data.soft_reject
                }, {
                    "color" : "#FFD700",
                    "label" : "Probable spam",
                    "data" : data.probable,
                    "value" : data.probable
                }, {
                    "color" : "#436EEE",
                    "label" : "Greylisted",
                    "data" : data.greylist,
                    "value" : data.greylist
                }, {
                    "color" : "#FF0000",
                    "label" : "Rejected",
                    "data" : data.reject,
                    "value" : data.reject
                } ];
                pie = drawPie(pie, "chart", new_data);
            }
        }

        function drawPie(obj, id, data, conf) {
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
                                "speed": 500
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
        }

        var rrd_pie_config = {
            header: {},
            size: {
                canvasWidth: 400,
                canvasHeight: 180,
                pieInnerRadius: "20%",
                pieOuterRadius: "80%"
            },
            labels: {
                outer: {
                    format: "none"
                },
                inner: {
                    hideWhenLessThanPercentage: 8
                },
            },
            misc: {
                pieCenterOffset: {
                    x: -120,
                    y: 10,
                },
                gradient: {
                    enabled: true,
                },
            },
        };

        var graph_options = {
            title: "Rspamd throughput",
            width: 1060,
            height: 370,
            yAxisLabel: "Message rate, msg/s",

            legend: {
                space: 140,
                entries: [{
                    label: "Rejected",
                    color: "#FF0000"
                }, {
                    label: "Temporary rejected",
                    color: "#CC9966"
                }, {
                    label: "Subject rewrited",
                    color: "#FF6600"
                }, {
                    label: "Probable spam",
                    color: "#FFD700"
                }, {
                    label: "Greylisted",
                    color: "#436EEE"
                }, {
                    label: "Clean",
                    color: "#66cc00"
                }]
            }
        };

        function initGraph() {
            // Get selectors' current state
            function getSelector(id) {
                var e = document.getElementById(id);
                return e.options[e.selectedIndex].value;
            }

            selData = getSelector("selData");

            graph = new D3Evolution("graph", $.extend({}, graph_options, {
                type:        getSelector("selType"),
                interpolate: getSelector("selInterpolate"),
                convert:     getSelector("selConvert"),
            }));
        }

        function getRrdSummary(json) {
            const xExtents = d3.extent(d3.merge(json), function (d) { return d.x; });
            const timeInterval = xExtents[1] - xExtents[0];

            return json.map(function (curr, i) {
                var avg = d3.mean(curr, function (d) { return d.y; });
                var yExtents = d3.extent(curr, function (d) { return d.y; });

                return {
                    label: graph_options.legend.entries[i].label,
                    value: avg && (avg * timeInterval) ^ 0,
                    min: yExtents[0],
                    avg: avg && avg.toFixed(6),
                    max: yExtents[1],
                    last: curr[curr.length - 1].y,
                    color: graph_options.legend.entries[i].color,
                };
            }, []);
        }

        function drawRrdTable(data) {
            $('#rrd-table').DataTable({
                destroy: true,
                paging: false,
                searching: false,
                info: false,
                data: data,
                columns: [
                    { data: "label", title: "Action" },
                    { data: "value", title: "Messages",       defaultContent: "" },
                    { data: "min",   title: "Minimum, msg/s", defaultContent: "" },
                    { data: "avg",   title: "Average, msg/s", defaultContent: "" },
                    { data: "max",   title: "Maximum, msg/s", defaultContent: "" },
                    { data: "last",  title: "Last, msg/s" },
                ],

                "fnRowCallback": function (nRow, aData) {
                    $(nRow).css("color", aData.color)
                }
            });
        }

        function getGraphData(type) {
            $.ajax({
                dataType: 'json',
                type: 'GET',
                url: 'graph',
                jsonp: false,
                data: {
                    "type": type
                },
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', getPassword());
                },
                success: function (data) {
                    const rrd_summary = getRrdSummary(data);
                    graph.data(data);
                    rrd_pie = drawPie(rrd_pie, "rrd-pie", rrd_summary, rrd_pie_config);
                    drawRrdTable(rrd_summary);
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
            if (digits == 0 || digits > 4) {
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
                            var label;
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
                                '<td><button type="button" class="btn btn-primary btn-sm mb-disabled">Save</button></td></tr>');
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
                            {"width": "5%", "searchable": false, "orderable": false, "type": "html"}
                        ],
                    });
                    symbols.columns.adjust().draw();
                    $('#symbolsTable :button').on('click',
                        function(){saveSymbols("./savesymbols", "symbolsTable")});
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
                return
            };
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
                success: function (data) {
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
            if (source === 'spam') {
                var url = 'learnspam';
            } else if (source === 'ham') {
                var url = 'learnham';
            } else if (source == 'fuzzy') {
                var url = 'fuzzyadd';
            } else if (source === 'scan') {
                var url = 'scan';
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
                    try {
                        var json = $.parseJSON(xhr.responseText);
                        var errorMsg = $('<a>').text(json.error).html();
                    } catch (err) {
                        var errorMsg = $('<a>').text("Error: [" + textStatus + "] " + errorThrown).html();
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
            var items = [];
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
                      $('#actionsFormField').attr('disabled', true)
                    }
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
        // @catch changes of file upload form
        $(window).resize(function (e) {
            var form = $(this).attr('id');
            var height = $(form).height();
        });
        // @watch textarea changes
        $('textarea').change(function () {
            if ($(this).val().length != '') {
                $(this).closest('form').find('button').removeAttr('disabled').removeClass('disabled');
            } else {
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
            } else if (type === 'map') {
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
                jsonp: false,
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
                values.push({
                    name: $(this).attr('id').substring(5),
                    value: parseFloat($(this).val())
                });
            });
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
            $('#modalDialog').modal('hide');
            return false;
        }
        // @connect to server
        function connectRSPAMD() {
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
            var nav = $('#navBar');
            var ui = $('#mainUI');
            var dialog = $('#connectDialog');
            var backdrop = $('#backDrop');
            var disconnect = $('#navBar .pull-right');
            $(ui).hide();
            $(dialog).show();
            $('#connectHost').focus();
            $(backdrop).show();
            document.getElementById("connectPassword").focus();
            $('#connectForm').one('submit', function (e) {
                e.preventDefault();
                var password = $('#connectPassword').val();
                document.getElementById('connectPassword').value = '';
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
                        if (data.auth === 'failed') {
                            $(form).each(function () {
                                $('.form-group').addClass('error');
                            });
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
                        alertMessage('alert-modal alert-error', data.statusText);
                    }
                });
            });
        }

        function displayUI() {
            // @toggle auth and main
            var disconnect = $('#navBar .pull-right');
            $('#mainUI').show();
            $('#progress').show();

            initGraph();
            tabClick("#refresh");

            $('#progress').hide();
            $(disconnect).show();
        }

        $.ajaxSetup({
            timeout: 1000,
            jsonp: false
        })
        connectRSPAMD();

        $(document).ajaxStart(function () {
            $('#navBar').addClass('loading');
        });
        $(document).ajaxComplete(function () {
            setTimeout(function () {
                $('#navBar').removeClass('loading');
            }, 1000);
        });

        $('a[data-toggle="tab"]').on('click', function (e) {
            const tab_id = "#" + $(e.target).attr("id")
            tabClick(tab_id);
        });
    });
})();
