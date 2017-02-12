/*
 The MIT License (MIT)

 Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>
 Copyright (C) 2017 Alexander Moisseev

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

define(['jquery', 'd3evolution', 'datatables'],
function($, D3Evolution, unused) {
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
                color: "#BF8040"
            }, {
                label: "Subject rewrited",
                color: "#FF6600"
            }, {
                label: "Probable spam",
                color: "#FFAD00"
            }, {
                label: "Greylisted",
                color: "#436EEE"
            }, {
                label: "Clean",
                color: "#66CC00"
            }]
        }
    };

    function initGraph() {
        // Get selectors' current state
        function getSelector(id) {
            var e = document.getElementById(id);
            return e.options[e.selectedIndex].value;
        }
        var graph = new D3Evolution("graph", $.extend({}, graph_options, {
            type:        getSelector("selType"),
            interpolate: getSelector("selInterpolate"),
            convert:     getSelector("selConvert"),
        }));
        $("#selConvert").change(function () {
            graph.convert(this.value);
        });
        $("#selType").change(function () {
            graph.type(this.value);
        });
        $("#selInterpolate").change(function () {
            graph.interpolate(this.value);
        });

        return graph;
    }

    function getRrdSummary(json) {
        var xExtents = d3.extent(d3.merge(json), function (d) { return d.x; });
        var timeInterval = xExtents[1] - xExtents[0];

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
                $(nRow).css("color", aData.color);
            }
        });
    }

    var interface = {};

    interface.draw = function(rspamd, graphs, neighbours, checked_server, type) {
        function updateWidgets(data) {
            graphs.graph.data(data);
            if (!data) {
                graphs.rrd_pie.destroy();
                drawRrdTable([]);
                return;
            }
            var rrd_summary = getRrdSummary(data);
            graphs.rrd_pie = rspamd.drawPie(graphs.rrd_pie,
                "rrd-pie",
                rrd_summary,
                rrd_pie_config);
            drawRrdTable(rrd_summary);
        }

        if (graphs.graph === undefined) {
            graphs.graph = initGraph();
        }

        if (type === undefined) {
            function getSelector(id) {
                var e = document.getElementById(id);
                return e.options[e.selectedIndex].value;
            }
            type = getSelector("selData");
        }

        if (checked_server === "All SERVERS") {
            rspamd.queryNeighbours("graph", function (neighbours_data) {
                neighbours_data
                    .filter(function (d) { return d.status }) // filter out unavailable neighbours
                    .map(function (d){ return d.data; })
                    .reduce(function (res, curr) {
                        if ((curr[0][0].x !== res[0][0].x) ||
                            (curr[0][curr[0].length - 1].x !== res[0][res[0].length - 1].x)) {
                            rspamd.alertMessage('alert-error',
                                'Neighbours time extents do not match. Check if time is synchronized on all servers.');
                            updateWidgets();
                            return;
                        }

                        let data = [];
                        curr.forEach(function (action, j) {
                            data.push(
                                action.map(function (d, i) {
                                    return {
                                        x: d.x,
                                        y: ((res[j][i].y === null) ? d.y : res[j][i].y + d.y)
                                    };
                                })
                            );
                        });
                        updateWidgets(data);
                    });
            },
            function (serv, jqXHR, textStatus, errorThrown) {
                var alert_status = serv.name + '_alerted';

                if (!(alert_status in sessionStorage)) {
                    sessionStorage.setItem(alert_status, true);
                    rspamd.alertMessage('alert-error', 'Cannot receive RRD data from: ' +
                        serv.name + ', error: ' + errorThrown);
                }
            }, "GET", {}, {}, {
                type: type
            });
            return;
        }

        $.ajax({
            dataType: 'json',
            type: 'GET',
            url: neighbours[checked_server].url + 'graph',
            jsonp: false,
            data: {
                "type": type
            },
            beforeSend: function (xhr) {
                xhr.setRequestHeader('Password', rspamd.getPassword());
            },
            success: function (data) {
                updateWidgets(data);
            },
            error: function (jqXHR, textStatus, errorThrown) {
                rspamd.alertMessage('alert-error', 'Cannot receive throughput data: ' +
                    textStatus + ' ' + jqXHR.status + ' ' + errorThrown);
            }
        });
    };

    return interface;
});
