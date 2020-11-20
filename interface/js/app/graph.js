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

/* global d3:false, FooTable:false */

define(["jquery", "d3evolution", "footable"],
    function ($, D3Evolution) {
        "use strict";

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
                    label: "reject",
                    color: "#FF0000"
                }, {
                    label: "soft reject",
                    color: "#BF8040"
                }, {
                    label: "rewrite subject",
                    color: "#FF6600"
                }, {
                    label: "add header",
                    color: "#FFAD00"
                }, {
                    label: "greylist",
                    color: "#436EEE"
                }, {
                    label: "no action",
                    color: "#66CC00"
                }]
            }
        };

        function initGraph(rspamd) {
            var graph = new D3Evolution("graph", $.extend({}, graph_options, {
                yScale: rspamd.getSelector("selYScale"),
                type: rspamd.getSelector("selType"),
                interpolate: rspamd.getSelector("selInterpolate"),
                convert: rspamd.getSelector("selConvert"),
            }));
            $("#selYScale").change(function () {
                graph.yScale(this.value);
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

            return graph;
        }

        function getRrdSummary(json, scaleFactor) {
            var xExtents = d3.extent(d3.merge(json), function (d) { return d.x; });
            var timeInterval = xExtents[1] - xExtents[0];

            var total = 0;
            var rows = json.map(function (curr, i) {
                // Time intervals that don't have data are excluded from average calculation as d3.mean()ignores nulls
                var avg = d3.mean(curr, function (d) { return d.y; });
                // To find an integral on the whole time interval we need to convert nulls to zeroes
                var value = d3.mean(curr, function (d) { return Number(d.y); }) * timeInterval / scaleFactor ^ 0; // eslint-disable-line no-bitwise
                var yExtents = d3.extent(curr, function (d) { return d.y; });

                total += value;
                return {
                    label: graph_options.legend.entries[i].label,
                    value: value,
                    min: Number(yExtents[0].toFixed(6)),
                    avg: Number(avg.toFixed(6)),
                    max: Number(yExtents[1].toFixed(6)),
                    last: Number(curr[curr.length - 1].y.toFixed(6)),
                    color: graph_options.legend.entries[i].color,
                };
            }, []);

            return {
                rows: rows,
                total: total
            };
        }

        function initSummaryTable(tables, rows, unit) {
            tables.rrd_summary = FooTable.init("#rrd-table", {
                sorting: {
                    enabled: true
                },
                columns: [
                    {name:"label", title:"Action"},
                    {name:"value", title:"Messages", defaultContent:""},
                    {name:"min", title:"Minimum, <span class=\"unit\">" + unit + "</span>", defaultContent:""},
                    {name:"avg", title:"Average, <span class=\"unit\">" + unit + "</span>", defaultContent:""},
                    {name:"max", title:"Maximum, <span class=\"unit\">" + unit + "</span>", defaultContent:""},
                    {name:"last", title:"Last, " + unit},
                ],
                rows: rows.map(function (curr, i) {
                    return {
                        options: {
                            style: {
                                color: graph_options.legend.entries[i].color
                            }
                        },
                        value: curr
                    };
                }, [])
            });
        }

        function drawRrdTable(tables, rows, unit) {
            if (Object.prototype.hasOwnProperty.call(tables, "rrd_summary")) {
                $.each(tables.rrd_summary.rows.all, function (i, row) {
                    row.val(rows[i], false, true);
                });
            } else {
                initSummaryTable(tables, rows, unit);
            }
        }

        var ui = {};
        var prevUnit = "msg/s";

        ui.draw = function (rspamd, graphs, tables, neighbours, checked_server, type) {
            function updateWidgets(data) {
                var rrd_summary = {rows:[]};
                var unit = "msg/s";

                if (data) {
                    // Autoranging
                    var scaleFactor = 1;
                    var yMax = d3.max(d3.merge(data), function (d) { return d.y; });
                    if (yMax < 1) {
                        scaleFactor = 60;
                        unit = "msg/min";
                        data.forEach(function (s) {
                            s.forEach(function (d) {
                                if (d.y !== null) { d.y *= scaleFactor; }
                            });
                        });
                    }

                    rrd_summary = getRrdSummary(data, scaleFactor);
                }

                if (graphs.rrd_pie) {
                    graphs.rrd_pie.destroy();
                    delete graphs.rrd_pie;
                }
                if (rrd_summary.total) {
                    graphs.rrd_pie = rspamd.drawPie(graphs.rrd_pie,
                        "rrd-pie",
                        rrd_summary.rows,
                        rrd_pie_config);
                } else {
                    // Show grayed out pie as percentage is undefined
                    graphs.rrd_pie = rspamd.drawPie(graphs.rrd_pie,
                        "rrd-pie",
                        [{
                            value: 1,
                            color: "#FFFFFF",
                        }],
                        $.extend({}, rrd_pie_config, {
                            labels: {
                                outer: {
                                    format: "none"
                                },
                                inner: {
                                    format: "none"
                                },
                            },
                            tooltips: {
                                enabled: true,
                                string: "Undefined"
                            },
                        })
                    );
                }

                graphs.graph.data(data);
                if (unit !== prevUnit) {
                    graphs.graph.yAxisLabel("Message rate, " + unit);
                    $(".unit").text(unit);
                    prevUnit = unit;
                }
                drawRrdTable(tables, rrd_summary.rows, unit);
                document.getElementById("rrd-total-value").innerHTML = rrd_summary.total;
            }

            if (!graphs.graph) {
                graphs.graph = initGraph(rspamd);
            }

            rspamd.query("graph", {
                success: function (req_data) {
                    var data = null;
                    var neighbours_data = req_data
                        .filter(function (d) { return d.status; }) // filter out unavailable neighbours
                        .map(function (d) { return d.data; });

                    if (neighbours_data.length === 1) {
                        data = neighbours_data[0];
                    } else {
                        var time_match = true;
                        neighbours_data.reduce(function (res, curr, _, arr) {
                            if ((curr[0][0].x !== res[0][0].x) ||
                            (curr[0][curr[0].length - 1].x !== res[0][res[0].length - 1].x)) {
                                time_match = false;
                                rspamd.alertMessage("alert-error",
                                    "Neighbours time extents do not match. Check if time is synchronized on all servers.");
                                arr.splice(1); // Break out of .reduce() by mutating the source array
                            }
                            return curr;
                        });

                        if (time_match) {
                            data = neighbours_data.reduce(function (res, curr) {
                                return curr.map(function (action, j) {
                                    return action.map(function (d, i) {
                                        return {
                                            x: d.x,
                                            y: (res[j][i].y === null) ? d.y : res[j][i].y + d.y
                                        };
                                    });
                                });
                            });
                        }
                    }
                    updateWidgets(data);
                },
                complete: function () { $("#refresh").removeAttr("disabled").removeClass("disabled"); },
                errorMessage: "Cannot receive throughput data",
                errorOnceId: "alerted_graph_",
                data: {type:type}
            });
        };

        ui.setup = function (rspamd) {
            // Handling mouse events on overlapping elements
            $("#rrd-pie").mouseover(function () {
                $("#rrd-pie").css("z-index", "200");
                $("#rrd-table_toggle").css("z-index", "300");
            });
            $("#rrd-table_toggle").mouseover(function () {
                $("#rrd-pie").css("z-index", "0");
                $("#rrd-table_toggle").css("z-index", "0");
            });

            return rspamd.getSelector("selData");
        };

        return ui;
    });
