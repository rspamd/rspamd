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

/* global FooTable */

define(["jquery", "app/rspamd", "d3evolution", "d3pie", "d3", "footable"],
    ($, rspamd, D3Evolution, D3Pie, d3) => {
        "use strict";

        const rrd_pie_config = {
            cornerRadius: 2,
            size: {
                canvasWidth: 400,
                canvasHeight: 180,
                pieInnerRadius: "50%",
                pieOuterRadius: "80%"
            },
            labels: {
                outer: {
                    format: "none"
                },
                inner: {
                    hideWhenLessThanPercentage: 8,
                    offset: 0
                },
            },
            padAngle: 0.02,
            pieCenterOffset: {
                x: -120,
                y: 10,
            },
            total: {
                enabled: true
            },
        };

        const ui = {};
        let prevUnit = "msg/s";

        ui.draw = function (graphs, neighbours, checked_server, type) {
            const graph_options = {
                title: "Rspamd throughput",
                width: 1060,
                height: 370,
                yAxisLabel: "Message rate, msg/s",

                legend: {
                    space: 140,
                    entries: rspamd.chartLegend
                }
            };

            function initGraph() {
                const graph = new D3Evolution("graph", $.extend({}, graph_options, {
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
                const xExtents = d3.extent(d3.merge(json), (d) => d.x);
                const timeInterval = xExtents[1] - xExtents[0];

                let total = 0;
                const rows = json.map((curr, i) => {
                    // Time intervals that don't have data are excluded from average calculation as d3.mean()ignores nulls
                    const avg = d3.mean(curr, (d) => d.y);
                    // To find an integral on the whole time interval we need to convert nulls to zeroes
                    // eslint-disable-next-line no-bitwise
                    const value = d3.mean(curr, (d) => Number(d.y)) * timeInterval / scaleFactor ^ 0;
                    const yExtents = d3.extent(curr, (d) => d.y);

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

            function initSummaryTable(rows, unit) {
                rspamd.tables.rrd_summary = FooTable.init("#rrd-table", {
                    sorting: {
                        enabled: true
                    },
                    columns: [
                        {name: "label", title: "Action"},
                        {name: "value", title: "Messages", defaultContent: ""},
                        {name: "min", title: "Minimum, <span class=\"unit\">" + unit + "</span>", defaultContent: ""},
                        {name: "avg", title: "Average, <span class=\"unit\">" + unit + "</span>", defaultContent: ""},
                        {name: "max", title: "Maximum, <span class=\"unit\">" + unit + "</span>", defaultContent: ""},
                        {name: "last", title: "Last, " + unit},
                    ],
                    rows: rows.map((curr, i) => ({
                        options: {
                            style: {
                                color: graph_options.legend.entries[i].color
                            }
                        },
                        value: curr
                    }), [])
                });
            }

            function drawRrdTable(rows, unit) {
                if (Object.prototype.hasOwnProperty.call(rspamd.tables, "rrd_summary")) {
                    $.each(rspamd.tables.rrd_summary.rows.all, (i, row) => {
                        row.val(rows[i], false, true);
                    });
                } else {
                    initSummaryTable(rows, unit);
                }
            }

            function updateWidgets(data) {
                let rrd_summary = {rows: []};
                let unit = "msg/s";

                if (data) {
                    // Autoranging
                    let scaleFactor = 1;
                    const yMax = d3.max(d3.merge(data), (d) => d.y);
                    if (yMax < 1) {
                        scaleFactor = 60;
                        unit = "msg/min";
                        data.forEach((s) => {
                            s.forEach((d) => {
                                if (d.y !== null) { d.y *= scaleFactor; }
                            });
                        });
                    }

                    rrd_summary = getRrdSummary(data, scaleFactor);
                }

                if (!graphs.rrd_pie) graphs.rrd_pie = new D3Pie("rrd-pie", rrd_pie_config);
                graphs.rrd_pie.data(rrd_summary.rows);

                graphs.graph.data(data);
                if (unit !== prevUnit) {
                    graphs.graph.yAxisLabel("Message rate, " + unit);
                    $(".unit").text(unit);
                    prevUnit = unit;
                }
                drawRrdTable(rrd_summary.rows, unit);
                document.getElementById("rrd-total-value").innerHTML = rrd_summary.total;
            }

            if (!graphs.graph) {
                graphs.graph = initGraph();
            }


            rspamd.query("graph", {
                success: function (req_data) {
                    let data = null;
                    const neighbours_data = req_data
                        .filter((d) => d.status) // filter out unavailable neighbours
                        .map((d) => d.data);

                    if (neighbours_data.length === 1) {
                        [data] = neighbours_data;
                    } else {
                        let time_match = true;
                        neighbours_data.reduce((res, curr, _, arr) => {
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
                            data = neighbours_data.reduce((res, curr) => curr.map((action, j) => action.map((d, i) => ({
                                x: d.x,
                                y: (res[j][i].y === null) ? d.y : res[j][i].y + d.y
                            }))));
                        }
                    }
                    updateWidgets(data);
                },
                complete: function () { $("#refresh").removeAttr("disabled").removeClass("disabled"); },
                errorMessage: "Cannot receive throughput data",
                errorOnceId: "alerted_graph_",
                data: {type: type}
            });
        };


        // Handling mouse events on overlapping elements
        $("#rrd-pie").mouseover(() => {
            $("#rrd-pie,#rrd-pie-tooltip").css("z-index", "200");
            $("#rrd-table_toggle").css("z-index", "300");
        });
        $("#rrd-table_toggle").mouseover(() => {
            $("#rrd-pie,#rrd-pie-tooltip").css("z-index", "0");
            $("#rrd-table_toggle").css("z-index", "0");
        });

        return ui;
    });
