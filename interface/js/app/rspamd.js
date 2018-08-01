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

/* global jQuery:false, Visibility:false */

define(["jquery", "d3pie", "visibility", "app/stats", "app/graph", "app/config",
    "app/symbols", "app/history", "app/upload"],
function ($, d3pie, visibility, tab_stat, tab_graph, tab_config,
    tab_symbols, tab_history, tab_upload) {
    "use strict";
    // begin
    var graphs = {};
    var tables = {};
    var neighbours = []; // list of clusters
    var checked_server = "All SERVERS";
    var ui = {
        read_only: false,
    };

    var timer_id = [];
    var selData; // Graph's dataset selector state

    function cleanCredentials() {
        sessionStorage.clear();
        $("#statWidgets").empty();
        $("#listMaps").empty();
        $("#modalBody").empty();
        $("#historyLog tbody").remove();
        $("#errorsLog tbody").remove();
        $("#symbolsTable tbody").remove();
    }

    function stopTimers() {
        for (var key in timer_id) {
            Visibility.stop(timer_id[key]);
        }
    }

    function disconnect() {
        if (graphs.chart) {
            graphs.chart.destroy();
            delete graphs.chart;
        }
        if (graphs.rrd_pie) {
            graphs.rrd_pie.destroy();
            delete graphs.rrd_pie;
        }
        if (graphs.graph) {
            graphs.graph.destroy();
            delete graphs.graph;
        }
        if (tables.history) {
            tables.history.destroy();
            delete tables.history;
        }
        if (tables.errors) {
            tables.errors.destroy();
            delete tables.errors;
        }
        if (tables.symbols) {
            tables.symbols.destroy();
            delete tables.symbols;
        }

        stopTimers();
        cleanCredentials();
        ui.connect();
    }

    function tabClick(id) {
        var tab_id = id;
        if ($(tab_id).attr("disabled")) return;
        $(tab_id).attr("disabled", true);

        stopTimers();

        if (tab_id === "#refresh") {
            tab_id = "#" + $(".navbar-nav .active > a").attr("id");
        }

        switch (tab_id) {
        case "#status_nav":
            tab_stat.statWidgets(ui, graphs, checked_server);
            timer_id.status = Visibility.every(10000, function () {
                tab_stat.statWidgets(ui, graphs, checked_server);
            });
            break;
        case "#throughput_nav":
            tab_graph.draw(ui, graphs, neighbours, checked_server, selData);

            var autoRefresh = {
                hourly: 60000,
                daily: 300000
            };
            timer_id.throughput = Visibility.every(autoRefresh[selData] || 3600000, function () {
                tab_graph.draw(ui, graphs, neighbours, checked_server, selData);
            });
            break;
        case "#configuration_nav":
            tab_config.getActions(ui, checked_server);
            tab_config.getMaps(ui);
            break;
        case "#symbols_nav":
            tab_symbols.getSymbols(ui, checked_server);
            break;
        case "#history_nav":
            tab_history.getHistory(ui, tables, neighbours, checked_server);
            tab_history.getErrors(ui, tables, neighbours, checked_server);
            break;
        case "#disconnect":
            disconnect();
            break;
        }

        setTimeout(function () {
            $(tab_id).removeAttr("disabled");
            $("#refresh").removeAttr("disabled");
        }, 1000);
    }

    // @return password
    function getPassword() {
        return sessionStorage.getItem("Password");
    }

    // @save credentials
    function saveCredentials(password) {
        sessionStorage.setItem("Password", password);
    }

    function isLogged() {
        if (sessionStorage.getItem("Credentials") !== null) {
            return true;
        }
        return false;
    }

    function displayUI() {
        // @toggle auth and main
        var buttons = $("#navBar .pull-right");
        $("#mainUI").show();
        $("#progress").show();
        $(buttons).show();
        tabClick("#refresh");
        $("#progress").hide();
    }

    function alertMessage(alertClass, alertText) {
        var a = $("<div class=\"alert " + alertClass + " alert-dismissible fade in show\">" +
                "<button type=\"button\" class=\"close\" data-dismiss=\"alert\" title=\"Dismiss\">&times;</button>" +
                "<strong>" + alertText + "</strong>");
        $(".notification-area").append(a);

        setTimeout(function () {
            $(a).fadeTo(500, 0).slideUp(500, function () {
                $(this).alert("close");
            });
        }, 5000);
    }

    function queryServer(neighbours_status, ind, req_url, o) {
        neighbours_status[ind].checked = false;
        neighbours_status[ind].data = {};
        neighbours_status[ind].status = false;
        var req_params = {
            jsonp: false,
            data: o.data,
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Password", getPassword());

                if (o.headers) {
                    $.each(o.headers, function (hname, hvalue) {
                        xhr.setRequestHeader(hname, hvalue);
                    });
                }
            },
            url: neighbours_status[ind].url + req_url,
            success: function (json) {
                neighbours_status[ind].checked = true;
                if (!jQuery.isEmptyObject(json) || req_url === "neighbours") {
                    neighbours_status[ind].status = true;
                    neighbours_status[ind].data = json;
                }
            },
            error: function (jqXHR, textStatus, errorThrown) {
                neighbours_status[ind].checked = true;
                function errorMessage() {
                    alertMessage("alert-error", neighbours_status[ind].name + " > " +
                        ((o.errorMessage) ? o.errorMessage : "Request failed") + ": " + errorThrown);
                }
                if (o.error) {
                    o.error(neighbours_status[ind],
                        jqXHR, textStatus, errorThrown);
                } else if (o.errorOnceId) {
                    var alert_status = o.errorOnceId + neighbours_status[ind].name;
                    if (!(alert_status in sessionStorage)) {
                        sessionStorage.setItem(alert_status, true);
                        errorMessage();
                    }
                } else {
                    errorMessage();
                }
            },
            complete: function () {
                if (neighbours_status.every(function (elt) { return elt.checked; })) {
                    if (neighbours_status.some(function (elt) { return elt.status; })) {
                        if (o.success) {
                            o.success(neighbours_status);
                        } else {
                            alertMessage("alert-success", "Request completed");
                        }
                    } else {
                        alertMessage("alert-error", "Request failed");
                    }
                }
            }
        };
        if (o.method) {
            req_params.method = o.method;
        }
        if (o.params) {
            $.each(o.params, function (k, v) {
                req_params[k] = v;
            });
        }
        $.ajax(req_params);
    }

    // Public functions
    ui.alertMessage = alertMessage;
    ui.setup = function () {
        $("#selData").change(function () {
            selData = this.value;
            tabClick("#throughput_nav");
        });
        $.ajaxSetup({
            timeout: 20000,
            jsonp: false
        });

        $(document).ajaxStart(function () {
            $("#navBar").addClass("loading");
        });
        $(document).ajaxComplete(function () {
            setTimeout(function () {
                $("#navBar").removeClass("loading");
            }, 1000);
        });

        $("a[data-toggle=\"tab\"]").on("click", function (e) {
            var tab_id = "#" + $(e.target).attr("id");
            tabClick(tab_id);
        });

        $("#selSrv").change(function () {
            checked_server = this.value;
            $("#selSrv [value=\"" + checked_server + "\"]").prop("checked", true);
            tabClick("#" + $("#navBar ul li.active > a").attr("id"));
        });

        // Radio buttons
        $(document).on("click", "input:radio[name=\"clusterName\"]", function () {
            if (!this.disabled) {
                checked_server = this.value;
                tabClick("#status_nav");
            }
        });
        tab_config.setup(ui);
        tab_symbols.setup(ui);
        tab_upload.setup(ui);
        selData = tab_graph.setup();
    };

    ui.connect = function () {
        if (isLogged()) {
            var data = JSON.parse(sessionStorage.getItem("Credentials"));

            if (data && data[checked_server].read_only) {
                ui.read_only = true;
                $("#learning_nav").hide();
                $("#resetHistory").attr("disabled", true);
                $("#errors-history").hide();
            } else {
                ui.read_only = false;
                $("#learning_nav").show();
                $("#resetHistory").removeAttr("disabled", true);
            }
            displayUI();
            return;
        }

        var dialog = $("#connectDialog");
        var backdrop = $("#backDrop");
        $("#mainUI").hide();
        $(dialog).show();
        $(backdrop).show();
        $("#connectPassword").focus();
        $("#connectForm").off("submit");

        $("#connectForm").on("submit", function (e) {
            e.preventDefault();
            var password = $("#connectPassword").val();
            if (!(/^[\u0020-\u007e]*$/).test(password)) {
                alertMessage("alert-modal alert-error", "Invalid characters in the password");
                $("#connectPassword").focus();
                return;
            }

            $.ajax({
                global: false,
                jsonp: false,
                dataType: "json",
                type: "GET",
                url: "auth",
                beforeSend: function (xhr) {
                    xhr.setRequestHeader("Password", password);
                },
                success: function (json) {
                    $("#connectPassword").val("");
                    if (json.auth === "failed") {
                        // Is actually never returned by Rspamd
                    } else {
                        if (json.read_only) {
                            ui.read_only = true;
                            $("#learning_nav").hide();
                            $("#resetHistory").attr("disabled", true);
                            $("#errors-history").hide();
                        } else {
                            ui.read_only = false;
                            $("#learning_nav").show();
                            $("#resetHistory").removeAttr("disabled", true);
                        }

                        saveCredentials(password);
                        $(dialog).hide();
                        $(backdrop).hide();
                        displayUI();
                    }
                },
                error: function (jqXHR) {
                    ui.alertMessage("alert-modal alert-error", jqXHR.statusText);
                    $("#connectPassword").val("");
                    $("#connectPassword").focus();
                }
            });
        });
    };

    ui.drawPie = function (object, id, data, conf) {
        var obj = object;
        if (obj) {
            obj.updateProp("data.content",
                data.filter(function (elt) {
                    return elt.value > 0;
                })
            );
        } else {
            obj = new d3pie(id,
                $.extend({}, {
                    header: {
                        title: {
                            text: "Rspamd filter stats",
                            fontSize: 24,
                            font: "open sans"
                        },
                        subtitle: {
                            color: "#999999",
                            fontSize: 12,
                            font: "open sans"
                        },
                        titleSubtitlePadding: 9
                    },
                    footer: {
                        color: "#999999",
                        fontSize: 10,
                        font: "open sans",
                        location: "bottom-left"
                    },
                    size: {
                        canvasWidth: 600,
                        canvasHeight: 400,
                        pieInnerRadius: "20%",
                        pieOuterRadius: "85%"
                    },
                    data: {
                        // "sortOrder": "value-desc",
                        content: data.filter(function (elt) {
                            return elt.value > 0;
                        })
                    },
                    labels: {
                        outer: {
                            hideWhenLessThanPercentage: 1,
                            pieDistance: 30
                        },
                        inner: {
                            hideWhenLessThanPercentage: 4
                        },
                        mainLabel: {
                            fontSize: 14
                        },
                        percentage: {
                            color: "#eeeeee",
                            fontSize: 14,
                            decimalPlaces: 0
                        },
                        lines: {
                            enabled: true
                        },
                        truncation: {
                            enabled: true
                        }
                    },
                    tooltips: {
                        enabled: true,
                        type: "placeholder",
                        string: "{label}: {value} ({percentage}%)"
                    },
                    effects: {
                        pullOutSegmentOnClick: {
                            effect: "back",
                            speed: 400,
                            size: 8
                        },
                        load: {
                            effect: "none"
                        }
                    },
                    misc: {
                        gradient: {
                            enabled: true,
                            percentage: 100
                        }
                    }
                }, conf));
        }
        return obj;
    };

    ui.getPassword = getPassword;

    /**
     * @param {string} url - A string containing the URL to which the request is sent
     * @param {Object} [options] - A set of key/value pairs that configure the Ajax request. All settings are optional.
     *
     * @param {Object|string|Array} [options.data] - Data to be sent to the server.
     * @param {Function} [options.error] - A function to be called if the request fails.
     * @param {string} [options.errorMessage] - Text to display in the alert message if the request fails.
     * @param {string} [options.errorOnceId] - A prefix of the alert ID to be added to the session storage. If the
     *     parameter is set, the error for each server will be displayed only once per session.
     * @param {Object} [options.headers] - An object of additional header key/value pairs to send along with requests
     *     using the XMLHttpRequest transport.
     * @param {string} [options.method] - The HTTP method to use for the request.
     * @param {Object} [options.params] - An object of additional jQuery.ajax() settings key/value pairs.
     * @param {string} [options.server] - A server to which send the request.
     * @param {Function} [options.success] - A function to be called if the request succeeds.
     *
     * @returns {undefined}
     */
    ui.query = function (url, options) {
        // Force options to be an object
        var o = options || {};
        Object.keys(o).forEach(function (option) {
            if (["data", "error", "errorMessage", "errorOnceId", "headers", "method", "params", "server", "success"]
                .indexOf(option) < 0) {
                throw new Error("Unknown option: " + option);
            }
        });

        var neighbours_status = [{
            name: "local",
            host: "local",
            url: "",
        }];
        o.server = o.server || checked_server;
        if (o.server === "All SERVERS") {
            queryServer(neighbours_status, 0, "neighbours", {
                success: function (json) {
                    var data = json[0].data;
                    if (jQuery.isEmptyObject(data)) {
                        neighbours = {
                            local:  {
                                host: window.location.host,
                                url: window.location.href
                            }
                        };
                    } else {
                        neighbours = data;
                    }
                    neighbours_status = [];
                    $.each(neighbours, function (ind) {
                        neighbours_status.push({
                            name: ind,
                            host: neighbours[ind].host,
                            url: neighbours[ind].url,
                        });
                    });
                    $.each(neighbours_status, function (ind) {
                        queryServer(neighbours_status, ind, url, o);
                    });
                },
                errorMessage: "Cannot receive neighbours data"
            });
        } else {
            if (o.server !== "local") {
                neighbours_status = [{
                    name: o.server,
                    host:  neighbours[o.server].host,
                    url: neighbours[o.server].url,
                }];
            }
            queryServer(neighbours_status, 0, url, o);
        }
    };

    return ui;
});
