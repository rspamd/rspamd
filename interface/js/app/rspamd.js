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

/* global jQuery:false, FooTable:false, Visibility:false */

define(["jquery", "d3pie", "visibility", "nprogress", "stickytabs", "app/stats", "app/graph", "app/config",
    "app/symbols", "app/history", "app/upload", "app/selectors"],
// eslint-disable-next-line max-params
function ($, D3pie, visibility, NProgress, stickyTabs, tab_stat, tab_graph, tab_config,
    tab_symbols, tab_history, tab_upload, tab_selectors) {
    "use strict";
    var ui = {
        page_size: {
            scan: 25,
            errors: 25,
            history: 25
        },
        symbols: {
            scan: [],
            history: []
        }
    };

    var graphs = {};
    var tables = {};
    var neighbours = []; // list of clusters
    var checked_server = "All SERVERS";
    var timer_id = [];
    var locale = null;
    var selData = null; // Graph's dataset selector state

    NProgress.configure({
        minimum: 0.01,
        showSpinner: false,
    });

    function cleanCredentials() {
        sessionStorage.clear();
        $("#statWidgets").empty();
        $("#listMaps").empty();
        $("#modalBody").empty();
    }

    function stopTimers() {
        for (var key in timer_id) {
            if (!{}.hasOwnProperty.call(timer_id, key)) continue;
            Visibility.stop(timer_id[key]);
        }
    }

    function disconnect() {
        [graphs, tables].forEach(function (o) {
            Object.keys(o).forEach(function (key) {
                o[key].destroy();
                delete o[key];
            });
        });

        // Remove jquery-stickytabs listeners
        $(window).off("hashchange");
        $(".nav-tabs-sticky > .nav-item > .nav-link").off("click").removeClass("active");

        stopTimers();
        cleanCredentials();
        ui.connect();
    }

    function tabClick(id) {
        var tab_id = id;
        if ($(id).attr("disabled")) return;
        var navBarControls = $("#selSrv, #navBar li, #navBar a, #navBar button");
        if (id !== "#autoRefresh") navBarControls.attr("disabled", true).addClass("disabled", true);

        stopTimers();

        if (id === "#refresh" || id === "#autoRefresh") {
            tab_id = "#" + $(".nav-link.active").attr("id");
        }

        $("#autoRefresh").hide();
        $("#refresh").addClass("radius-right");

        function setAutoRefresh(refreshInterval, timer, callback) {
            function countdown(interval) {
                Visibility.stop(timer_id.countdown);
                if (!interval) {
                    $("#countdown").text("--:--");
                    return;
                }

                var timeLeft = interval;
                $("#countdown").text("00:00");
                timer_id.countdown = Visibility.every(1000, 1000, function () {
                    timeLeft -= 1000;
                    $("#countdown").text(new Date(timeLeft).toISOString().substr(14, 5));
                    if (timeLeft <= 0) Visibility.stop(timer_id.countdown);
                });
            }

            $("#refresh").removeClass("radius-right");
            $("#autoRefresh").show();

            countdown(refreshInterval);
            if (!refreshInterval) return;
            timer_id[timer] = Visibility.every(refreshInterval, function () {
                countdown(refreshInterval);
                if ($("#refresh").attr("disabled")) return;
                $("#refresh").attr("disabled", true).addClass("disabled", true);
                callback();
            });
        }

        if (["#scan_nav", "#selectors_nav", "#disconnect"].indexOf(tab_id) !== -1) {
            $("#refresh").hide();
        } else {
            $("#refresh").show();
        }

        switch (tab_id) {
            case "#status_nav":
                (function () {
                    var refreshInterval = $(".dropdown-menu a.active.preset").data("value");
                    setAutoRefresh(refreshInterval, "status",
                        function () { return tab_stat.statWidgets(ui, graphs, checked_server); });
                    if (id !== "#autoRefresh") tab_stat.statWidgets(ui, graphs, checked_server);

                    $(".preset").show();
                    $(".history").hide();
                    $(".dynamic").hide();
                }());
                break;
            case "#throughput_nav":
                (function () {
                    var step = {
                        day: 60000,
                        week: 300000
                    };
                    var refreshInterval = step[selData] || 3600000;
                    $("#dynamic-item").text((refreshInterval / 60000) + " min");

                    if (!$(".dropdown-menu a.active.dynamic").data("value")) {
                        refreshInterval = null;
                    }
                    setAutoRefresh(refreshInterval, "throughput",
                        function () { return tab_graph.draw(ui, graphs, tables, neighbours, checked_server, selData); });
                    if (id !== "#autoRefresh") tab_graph.draw(ui, graphs, tables, neighbours, checked_server, selData);

                    $(".preset").hide();
                    $(".history").hide();
                    $(".dynamic").show();
                }());
                break;
            case "#configuration_nav":
                tab_config.getActions(ui, checked_server);
                tab_config.getMaps(ui, checked_server);
                break;
            case "#symbols_nav":
                tab_symbols.getSymbols(ui, tables, checked_server);
                break;
            case "#history_nav":
                (function () {
                    function getHistoryAndErrors() {
                        tab_history.getHistory(ui, tables);
                        tab_history.getErrors(ui, tables);
                    }
                    var refreshInterval = $(".dropdown-menu a.active.history").data("value");
                    setAutoRefresh(refreshInterval, "history",
                        function () { return getHistoryAndErrors(); });
                    if (id !== "#autoRefresh") getHistoryAndErrors();

                    $(".preset").hide();
                    $(".history").show();
                    $(".dynamic").hide();
                }());
                break;
            case "#disconnect":
                disconnect();
                break;
            default:
        }

        setTimeout(function () {
            // Do not enable Refresh button until AJAX requests to all neighbours are finished
            if (tab_id === "#history_nav") navBarControls = $(navBarControls).not("#refresh");

            navBarControls.removeAttr("disabled").removeClass("disabled");
        }, (id === "#autoRefresh") ? 0 : 1000);
    }

    function getPassword() {
        return sessionStorage.getItem("Password");
    }

    // Get selectors' current state
    function getSelector(id) {
        var e = document.getElementById(id);
        return e.options[e.selectedIndex].value;
    }

    function get_compare_function(table) {
        var compare_functions = {
            magnitude: function (e1, e2) {
                return Math.abs(e2.score) - Math.abs(e1.score);
            },
            name: function (e1, e2) {
                return e1.name.localeCompare(e2.name);
            },
            score: function (e1, e2) {
                return e2.score - e1.score;
            }
        };

        return compare_functions[getSelector("selSymOrder_" + table)];
    }

    function saveCredentials(password) {
        sessionStorage.setItem("Password", password);
    }

    function set_page_size(table, page_size, callback) {
        var n = parseInt(page_size, 10); // HTML Input elements return string representing a number
        if (n !== ui.page_size[table] && n > 0) {
            ui.page_size[table] = n;
            if (callback) {
                return callback(n);
            }
        }
        return null;
    }

    function sort_symbols(o, compare_function) {
        return Object.keys(o)
            .map(function (key) {
                return o[key];
            })
            .sort(compare_function)
            .map(function (e) { return e.str; })
            .join("<br>\n");
    }

    function unix_time_format(tm) {
        var date = new Date(tm ? tm * 1000 : 0);
        return (locale)
            ? date.toLocaleString(locale)
            : date.toLocaleString();
    }

    function displayUI() {
        // In many browsers local storage can only store string.
        // So when we store the boolean true or false, it actually stores the strings "true" or "false".
        ui.read_only = sessionStorage.getItem("read_only") === "true";

        ui.query("auth", {
            success: function (neighbours_status) {
                $("#selSrv").empty();
                $("#selSrv").append($('<option value="All SERVERS">All SERVERS</option>'));
                neighbours_status.forEach(function (e) {
                    $("#selSrv").append($('<option value="' + e.name + '">' + e.name + "</option>"));
                    if (checked_server === e.name) {
                        $('#selSrv [value="' + e.name + '"]').prop("selected", true);
                    } else if (!e.status) {
                        $('#selSrv [value="' + e.name + '"]').prop("disabled", true);
                    }
                });
                if (!ui.read_only) tab_selectors.displayUI(ui);
            },
            complete: function () {
                if (ui.read_only) {
                    $(".ro-disable").attr("disabled", true);
                    $(".ro-hide").hide();
                } else {
                    $(".ro-disable").removeAttr("disabled", true);
                    $(".ro-hide").show();
                }

                $("#preloader").addClass("d-none");
                $("#navBar, #mainUI").removeClass("d-none");
                $(".nav-tabs-sticky").stickyTabs({initialTab:"#status_nav"});
            },
            errorMessage: "Cannot get server status",
            server: "All SERVERS"
        });
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
            headers: $.extend({Password:getPassword()}, o.headers),
            url: neighbours_status[ind].url + req_url,
            xhr: function () {
                var xhr = $.ajaxSettings.xhr();
                // Download progress
                if (req_url !== "neighbours") {
                    xhr.addEventListener("progress", function (e) {
                        if (e.lengthComputable) {
                            neighbours_status[ind].percentComplete = e.loaded / e.total;
                            var percentComplete = neighbours_status.reduce(function (prev, curr) {
                                return curr.percentComplete ? curr.percentComplete + prev : prev;
                            }, 0);
                            NProgress.set(percentComplete / neighbours_status.length);
                        }
                    }, false);
                }
                return xhr;
            },
            success: function (json) {
                neighbours_status[ind].checked = true;
                neighbours_status[ind].status = true;
                neighbours_status[ind].data = json;
            },
            error: function (jqXHR, textStatus, errorThrown) {
                neighbours_status[ind].checked = true;
                function errorMessage() {
                    alertMessage("alert-error", neighbours_status[ind].name + " > " +
                        (o.errorMessage ? o.errorMessage : "Request failed") +
                        (errorThrown ? ": " + errorThrown : ""));
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
            complete: function (jqXHR) {
                if (neighbours_status.every(function (elt) { return elt.checked; })) {
                    if (neighbours_status.some(function (elt) { return elt.status; })) {
                        if (o.success) {
                            o.success(neighbours_status, jqXHR);
                        } else {
                            alertMessage("alert-success", "Request completed");
                        }
                    } else {
                        alertMessage("alert-error", "Request failed");
                    }
                    if (o.complete) o.complete();
                    NProgress.done();
                }
            },
            statusCode: o.statusCode
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
        (function initSettings() {
            var selected_locale = null;
            var custom_locale = null;
            var localeTextbox = ".popover #settings-popover #locale";

            function validateLocale(saveToLocalStorage) {
                function toggle_form_group_class(remove, add) {
                    $(localeTextbox).removeClass("is-" + remove).addClass("is-" + add);
                }

                var now = new Date();

                if (custom_locale.length) {
                    try {
                        now.toLocaleString(custom_locale);

                        if (saveToLocalStorage) localStorage.setItem("custom_locale", custom_locale);
                        locale = (selected_locale === "custom") ? custom_locale : null;
                        toggle_form_group_class("invalid", "valid");
                    } catch (err) {
                        locale = null;
                        toggle_form_group_class("valid", "invalid");
                    }
                } else {
                    if (saveToLocalStorage) localStorage.setItem("custom_locale", null);
                    locale = null;
                    $(localeTextbox).removeClass("is-valid is-invalid");
                }

                // Display date example
                $(".popover #settings-popover #date-example").text(
                    (locale)
                        ? now.toLocaleString(locale)
                        : now.toLocaleString()
                );
            }

            $("#settings").popover({
                container: "body",
                placement: "bottom",
                html: true,
                sanitize: false,
                content: function () {
                    // Using .clone() has the side-effect of producing elements with duplicate id attributes.
                    return $("#settings-popover").clone();
                }
            // Restore the tooltip of the element that the popover is attached to.
            }).attr("title", function () {
                return $(this).attr("data-original-title");
            });
            $("#settings").on("click", function (e) {
                e.preventDefault();
            });
            $("#settings").on("inserted.bs.popover", function () {
                selected_locale = localStorage.getItem("selected_locale") || "browser";
                custom_locale = localStorage.getItem("custom_locale") || "";
                validateLocale();

                $('.popover #settings-popover input:radio[name="locale"]').val([selected_locale]);
                $(localeTextbox).val(custom_locale);
            });
            $(document).on("change", '.popover #settings-popover input:radio[name="locale"]', function () {
                selected_locale = this.value;
                localStorage.setItem("selected_locale", selected_locale);
                validateLocale();
            });
            $(document).on("input", ".popover #settings-popover #locale", function () {
                custom_locale = $(localeTextbox).val();
                validateLocale(true);
            });

            // Dismiss Bootstrap popover by clicking outside
            $("body").on("click", function (e) {
                $(".popover").each(function () {
                    if (
                        // Popover's descendant
                        $(this).has(e.target).length ||
                        // Button (or icon within a button) that triggers the popover.
                        $(e.target).closest("button").attr("aria-describedby") === this.id
                    ) return;
                    $(this).popover("hide");
                });
            });
        }());

        $("#selData").change(function () {
            selData = this.value;
            tabClick("#throughput_nav");
        });
        $.ajaxSetup({
            timeout: 20000,
            jsonp: false
        });

        $(document).ajaxStart(function () {
            $("#refresh > svg").addClass("fa-spin");
        });
        $(document).ajaxComplete(function () {
            setTimeout(function () {
                $("#refresh > svg").removeClass("fa-spin");
            }, 1000);
        });

        $('a[data-toggle="tab"]').on("shown.bs.tab", function () {
            tabClick("#" + $(this).attr("id"));
        });
        $("#refresh, #disconnect").on("click", function (e) {
            e.preventDefault();
            tabClick("#" + $(this).attr("id"));
        });
        $(".dropdown-menu a").click(function (e) {
            e.preventDefault();
            var classList = $(this).attr("class");
            var menuClass = (/\b(?:dynamic|history|preset)\b/).exec(classList)[0];
            $(".dropdown-menu a.active." + menuClass).removeClass("active");
            $(this).addClass("active");
            tabClick("#autoRefresh");
        });

        $("#selSrv").change(function () {
            checked_server = this.value;
            $("#selSrv [value=\"" + checked_server + "\"]").prop("checked", true);
            tabClick("#" + $("#navBar > ul > .nav-item > .nav-link.active").attr("id"));
        });

        // Radio buttons
        $(document).on("click", "input:radio[name=\"clusterName\"]", function () {
            if (!this.disabled) {
                checked_server = this.value;
                tabClick("#status_nav");
            }
        });
        tab_config.setup(ui);
        tab_history.setup(ui, tables);
        tab_selectors.setup(ui);
        tab_symbols.setup(ui, tables);
        tab_upload.setup(ui, tables);
        selData = tab_graph.setup(ui);

        $("#loading").addClass("d-none");
    };

    ui.connect = function () {
        // Query "/stat" to check if user is already logged in or client ip matches "secure_ip"
        $.ajax({
            type: "GET",
            url: "stat",
            success: function () {
                displayUI();
            },
            error: function () {
                $("#connectDialog")
                    .on("shown.bs.modal", function () {
                        $("#connectDialog").off("shown.bs.modal");
                        $("#connectPassword").focus();
                    })
                    .modal("show");

                $("#connectForm").on("submit", function (e) {
                    e.preventDefault();
                    var password = $("#connectPassword").val();
                    if (!(/^[\u0020-\u007e]*$/).test(password)) {
                        alertMessage("alert-modal alert-error", "Invalid characters in the password");
                        $("#connectPassword").focus();
                        return;
                    }

                    ui.query("auth", {
                        headers: {
                            Password: password
                        },
                        success: function (json) {
                            var data = json[0].data;
                            $("#connectPassword").val("");
                            if (data.auth === "ok") {
                                sessionStorage.setItem("read_only", data.read_only);
                                saveCredentials(password);
                                $("#connectForm").off("submit");
                                $("#connectDialog").modal("hide");
                                displayUI();
                            }
                        },
                        error: function (jqXHR) {
                            ui.alertMessage("alert-modal alert-error", jqXHR.statusText);
                            $("#connectPassword").val("");
                            $("#connectPassword").focus();
                        },
                        params: {
                            global: false,
                        },
                        server: "local"
                    });
                });
            }
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
            obj = new D3pie(id,
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
    ui.getSelector = getSelector;

    /**
     * @param {string} url - A string containing the URL to which the request is sent
     * @param {Object} [options] - A set of key/value pairs that configure the Ajax request. All settings are optional.
     *
     * @param {Function} [options.complete] - A function to be called when the requests to all neighbours complete.
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
            if (["complete", "data", "error", "errorMessage", "errorOnceId", "headers", "method", "params", "server", "statusCode",
                "success"]
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
                            local: {
                                host: window.location.host,
                                url: window.location.origin + window.location.pathname
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
                    host: neighbours[o.server].host,
                    url: neighbours[o.server].url,
                }];
            }
            queryServer(neighbours_status, 0, url, o);
        }
    };

    // Scan and History shared functions

    ui.unix_time_format = unix_time_format;
    ui.set_page_size = set_page_size;

    ui.bindHistoryTableEventHandlers = function (table, symbolsCol) {
        function change_symbols_order(order) {
            $(".btn-sym-" + table + "-" + order).addClass("active").siblings().removeClass("active");
            var compare_function = get_compare_function(table);
            $.each(tables[table].rows.all, function (i, row) {
                var cell_val = sort_symbols(ui.symbols[table][i], compare_function);
                row.cells[symbolsCol].val(cell_val, false, true);
            });
        }

        $("#selSymOrder_" + table).unbind().change(function () {
            var order = this.value;
            change_symbols_order(order);
        });
        $("#" + table + "_page_size").change(function () {
            set_page_size(table, this.value, function (n) { tables[table].pageSize(n); });
        });
        $(document).on("click", ".btn-sym-order-" + table + " input", function () {
            var order = this.value;
            $("#selSymOrder_" + table).val(order);
            change_symbols_order(order);
        });
    };

    ui.destroyTable = function (table) {
        if (tables[table]) {
            tables[table].destroy();
            delete tables[table];
        }
    };


    ui.initHistoryTable = function (rspamd, data, items, table, columns, expandFirst) {
        /* eslint-disable consistent-this, no-underscore-dangle, one-var-declaration-per-line */
        FooTable.actionFilter = FooTable.Filtering.extend({
            construct: function (instance) {
                this._super(instance);
                this.actions = ["reject", "add header", "greylist",
                    "no action", "soft reject", "rewrite subject"];
                this.def = "Any action";
                this.$action = null;
            },
            $create: function () {
                this._super();
                var self = this, $form_grp = $("<div/>", {
                    class: "form-group"
                }).append($("<label/>", {
                    class: "sr-only",
                    text: "Action"
                })).prependTo(self.$form);

                self.$action = $("<select/>", {
                    class: "form-control"
                }).on("change", {
                    self: self
                }, self._onStatusDropdownChanged).append(
                    $("<option/>", {
                        text: self.def
                    })).appendTo($form_grp);

                $.each(self.actions, function (i, action) {
                    self.$action.append($("<option/>").text(action));
                });
            },
            _onStatusDropdownChanged: function (e) {
                var self = e.data.self, selected = $(this).val();
                if (selected !== self.def) {
                    if (selected === "reject") {
                        self.addFilter("action", "reject -soft", ["action"]);
                    } else {
                        self.addFilter("action", selected, ["action"]);
                    }
                } else {
                    self.removeFilter("action");
                }
                self.filter();
            },
            draw: function () {
                this._super();
                var action = this.find("action");
                if (action instanceof FooTable.Filter) {
                    if (action.query.val() === "reject -soft") {
                        this.$action.val("reject");
                    } else {
                        this.$action.val(action.query.val());
                    }
                } else {
                    this.$action.val(this.def);
                }
            }
        });
        /* eslint-enable consistent-this, no-underscore-dangle, one-var-declaration-per-line */

        tables[table] = FooTable.init("#historyTable_" + table, {
            columns: columns,
            rows: items,
            expandFirst: expandFirst,
            paging: {
                enabled: true,
                limit: 5,
                size: ui.page_size[table]
            },
            filtering: {
                enabled: true,
                position: "left",
                connectors: false
            },
            sorting: {
                enabled: true
            },
            components: {
                filtering: FooTable.actionFilter
            },
            on: {
                "expand.ft.row": function (e, ft, row) {
                    setTimeout(function () {
                        var detail_row = row.$el.next();
                        var order = getSelector("selSymOrder_" + table);
                        detail_row.find(".btn-sym-" + table + "-" + order)
                            .addClass("active").siblings().removeClass("active");
                    }, 5);
                }
            }
        });
    };

    ui.escapeHTML = function (string) {
        var htmlEscaper = /[&<>"'/`=]/g;
        var htmlEscapes = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            "\"": "&quot;",
            "'": "&#39;",
            "/": "&#x2F;",
            "`": "&#x60;",
            "=": "&#x3D;"
        };
        return String(string).replace(htmlEscaper, function (match) {
            return htmlEscapes[match];
        });
    };

    ui.preprocess_item = function (rspamd, item) {
        function escape_HTML_array(arr) {
            arr.forEach(function (d, i) { arr[i] = ui.escapeHTML(d); });
        }

        for (var prop in item) {
            if (!{}.hasOwnProperty.call(item, prop)) continue;
            switch (prop) {
                case "rcpt_mime":
                case "rcpt_smtp":
                    escape_HTML_array(item[prop]);
                    break;
                case "symbols":
                    Object.keys(item.symbols).forEach(function (key) {
                        var sym = item.symbols[key];
                        if (!sym.name) {
                            sym.name = key;
                        }
                        sym.name = ui.escapeHTML(sym.name);
                        if (sym.description) {
                            sym.description = ui.escapeHTML(sym.description);
                        }

                        if (sym.options) {
                            escape_HTML_array(sym.options);
                        }
                    });
                    break;
                default:
                    if (typeof item[prop] === "string") {
                        item[prop] = ui.escapeHTML(item[prop]);
                    }
            }
        }

        if (item.action === "clean" || item.action === "no action") {
            item.action = "<div style='font-size:11px' class='badge badge-success'>" + item.action + "</div>";
        } else if (item.action === "rewrite subject" || item.action === "add header" || item.action === "probable spam") {
            item.action = "<div style='font-size:11px' class='badge badge-warning'>" + item.action + "</div>";
        } else if (item.action === "spam" || item.action === "reject") {
            item.action = "<div style='font-size:11px' class='badge badge-danger'>" + item.action + "</div>";
        } else {
            item.action = "<div style='font-size:11px' class='badge badge-info'>" + item.action + "</div>";
        }

        var score_content = (item.score < item.required_score)
            ? "<span class='text-success'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>"
            : "<span class='text-danger'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>";

        item.score = {
            options: {
                sortValue: item.score
            },
            value: score_content
        };
    };

    ui.process_history_v2 = function (rspamd, data, table) {
        // Display no more than rcpt_lim recipients
        var rcpt_lim = 3;
        var items = [];
        var unsorted_symbols = [];
        var compare_function = get_compare_function(table);

        $("#selSymOrder_" + table + ", label[for='selSymOrder_" + table + "']").show();

        $.each(data.rows,
            function (i, item) {
                function more(p) {
                    var l = item[p].length;
                    return (l > rcpt_lim) ? " … (" + l + ")" : "";
                }
                function format_rcpt(smtp, mime) {
                    var full = "";
                    var shrt = "";
                    if (smtp) {
                        full = "[" + item.rcpt_smtp.join(", ") + "] ";
                        shrt = "[" + item.rcpt_smtp.slice(0, rcpt_lim).join(",&#8203;") + more("rcpt_smtp") + "]";
                        if (mime) {
                            full += " ";
                            shrt += " ";
                        }
                    }
                    if (mime) {
                        full += item.rcpt_mime.join(", ");
                        shrt += item.rcpt_mime.slice(0, rcpt_lim).join(",&#8203;") + more("rcpt_mime");
                    }
                    return {full:full, shrt:shrt};
                }

                function get_symbol_class(name, score) {
                    if (name.match(/^GREYLIST$/)) {
                        return "symbol-special";
                    }

                    if (score < 0) {
                        return "symbol-negative";
                    } else if (score > 0) {
                        return "symbol-positive";
                    }
                    return null;
                }

                rspamd.preprocess_item(rspamd, item);
                Object.values(item.symbols).forEach(function (sym) {
                    sym.str = '<span class="symbol-default ' + get_symbol_class(sym.name, sym.score) + '"><strong>';

                    if (sym.description) {
                        sym.str += '<abbr title="' + sym.description + '">' + sym.name + "</abbr>";
                    } else {
                        sym.str += sym.name;
                    }
                    sym.str += "</strong> (" + sym.score + ")</span>";

                    if (sym.options) {
                        sym.str += " [" + sym.options.join(",") + "]";
                    }
                });
                unsorted_symbols.push(item.symbols);
                item.symbols = sort_symbols(item.symbols, compare_function);
                if (table === "scan") {
                    item.unix_time = (new Date()).getTime() / 1000;
                }
                item.time = {
                    value: unix_time_format(item.unix_time),
                    options: {
                        sortValue: item.unix_time
                    }
                };
                item.time_real = item.time_real.toFixed(3);
                item.id = item["message-id"];

                if (table === "history") {
                    var rcpt = {};
                    if (!item.rcpt_mime.length) {
                        rcpt = format_rcpt(true, false);
                    } else if ($(item.rcpt_mime).not(item.rcpt_smtp).length !== 0 || $(item.rcpt_smtp).not(item.rcpt_mime).length !== 0) {
                        rcpt = format_rcpt(true, true);
                    } else {
                        rcpt = format_rcpt(false, true);
                    }
                    item.rcpt_mime_short = rcpt.shrt;
                    item.rcpt_mime = rcpt.full;

                    if (item.sender_mime !== item.sender_smtp) {
                        item.sender_mime = "[" + item.sender_smtp + "] " + item.sender_mime;
                    }
                }
                items.push(item);
            });

        return {items:items, symbols:unsorted_symbols};
    };

    ui.waitForRowsDisplayed = function (table, rows_total, callback, iteration) {
        var i = (typeof iteration === "undefined") ? 10 : iteration;
        var num_rows = $("#historyTable_" + table + " > tbody > tr:not(.footable-detail-row)").length;
        if (num_rows === ui.page_size[table] ||
            num_rows === rows_total) {
            return callback();
        } else if (--i) {
            setTimeout(function () {
                ui.waitForRowsDisplayed(table, rows_total, callback, i);
            }, 500);
        }
        return null;
    };

    return ui;
});
