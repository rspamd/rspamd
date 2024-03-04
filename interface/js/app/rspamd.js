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

/* global require, Visibility */

define(["jquery", "app/common", "stickytabs", "visibility",
    "bootstrap", "fontawesome"],
($, common) => {
    "use strict";
    const ui = {};

    const defaultAjaxTimeout = 20000;

    const ajaxTimeoutBox = ".popover #settings-popover #ajax-timeout";
    const graphs = {};
    let checked_server = "All SERVERS";
    const timer_id = [];

    function ajaxSetup(ajax_timeout, setFieldValue, saveToLocalStorage) {
        const timeout = (ajax_timeout && ajax_timeout >= 0) ? ajax_timeout : defaultAjaxTimeout;
        if (saveToLocalStorage) localStorage.setItem("ajax_timeout", timeout);
        if (setFieldValue) $(ajaxTimeoutBox).val(timeout);

        $.ajaxSetup({
            timeout: timeout,
            jsonp: false
        });
    }

    function cleanCredentials() {
        sessionStorage.clear();
        $("#statWidgets").empty();
        $("#listMaps").empty();
        $("#modalBody").empty();
    }

    function stopTimers() {
        for (const key in timer_id) {
            if (!{}.hasOwnProperty.call(timer_id, key)) continue;
            Visibility.stop(timer_id[key]);
        }
    }

    function disconnect() {
        [graphs, common.tables].forEach((o) => {
            Object.keys(o).forEach((key) => {
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
        let tab_id = id;
        if ($(id).attr("disabled")) return;
        let navBarControls = $("#selSrv, #navBar li, #navBar a, #navBar button");
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

                let timeLeft = interval;
                $("#countdown").text("00:00");
                timer_id.countdown = Visibility.every(1000, 1000, () => {
                    timeLeft -= 1000;
                    $("#countdown").text(new Date(timeLeft).toISOString().substr(14, 5));
                    if (timeLeft <= 0) Visibility.stop(timer_id.countdown);
                });
            }

            $("#refresh").removeClass("radius-right");
            $("#autoRefresh").show();

            countdown(refreshInterval);
            if (!refreshInterval) return;
            timer_id[timer] = Visibility.every(refreshInterval, () => {
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
                require(["app/stats"], (module) => {
                    const refreshInterval = $(".dropdown-menu a.active.preset").data("value");
                    setAutoRefresh(refreshInterval, "status",
                        () => module.statWidgets(graphs, checked_server));
                    if (id !== "#autoRefresh") module.statWidgets(graphs, checked_server);

                    $(".preset").show();
                    $(".history").hide();
                    $(".dynamic").hide();
                });
                break;
            case "#throughput_nav":
                require(["app/graph"], (module) => {
                    const selData = common.getSelector("selData"); // Graph's dataset selector state
                    const step = {
                        day: 60000,
                        week: 300000
                    };
                    let refreshInterval = step[selData] || 3600000;
                    $("#dynamic-item").text((refreshInterval / 60000) + " min");

                    if (!$(".dropdown-menu a.active.dynamic").data("value")) {
                        refreshInterval = null;
                    }
                    setAutoRefresh(refreshInterval, "throughput",
                        () => module.draw(graphs, common.neighbours, checked_server, selData));
                    if (id !== "#autoRefresh") module.draw(graphs, common.neighbours, checked_server, selData);

                    $(".preset").hide();
                    $(".history").hide();
                    $(".dynamic").show();
                });
                break;
            case "#configuration_nav":
                require(["app/config"], (module) => {
                    module.getActions();
                    module.getMaps();
                });
                break;
            case "#symbols_nav":
                require(["app/symbols"], (module) => module.getSymbols());
                break;
            case "#scan_nav":
                require(["app/upload"]);
                break;
            case "#selectors_nav":
                require(["app/selectors"], (module) => module.displayUI());
                break;
            case "#history_nav":
                require(["app/history"], (module) => {
                    function getHistoryAndErrors() {
                        module.getHistory();
                        module.getErrors();
                    }
                    const refreshInterval = $(".dropdown-menu a.active.history").data("value");
                    setAutoRefresh(refreshInterval, "history",
                        () => getHistoryAndErrors());
                    if (id !== "#autoRefresh") getHistoryAndErrors();

                    $(".preset").hide();
                    $(".history").show();
                    $(".dynamic").hide();
                });
                break;
            case "#disconnect":
                disconnect();
                break;
            default:
        }

        setTimeout(() => {
            // Do not enable Refresh button until AJAX requests to all neighbours are finished
            if (tab_id === "#history_nav") navBarControls = $(navBarControls).not("#refresh");

            navBarControls.removeAttr("disabled").removeClass("disabled");
        }, (id === "#autoRefresh") ? 0 : 1000);
    }

    function saveCredentials(password) {
        sessionStorage.setItem("Password", password);
    }

    function displayUI() {
        // In many browsers local storage can only store string.
        // So when we store the boolean true or false, it actually stores the strings "true" or "false".
        common.read_only = sessionStorage.getItem("read_only") === "true";

        common.query("auth", {
            success: function (neighbours_status) {
                $("#selSrv").empty();
                $("#selSrv").append($('<option value="All SERVERS">All SERVERS</option>'));
                neighbours_status.forEach((e) => {
                    $("#selSrv").append($('<option value="' + e.name + '">' + e.name + "</option>"));
                    if (checked_server === e.name) {
                        $('#selSrv [value="' + e.name + '"]').prop("selected", true);
                    } else if (!e.status) {
                        $('#selSrv [value="' + e.name + '"]').prop("disabled", true);
                    }
                });
            },
            complete: function () {
                ajaxSetup(localStorage.getItem("ajax_timeout"));

                if (common.read_only) {
                    $(".ro-disable").attr("disabled", true);
                    $(".ro-hide").hide();
                } else {
                    $(".ro-disable").removeAttr("disabled", true);
                    $(".ro-hide").show();
                }

                $("#preloader").addClass("d-none");
                $("#navBar, #mainUI").removeClass("d-none");
                $(".nav-tabs-sticky").stickyTabs({initialTab: "#status_nav"});
            },
            errorMessage: "Cannot get server status",
            server: "All SERVERS"
        });
    }


    // Public functions

    ui.connect = function () {
        // Prevent locking out of the WebUI if timeout is too low.
        let timeout = localStorage.getItem("ajax_timeout");
        if (timeout < defaultAjaxTimeout) timeout = defaultAjaxTimeout;
        ajaxSetup(timeout);

        // Query "/stat" to check if user is already logged in or client ip matches "secure_ip"
        $.ajax({
            type: "GET",
            url: "stat",
            success: function (data) {
                sessionStorage.setItem("read_only", data.read_only);
                displayUI();
            },
            error: function () {
                function clearFeedback() {
                    $("#connectPassword").off("input").removeClass("is-invalid");
                    $("#authInvalidCharFeedback,#authUnauthorizedFeedback").hide();
                }

                $("#connectDialog")
                    .on("show.bs.modal", () => {
                        $("#connectDialog").off("show.bs.modal");
                        clearFeedback();
                    })
                    .on("shown.bs.modal", () => {
                        $("#connectDialog").off("shown.bs.modal");
                        $("#connectPassword").focus();
                    })
                    .modal("show");

                $("#connectForm").off("submit").on("submit", (e) => {
                    e.preventDefault();
                    const password = $("#connectPassword").val();

                    function invalidFeedback(tooltip) {
                        $("#connectPassword")
                            .addClass("is-invalid")
                            .off("input").on("input", () => clearFeedback());
                        $(tooltip).show();
                    }

                    if (!(/^[\u0020-\u007e]*$/).test(password)) {
                        invalidFeedback("#authInvalidCharFeedback");
                        $("#connectPassword").focus();
                        return;
                    }

                    common.query("auth", {
                        headers: {
                            Password: password
                        },
                        success: function (json) {
                            const [{data}] = json;
                            $("#connectPassword").val("");
                            if (data.auth === "ok") {
                                sessionStorage.setItem("read_only", data.read_only);
                                saveCredentials(password);
                                $("#connectForm").off("submit");
                                $("#connectDialog").modal("hide");
                                displayUI();
                            }
                        },
                        error: function (jqXHR, textStatus) {
                            if (textStatus.statusText === "Unauthorized") {
                                invalidFeedback("#authUnauthorizedFeedback");
                            } else {
                                common.alertMessage("alert-modal alert-error", textStatus.statusText);
                            }
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


    (function initSettings() {
        let selected_locale = null;
        let custom_locale = null;
        const localeTextbox = ".popover #settings-popover #locale";

        function validateLocale(saveToLocalStorage) {
            function toggle_form_group_class(remove, add) {
                $(localeTextbox).removeClass("is-" + remove).addClass("is-" + add);
            }

            const now = new Date();

            if (custom_locale.length) {
                try {
                    now.toLocaleString(custom_locale);

                    if (saveToLocalStorage) localStorage.setItem("custom_locale", custom_locale);
                    common.locale = (selected_locale === "custom") ? custom_locale : null;
                    toggle_form_group_class("invalid", "valid");
                } catch (err) {
                    common.locale = null;
                    toggle_form_group_class("valid", "invalid");
                }
            } else {
                if (saveToLocalStorage) localStorage.setItem("custom_locale", null);
                common.locale = null;
                $(localeTextbox).removeClass("is-valid is-invalid");
            }

            // Display date example
            $(".popover #settings-popover #date-example").text(
                (common.locale)
                    ? now.toLocaleString(common.locale)
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
        $("#settings").on("click", (e) => {
            e.preventDefault();
        });
        $("#settings").on("inserted.bs.popover", () => {
            selected_locale = localStorage.getItem("selected_locale") || "browser";
            custom_locale = localStorage.getItem("custom_locale") || "";
            validateLocale();

            $('.popover #settings-popover input:radio[name="locale"]').val([selected_locale]);
            $(localeTextbox).val(custom_locale);

            ajaxSetup(localStorage.getItem("ajax_timeout"), true);
        });
        $(document).on("change", '.popover #settings-popover input:radio[name="locale"]', function () {
            selected_locale = this.value;
            localStorage.setItem("selected_locale", selected_locale);
            validateLocale();
        });
        $(document).on("input", localeTextbox, () => {
            custom_locale = $(localeTextbox).val();
            validateLocale(true);
        });
        $(document).on("input", ajaxTimeoutBox, () => {
            ajaxSetup($(ajaxTimeoutBox).val(), false, true);
        });
        $(document).on("click", ".popover #settings-popover #ajax-timeout-restore", () => {
            ajaxSetup(null, true, true);
        });

        // Dismiss Bootstrap popover by clicking outside
        $("body").on("click", (e) => {
            $(".popover").each(function () {
                if (
                    // Popover's descendant
                    $(this).has(e.target).length ||
                    // Button (or icon within a button) that triggers the popover.
                    $(e.target).closest("button").attr("aria-describedby") === this.id
                ) return;
                $("#settings").popover("hide");
            });
        });
    }());

    $("#selData").change(() => {
        tabClick("#throughput_nav");
    });

    $(document).ajaxStart(() => {
        $("#refresh > svg").addClass("fa-spin");
    });
    $(document).ajaxComplete(() => {
        setTimeout(() => {
            $("#refresh > svg").removeClass("fa-spin");
        }, 1000);
    });

    $('a[data-bs-toggle="tab"]').on("shown.bs.tab", function () {
        tabClick("#" + $(this).attr("id"));
    });
    $("#refresh, #disconnect").on("click", function (e) {
        e.preventDefault();
        tabClick("#" + $(this).attr("id"));
    });
    $(".dropdown-menu a").click(function (e) {
        e.preventDefault();
        const classList = $(this).attr("class");
        const [menuClass] = (/\b(?:dynamic|history|preset)\b/).exec(classList);
        $(".dropdown-menu a.active." + menuClass).removeClass("active");
        $(this).addClass("active");
        tabClick("#autoRefresh");
    });

    $("#selSrv").change(function () {
        checked_server = this.value;
        $("#selSrv [value=\"" + checked_server + "\"]").prop("checked", true);
        if (checked_server === "All SERVERS") {
            $("#learnServers").removeClass("invisible");
        } else {
            $("#learnServers").addClass("invisible");
        }
        tabClick("#" + $("#tablist > .nav-item > .nav-link.active").attr("id"));
    });

    // Radio buttons
    $(document).on("click", "input:radio[name=\"clusterName\"]", function () {
        if (!this.disabled) {
            checked_server = this.value;
            tabClick("#status_nav");
        }
    });

    $("#loading").addClass("d-none");

    return ui;
});
