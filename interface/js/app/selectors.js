define(["jquery"],
    function ($) {
        "use strict";
        var ui = {};

        function enable_disable_check_btn() {
            $("#selectorsChkMsgBtn").prop("disabled", (
                $.trim($("#selectorsMsgArea").val()).length === 0 ||
                !$("#selectorsSelArea").hasClass("is-valid")
            ));
        }

        function get_server(rspamd) {
            var checked_server = rspamd.getSelector("selSrv");
            return (checked_server === "All SERVERS") ? "local" : checked_server;
        }

        function checkMsg(rspamd, data) {
            var selector = $("#selectorsSelArea").val();
            rspamd.query("plugins/selectors/check_message?selector=" + encodeURIComponent(selector), {
                data: data,
                method: "POST",
                success: function (neighbours_status) {
                    var json = neighbours_status[0].data;
                    if (json.success) {
                        rspamd.alertMessage("alert-success", "Message successfully processed");
                        $("#selectorsResArea")
                            .val(Object.prototype.hasOwnProperty.call(json, "data") ? json.data.toString() : "");
                    } else {
                        rspamd.alertMessage("alert-error", "Unexpected error processing message");
                    }
                },
                server: get_server(rspamd)
            });
        }

        function checkSelectors(rspamd) {
            function toggle_form_group_class(remove, add) {
                $("#selectorsSelArea").removeClass("is-" + remove).addClass("is-" + add);
                enable_disable_check_btn();
            }
            var selector = $("#selectorsSelArea").val();
            if (selector.length) {
                rspamd.query("plugins/selectors/check_selector?selector=" + encodeURIComponent(selector), {
                    method: "GET",
                    success: function (json) {
                        if (json[0].data.success) {
                            toggle_form_group_class("invalid", "valid");
                        } else {
                            toggle_form_group_class("valid", "invalid");
                        }
                    },
                    server: get_server(rspamd)
                });
            } else {
                $("#selectorsSelArea").removeClass("is-valid is-invalid");
                enable_disable_check_btn();
            }
        }

        function buildLists(rspamd) {
            function build_table_from_json(json, table_id) {
                Object.keys(json).forEach(function (key) {
                    var td = $("<td/>");
                    var tr = $("<tr/>")
                        .append(td.clone().html("<code>" + key + "</code>"))
                        .append(td.clone().html(json[key].description));
                    $(table_id + " tbody").append(tr);
                });
            }

            function getList(list) {
                rspamd.query("plugins/selectors/list_" + list, {
                    method: "GET",
                    success: function (neighbours_status) {
                        var json = neighbours_status[0].data;
                        build_table_from_json(json, "#selectorsTable-" + list);
                    },
                    server: get_server(rspamd)
                });
            }

            getList("extractors");
            getList("transforms");
        }

        ui.displayUI = function (rspamd) {
            buildLists(rspamd);
            checkSelectors(rspamd);
        };

        ui.setup = function (rspamd) {
            function toggleSidebar(side) {
                $("#sidebar-" + side).toggleClass("collapsed");
                var contentClass = "col-lg-6";
                var openSidebarsCount = $("#sidebar-left").hasClass("collapsed") +
                        $("#sidebar-right").hasClass("collapsed");
                switch (openSidebarsCount) {
                    case 1:
                        contentClass = "col-lg-9";
                        break;
                    case 2:
                        contentClass = "col-lg-12";
                        break;
                    default:
                }
                $("#content").removeClass("col-lg-12 col-lg-9 col-lg-6")
                    .addClass(contentClass);
            }
            $("#sidebar-tab-left>a").click(function () {
                toggleSidebar("left");
                return false;
            });
            $("#sidebar-tab-right>a").click(function () {
                toggleSidebar("right");
                return false;
            });

            $("#selectorsMsgClean").on("click", function () {
                $("#selectorsChkMsgBtn").attr("disabled", true);
                $("#selectorsMsgArea").val("");
                return false;
            });
            $("#selectorsClean").on("click", function () {
                $("#selectorsSelArea").val("");
                checkSelectors(rspamd);
                return false;
            });
            $("#selectorsChkMsgBtn").on("click", function () {
                $("#selectorsResArea").val("");
                checkMsg(rspamd, $("#selectorsMsgArea").val());
                return false;
            });

            $("#selectorsMsgArea").on("input", function () {
                enable_disable_check_btn();
            });
            $("#selectorsSelArea").on("input", function () {
                checkSelectors(rspamd);
            });
        };

        return ui;
    });
