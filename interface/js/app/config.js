/*
 The MIT License (MIT)

 Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>

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

define(["jquery"],
    function ($) {
        "use strict";
        var ui = {};

        function loadActionsFromForm() {
            var values = [];
            var inputs = $("#actionsForm :input[data-id=\"action\"]");
            // Rspamd order: [spam, rewrite_subject, probable_spam, greylist]
            values[0] = parseFloat(inputs[3].value);
            values[1] = parseFloat(inputs[2].value);
            values[2] = parseFloat(inputs[1].value);
            values[3] = parseFloat(inputs[0].value);

            return JSON.stringify(values);
        }

        ui.getActions = function getActions(rspamd, checked_server) {
            rspamd.query("actions", {
                success: function (data) {
                    $("#actionsBody").empty();
                    $("#actionsForm").empty();
                    var items = [];
                    $.each(data[0].data, function (i, item) {
                        var idx = -1;
                        var label = null;
                        if (item.action === "greylist") {
                            label = "Greylist";
                            idx = 0;
                        } else if (item.action === "add header") {
                            label = "Probably Spam";
                            idx = 1;
                        } else if (item.action === "rewrite subject") {
                            label = "Rewrite subject";
                            idx = 2;
                        } else if (item.action === "reject") {
                            label = "Spam";
                            idx = 3;
                        }
                        if (idx >= 0) {
                            items.push({
                                idx: idx,
                                html: "<div class=\"form-group\">" +
                                "<label class=\"control-label col-sm-2\">" + label + "</label>" +
                                "<div class=\"controls slider-controls col-sm-10\">" +
                                "<input class=\"action-scores form-control\" data-id=\"action\" type=\"number\" value=\"" + item.value + "\">" +
                                "</div>" +
                                "</div>"
                            });
                        }
                    });

                    items.sort(function (a, b) {
                        return a.idx - b.idx;
                    });

                    $("#actionsBody").html("<form id=\"actionsForm\"><fieldset id=\"actionsFormField\">" +
                    items.map(function (e) {
                        return e.html;
                    }).join("") +
                    "<br><div class=\"form-group\">" +
                    "<div class=\"btn-group\">" +
                    "<button class=\"btn btn-primary\" type=\"button\" id=\"saveActionsBtn\">Save actions</button>" +
                    "<button class=\"btn btn-primary\" type=\"button\" id=\"saveActionsClusterBtn\">Save cluster</button>" +
                    "</div></div></fieldset></form>");
                    if (rspamd.read_only) {
                        $("#saveActionsClusterBtn").attr("disabled", true);
                        $("#saveActionsBtn").attr("disabled", true);
                        $("#actionsFormField").attr("disabled", true);
                    }

                    function saveActions(server) {
                        var elts = loadActionsFromForm();
                        // String to array for comparison
                        var eltsArray = JSON.parse(loadActionsFromForm());
                        if (eltsArray[0] < 0) {
                            rspamd.alertMessage("alert-modal alert-error", "Spam can not be negative");
                        } else if (eltsArray[1] < 0) {
                            rspamd.alertMessage("alert-modal alert-error", "Rewrite subject can not be negative");
                        } else if (eltsArray[2] < 0) {
                            rspamd.alertMessage("alert-modal alert-error", "Probable spam can not be negative");
                        } else if (eltsArray[3] < 0) {
                            rspamd.alertMessage("alert-modal alert-error", "Greylist can not be negative");
                        } else if (
                            (eltsArray[2] === null || eltsArray[3] < eltsArray[2]) &&
                        (eltsArray[1] === null || eltsArray[2] < eltsArray[1]) &&
                        (eltsArray[0] === null || eltsArray[1] < eltsArray[0])
                        ) {
                            rspamd.query("saveactions", {
                                method: "POST",
                                params: {
                                    data: elts,
                                    dataType: "json"
                                },
                                server: server
                            });
                        } else {
                            rspamd.alertMessage("alert-modal alert-error", "Incorrect order of metric actions threshold");
                        }
                    }

                    $("#saveActionsBtn").on("click", function () {
                        saveActions();
                    });
                    $("#saveActionsClusterBtn").on("click", function () {
                        saveActions("All SERVERS");
                    });
                },
                server: (checked_server === "All SERVERS") ? "local" : checked_server
            });
        };

        ui.getMaps = function (rspamd, checked_server) {
            var $listmaps = $("#listMaps");
            $listmaps.closest(".widget-box").hide();
            rspamd.query("maps", {
                success: function (json) {
                    var data = json[0].data;
                    $listmaps.empty();
                    $("#modalBody").empty();
                    var $tbody = $("<tbody>");

                    $.each(data, function (i, item) {
                        var label = (item.editable === false || rspamd.read_only)
                            ? "<span class=\"label label-default\">Read</span>"
                            : "<span class=\"label label-default\">Read</span>&nbsp;<span class=\"label label-success\">Write</span>";
                        var $tr = $("<tr>");
                        $("<td class=\"col-md-2 maps-cell\">" + label + "</td>").appendTo($tr);
                        var $span = $("<span class=\"map-link\" data-toggle=\"modal\" data-target=\"#modalDialog\">" + item.uri + "</span>").data("item", item);
                        $span.wrap("<td>").parent().appendTo($tr);
                        $("<td>" + item.description + "</td>").appendTo($tr);
                        $tr.appendTo($tbody);
                    });
                    $tbody.appendTo($listmaps);
                    $listmaps.closest(".widget-box").show();
                },
                server: (checked_server === "All SERVERS") ? "local" : checked_server
            });
        };

        // @upload edited actions
        ui.setup = function (rspamd) {
        // Modal form for maps
            $(document).on("click", "[data-toggle=\"modal\"]", function () {
                function getSelector(id) {
                    var e = document.getElementById(id);
                    return e.options[e.selectedIndex].value;
                }
                var checked_server = getSelector("selSrv");
                var item = $(this).data("item");
                rspamd.query("getmap", {
                    headers: {
                        Map: item.map
                    },
                    success: function (data) {
                        var disabled = "";
                        var text = data[0].data;
                        if (item.editable === false || rspamd.read_only) {
                            disabled = "disabled=\"disabled\"";
                        }

                        $("#" + item.map).remove();
                        $("<form id=\"" + item.map + "\" class=\"form-horizontal form-map\" style=\"display:none\"" +
                        " data-type=\"map\" action=\"savemap\" method=\"post\">" +
                        "<textarea class=\"list-textarea\"" + disabled + ">" + text +
                        "</textarea>" +
                        "</form>").appendTo("#modalBody");

                        $("#modalTitle").html(item.uri);
                        $("#" + item.map).first().show();
                        $("#modalDialog .progress").hide();
                        $("#modalDialog").modal({backdrop:true, keyboard:"show", show:true});
                        if (item.editable === false) {
                            $("#modalSave").hide();
                            $("#modalSaveAll").hide();
                        } else {
                            $("#modalSave").show();
                            $("#modalSaveAll").show();
                        }
                    },
                    errorMessage: "Cannot receive maps data",
                    server: (checked_server === "All SERVERS") ? "local" : checked_server
                });
                return false;
            });
            // close modal without saving
            $("[data-dismiss=\"modal\"]").on("click", function () {
                $("#modalBody form").hide();
            });
            // @save forms from modal
            function saveMap(server) {
                var form = $("#modalBody").children().filter(":visible");
                var action = $(form).attr("action");
                var id = $(form).attr("id");
                var data = $("#" + id).find("textarea").val();
                rspamd.query(action, {
                    success: function () {
                        rspamd.alertMessage("alert-success", "Map data successfully saved");
                        $("#modalDialog").modal("hide");
                    },
                    errorMessage: "Save map error",
                    method: "POST",
                    headers: {
                        Map: id,
                    },
                    params: {
                        data: data,
                        dataType: "text",
                    },
                    server: server
                });
            }
            $("#modalSave").on("click", function () {
                saveMap();
            });
            $("#modalSaveAll").on("click", function () {
                saveMap("All SERVERS");
            });
        };

        return ui;
    });
