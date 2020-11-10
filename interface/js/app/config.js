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

define(["jquery", "codejar", "linenumbers", "prism"],
    function ($, CodeJar, withLineNumbers, Prism) {
        "use strict";
        var ui = {};

        ui.getActions = function getActions(rspamd, checked_server) {
            rspamd.query("actions", {
                success: function (data) {
                    $("#actionsFormField").empty();
                    var items = [];
                    $.each(data[0].data, function (i, item) {
                        var actionsOrder = ["greylist", "add header", "rewrite subject", "reject"];
                        var idx = actionsOrder.indexOf(item.action);
                        if (idx >= 0) {
                            items.push({
                                idx: idx,
                                html:
                                '<div class="form-group">' +
                                    '<label class="col-form-label col-md-2 float-left">' + item.action + "</label>" +
                                    '<div class="controls slider-controls col-md-10">' +
                                        '<input class="action-scores form-control" data-id="action" type="number" value="' +
                                          item.value + '">' +
                                    "</div>" +
                                "</div>"
                            });
                        }
                    });

                    items.sort(function (a, b) {
                        return a.idx - b.idx;
                    });

                    $("#actionsFormField").html(
                        items.map(function (e) {
                            return e.html;
                        }).join(""));
                },
                server: (checked_server === "All SERVERS") ? "local" : checked_server
            });
        };

        ui.saveActions = function (rspamd, server) {
            function descending(arr) {
                var desc = true;
                var filtered = arr.filter(function (el) {
                    return el !== null;
                });
                for (var i = 0; i < filtered.length - 1; i++) {
                    if (filtered[i + 1] >= filtered[i]) {
                        desc = false;
                        break;
                    }
                }
                return desc;
            }

            var elts = (function () {
                var values = [];
                var inputs = $("#actionsForm :input[data-id=\"action\"]");
                // Rspamd order: [spam, rewrite_subject, probable_spam, greylist]
                values[0] = parseFloat(inputs[3].value);
                values[1] = parseFloat(inputs[2].value);
                values[2] = parseFloat(inputs[1].value);
                values[3] = parseFloat(inputs[0].value);

                return JSON.stringify(values);
            }());
            // String to array for comparison
            var eltsArray = JSON.parse(elts);
            if (eltsArray[0] < 0) {
                rspamd.alertMessage("alert-modal alert-error", "Spam can not be negative");
            } else if (eltsArray[1] < 0) {
                rspamd.alertMessage("alert-modal alert-error", "Rewrite subject can not be negative");
            } else if (eltsArray[2] < 0) {
                rspamd.alertMessage("alert-modal alert-error", "Probable spam can not be negative");
            } else if (eltsArray[3] < 0) {
                rspamd.alertMessage("alert-modal alert-error", "Greylist can not be negative");
            } else if (descending(eltsArray)) {
                rspamd.query("saveactions", {
                    method: "POST",
                    params: {
                        data: elts,
                        dataType: "json"
                    },
                    server: server
                });
            } else {
                rspamd.alertMessage("alert-modal alert-error", "Incorrect order of actions thresholds");
            }
        };

        ui.getMaps = function (rspamd, checked_server) {
            var $listmaps = $("#listMaps");
            $listmaps.closest(".card").hide();
            rspamd.query("maps", {
                success: function (json) {
                    var data = json[0].data;
                    $listmaps.empty();
                    $("#modalBody").empty();
                    var $tbody = $("<tbody>");

                    $.each(data, function (i, item) {
                        var $td = '<td><span class="badge badge-secondary">Read</span></td>';
                        if (!(item.editable === false || rspamd.read_only)) {
                            $td = $($td).append('&nbsp;<span class="badge badge-success">Write</span>');
                        }
                        var $tr = $("<tr>").append($td);

                        var $span = $('<span class="map-link" data-toggle="modal" data-target="#modalDialog">' + item.uri + "</span>").data("item", item);
                        $span.wrap("<td>").parent().appendTo($tr);
                        $("<td>" + item.description + "</td>").appendTo($tr);
                        $tr.appendTo($tbody);
                    });
                    $tbody.appendTo($listmaps);
                    $listmaps.closest(".card").show();
                },
                server: (checked_server === "All SERVERS") ? "local" : checked_server
            });
        };

        ui.setup = function (rspamd) {
            var jar = {};
            // CodeJar requires ES6
            var editor = window.CodeJar &&
                // Required to restore cursor position
                (typeof window.getSelection().setBaseAndExtent === "function")
                ? {
                    codejar: true,
                    elt: "div",
                    class: "editor language-clike",
                    readonly_attr: {contenteditable: false},
                }
                // Fallback to textarea if the browser does not support ES6
                : {
                    elt: "textarea",
                    class: "form-control map-textarea",
                    readonly_attr: {readonly: true},
                };

            // Modal form for maps
            $(document).on("click", "[data-toggle=\"modal\"]", function () {
                var checked_server = rspamd.getSelector("selSrv");
                var item = $(this).data("item");
                rspamd.query("getmap", {
                    headers: {
                        Map: item.map
                    },
                    success: function (data) {
                        $("<" + editor.elt + ' id="editor" class="' + editor.class + '" data-id="' + item.map + '">' +
                            rspamd.escapeHTML(data[0].data) +
                            "</" + editor.elt + ">").appendTo("#modalBody");

                        if (editor.codejar) {
                            jar = new CodeJar(
                                document.querySelector("#editor"),
                                withLineNumbers(Prism.highlightElement)
                            );
                        }

                        var icon = "fa-edit";
                        if (item.editable === false || rspamd.read_only) {
                            $("#editor").attr(editor.readonly_attr);
                            icon = "fa-eye";
                            $("#modalSaveGroup").hide();
                        } else {
                            $("#modalSaveGroup").show();
                        }
                        $("#modalDialog .modal-header").find("[data-fa-i2svg]").addClass(icon);
                        $("#modalTitle").html(item.uri);

                        $("#modalDialog").modal("show");
                    },
                    errorMessage: "Cannot receive maps data",
                    server: (checked_server === "All SERVERS") ? "local" : checked_server
                });
                return false;
            });
            $("#modalDialog").on("hidden.bs.modal", function () {
                if (editor.codejar) {
                    jar.destroy();
                    $(".codejar-wrap").remove();
                } else {
                    $("#editor").remove();
                }
            });

            $("#saveActionsBtn").on("click", function () {
                ui.saveActions(rspamd);
            });
            $("#saveActionsClusterBtn").on("click", function () {
                ui.saveActions(rspamd, "All SERVERS");
            });

            function saveMap(server) {
                rspamd.query("savemap", {
                    success: function () {
                        rspamd.alertMessage("alert-success", "Map data successfully saved");
                        $("#modalDialog").modal("hide");
                    },
                    errorMessage: "Save map error",
                    method: "POST",
                    headers: {
                        Map: $("#editor").data("id"),
                    },
                    params: {
                        data: editor.codejar ? jar.toString() : $("#editor").val(),
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
