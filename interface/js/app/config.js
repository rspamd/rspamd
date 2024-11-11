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

/* global require */

define(["jquery", "app/common"],
    ($, common) => {
        "use strict";
        const ui = {};

        ui.getActions = function getActions() {
            common.query("actions", {
                success: function (data) {
                    $("#actionsFormField").empty();
                    const items = [];
                    $.each(data[0].data, (i, item) => {
                        const actionsOrder = ["greylist", "add header", "rewrite subject", "reject"];
                        const idx = actionsOrder.indexOf(item.action);
                        if (idx >= 0) {
                            items.push({
                                idx: idx,
                                html:
                                '<div class="form-group">' +
                                    '<label class="col-form-label col-md-2 float-start">' + item.action + "</label>" +
                                    '<div class="controls slider-controls col-md-10">' +
                                        '<input class="action-scores form-control" data-id="action" type="number" value="' +
                                          item.value + '">' +
                                    "</div>" +
                                "</div>"
                            });
                        }
                    });

                    items.sort((a, b) => a.idx - b.idx);

                    $("#actionsFormField").html(
                        items.map((e) => e.html).join(""));
                },
                server: common.getServer()
            });
        };

        ui.saveActions = function (server) {
            function descending(arr) {
                let desc = true;
                const filtered = arr.filter((el) => el !== null);
                for (let i = 0; i < filtered.length - 1; i++) {
                    if (filtered[i + 1] >= filtered[i]) {
                        desc = false;
                        break;
                    }
                }
                return desc;
            }

            const elts = (function () {
                const values = [];
                const inputs = $("#actionsForm :input[data-id=\"action\"]");
                // Rspamd order: [spam, rewrite_subject, probable_spam, greylist]
                values[0] = parseFloat(inputs[3].value);
                values[1] = parseFloat(inputs[2].value);
                values[2] = parseFloat(inputs[1].value);
                values[3] = parseFloat(inputs[0].value);

                return JSON.stringify(values);
            }());
            // String to array for comparison
            const eltsArray = JSON.parse(elts);
            if (eltsArray[0] < 0) {
                common.alertMessage("alert-modal alert-error", "Spam can not be negative");
            } else if (eltsArray[1] < 0) {
                common.alertMessage("alert-modal alert-error", "Rewrite subject can not be negative");
            } else if (eltsArray[2] < 0) {
                common.alertMessage("alert-modal alert-error", "Probable spam can not be negative");
            } else if (eltsArray[3] < 0) {
                common.alertMessage("alert-modal alert-error", "Greylist can not be negative");
            } else if (descending(eltsArray)) {
                common.query("saveactions", {
                    method: "POST",
                    params: {
                        data: elts,
                        dataType: "json"
                    },
                    server: server
                });
            } else {
                common.alertMessage("alert-modal alert-error", "Incorrect order of actions thresholds");
            }
        };

        ui.getMaps = function () {
            const $listmaps = $("#listMaps");
            $listmaps.closest(".card").hide();
            common.query("maps", {
                success: function (json) {
                    const [{data}] = json;
                    $listmaps.empty();
                    $("#modalBody").empty();
                    const $tbody = $("<tbody>");

                    $.each(data, (i, item) => {
                        let $td = '<td><span class="badge text-bg-secondary">Read</span></td>';
                        if (!(item.editable === false || common.read_only)) {
                            $td = $($td).append('&nbsp;<span class="badge text-bg-success">Write</span>');
                        }
                        const $tr = $("<tr>").append($td);

                        const $span = $('<span class="map-link" data-bs-toggle="modal" data-bs-target="#modalDialog">' +
                            item.uri + "</span>").data("item", item);
                        $span.wrap("<td>").parent().appendTo($tr);
                        $("<td>" + item.description + "</td>").appendTo($tr);
                        $tr.appendTo($tbody);
                    });
                    $tbody.appendTo($listmaps);
                    $listmaps.closest(".card").show();
                },
                server: common.getServer()
            });
        };


        let jar = {};
        const editor = {
            advanced: {
                codejar: true,
                elt: "div",
                class: "editor language-clike",
                readonly_attr: {contenteditable: false},
            },
            basic: {
                elt: "textarea",
                class: "form-control map-textarea",
                readonly_attr: {readonly: true},
            }
        };
        let mode = "advanced";

        // Modal form for maps
        $(document).on("click", "[data-bs-toggle=\"modal\"]", function () {
            const item = $(this).data("item");
            common.query("getmap", {
                headers: {
                    Map: item.map
                },
                success: function (data) {
                    // Highlighting a large amount of text is unresponsive
                    mode = (new Blob([data[0].data]).size > 5120) ? "basic" : $("input[name=editorMode]:checked").val();

                    $("<" + editor[mode].elt + ' id="editor" class="' + editor[mode].class + '" data-id="' + item.map +
                        '"></' + editor[mode].elt + ">").appendTo("#modalBody");

                    if (editor[mode].codejar) {
                        require(["codejar", "linenumbers", "prism"], (CodeJar, withLineNumbers, Prism) => {
                            jar = new CodeJar(
                                document.querySelector("#editor"),
                                withLineNumbers((el) => Prism.highlightElement(el))
                            );
                            jar.updateCode(data[0].data);
                        });
                    } else {
                        document.querySelector("#editor").innerHTML = common.escapeHTML(data[0].data);
                    }

                    let icon = "fa-pen-to-square";
                    if (item.editable === false || common.read_only) {
                        $("#editor").attr(editor[mode].readonly_attr);
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
                server: common.getServer()
            });
            return false;
        });
        $("#modalDialog").on("hidden.bs.modal", () => {
            if (editor[mode].codejar) {
                jar.destroy();
                $(".codejar-wrap").remove();
            } else {
                $("#editor").remove();
            }
        });

        $("#saveActionsBtn").on("click", () => {
            ui.saveActions();
        });
        $("#saveActionsClusterBtn").on("click", () => {
            ui.saveActions("All SERVERS");
        });

        function saveMap(server) {
            common.query("savemap", {
                success: function () {
                    common.alertMessage("alert-success", "Map data successfully saved");
                    $("#modalDialog").modal("hide");
                },
                errorMessage: "Save map error",
                method: "POST",
                headers: {
                    Map: $("#editor").data("id"),
                },
                params: {
                    data: editor[mode].codejar ? jar.toString() : $("#editor").val(),
                    dataType: "text",
                },
                server: server
            });
        }
        $("#modalSave").on("click", () => {
            saveMap();
        });
        $("#modalSaveAll").on("click", () => {
            saveMap("All SERVERS");
        });

        return ui;
    });
