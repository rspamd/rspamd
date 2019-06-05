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

        function cleanTextUpload(source) {
            $("#" + source + "TextSource").val("");
        }

        // @upload text
        function uploadText(rspamd, data, source, headers) {
            var url = null;
            if (source === "spam") {
                url = "learnspam";
            } else if (source === "ham") {
                url = "learnham";
            } else if (source === "fuzzy") {
                url = "fuzzyadd";
            } else if (source === "scan") {
                url = "scan";
            }
            rspamd.query(url, {
                data: data,
                params: {
                    processData: false,
                },
                method: "POST",
                headers: headers,
                success: function (json, jqXHR) {
                    cleanTextUpload(source);
                    rspamd.alertMessage("alert-success", "Data successfully uploaded");
                    if (jqXHR.status !== 200) {
                        rspamd.alertMessage("alert-info", jqXHR.statusText);
                    }
                }
            });
        }
        // @upload text
        function scanText(rspamd, data, server) {
            var items = [];
            rspamd.query("scan", {
                data: data,
                params: {
                    processData: false,
                },
                method: "POST",
                success: function (neighbours_status) {
                    var json = neighbours_status[0].data;
                    if (json.action) {
                        rspamd.alertMessage("alert-success", "Data successfully scanned");
                        var action = "";

                        if (json.action === "clean" || json.action === "no action") {
                            action = "label-success";
                        } else if (json.action === "rewrite subject" || json.action === "add header" || json.action === "probable spam") {
                            action = "label-warning";
                        } else if (json.action === "spam") {
                            action = "label-danger";
                        }

                        var score = "";
                        if (json.score <= json.required_score) {
                            score = "label-success";
                        } else if (json.score >= json.required_score) {
                            score = "label-danger";
                        }
                        $("<tbody id=\"tmpBody\"><tr>" +
                            "<td><span class=\"label " + action + "\">" + json.action + "</span></td>" +
                            "<td><span class=\"label " + score + "\">" + json.score.toFixed(2) + "/" + json.required_score.toFixed(2) + "</span></td>" +
                            "</tr></tbody>")
                            .insertAfter("#scanOutput thead");
                        var sym_desc = {};
                        var nsym = 0;

                        $.each(json.symbols, function (i, item) {
                            if (typeof item === "object") {
                                var sym_id = "sym_" + nsym;
                                if (item.description) {
                                    sym_desc[sym_id] = item.description;
                                }
                                items.push("<div class=\"cell-overflow\" tabindex=\"1\"><abbr id=\"" + sym_id +
                                "\">" + item.name + "</abbr>: " + item.score.toFixed(2) + "</div>");
                                nsym++;
                            }
                        });
                        $("<td/>", {
                            id: "tmpSymbols",
                            html: items.join("")
                        }).appendTo("#scanResult");
                        $("#tmpSymbols").insertAfter("#tmpBody td:last").removeAttr("id");
                        $("#tmpBody").removeAttr("id");
                        $("#scanResult").show();
                        // Show tooltips
                        $.each(sym_desc, function (k, v) {
                            $("#" + k).tooltip({
                                placement: "bottom",
                                title: v
                            });
                        });
                        $("html, body").animate({
                            scrollTop: $("#scanResult").offset().top
                        }, 1000);
                    } else {
                        rspamd.alertMessage("alert-error", "Cannot scan data");
                    }
                },
                errorMessage: "Cannot upload data",
                statusCode: {
                    404: function () {
                        rspamd.alertMessage("alert-error", "Cannot upload data, no server found");
                    },
                    500: function () {
                        rspamd.alertMessage("alert-error", "Cannot tokenize message: no text data");
                    },
                    503: function () {
                        rspamd.alertMessage("alert-error", "Cannot tokenize message: no text data");
                    }
                },
                server: server
            });
        }

        ui.setup = function (rspamd) {
            function getSelector(id) {
                var e = document.getElementById(id);
                return e.options[e.selectedIndex].value;
            }

            $("#scan button").attr("disabled", true);
            $("textarea").on("input", function () {
                var $this = $(this);
                $("#scan button")
                    .prop("disabled", ($.trim($this.val()).length === 0));
            });
            $("#scanClean").on("click", function () {
                $("#scan button").attr("disabled", true);
                $("#scanMsgSource").val("");
                $("#scanResult").hide();
                $("#scanOutput tbody").remove();
                $("html, body").animate({scrollTop:0}, 1000);
                return false;
            });
            // @init upload
            $("[data-upload]").on("click", function () {
                var source = $(this).data("upload");
                var data = $("#scanMsgSource").val();
                var headers = (source === "fuzzy")
                    ? {
                        flag: $("#fuzzyFlagText").val(),
                        weight: $("#fuzzyWeightText").val()
                    }
                    : {};
                if ($.trim(data).length > 0) {
                    if (source === "scan") {
                        var checked_server = getSelector("selSrv");
                        var server = (checked_server === "All SERVERS") ? "local" : checked_server;
                        scanText(rspamd, data, server);
                    } else {
                        uploadText(rspamd, data, source, headers);
                    }
                } else {
                    rspamd.alertMessage("alert-error", "Message source field cannot be blank");
                }
                return false;
            });
        };


        return ui;
    });
