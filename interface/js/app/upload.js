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
            var url;
            if (source === "spam") {
                url = "learnspam";
            } else if (source === "ham") {
                url = "learnham";
            } else if (source === "fuzzy") {
                url = "fuzzyadd";
            } else if (source === "scan") {
                url = "scan";
            }
            $.ajax({
                data: data,
                dataType: "json",
                type: "POST",
                url: url,
                processData: false,
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader("Password", rspamd.getPassword());
                    $.each(headers, function (name, value) {
                        xhr.setRequestHeader(name, value);
                    });
                },
                success: function (data) {
                    cleanTextUpload(source);
                    if (data.success) {
                        rspamd.alertMessage("alert-success", "Data successfully uploaded");
                    }
                },
                error: function (xhr, textStatus, errorThrown) {
                    var errorMsg;

                    try {
                        var json = $.parseJSON(xhr.responseText);
                        errorMsg = $("<a>").text(json.error).html();
                    } catch (err) {
                        errorMsg = $("<a>").text("Error: [" + textStatus + "] " + errorThrown).html();
                    }
                    rspamd.alertMessage("alert-error", errorMsg);
                }
            });
        }
        // @upload text
        function scanText(rspamd, data) {
            var url = "scan";
            var items = [];
            $.ajax({
                data: data,
                dataType: "json",
                type: "POST",
                url: url,
                processData: false,
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader("Password", rspamd.getPassword());
                },
                success: function (input) {
                    var data = input;
                    if (data.action) {
                        rspamd.alertMessage("alert-success", "Data successfully scanned");
                        var action = "";

                        if (data.action === "clean" || "no action") {
                            action = "label-success";
                        }
                        else if (data.action === "rewrite subject" || "add header" || "probable spam") {
                            action = "label-warning";
                        }
                        else if (data.action === "spam") {
                            action = "label-danger";
                        }

                        var score = "";
                        if (data.score <= data.required_score) {
                            score = "label-success";
                        }
                        else if (data.score >= data.required_score) {
                            score = "label-danger";
                        }
                        $("<tbody id=\"tmpBody\"><tr>" +
                            "<td><span class=\"label " + action + "\">" + data.action + "</span></td>" +
                            "<td><span class=\"label " + score + "\">" + data.score.toFixed(2) + "/" + data.required_score.toFixed(2) + "</span></td>" +
                            "</tr></tbody>")
                            .insertAfter("#scanOutput thead");
                        var sym_desc = {};
                        var nsym = 0;

                        $.each(data.symbols, function (i, item) {
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
                error: function (jqXHR, textStatus, errorThrown) {
                    rspamd.alertMessage("alert-error", "Cannot upload data: " +
                    textStatus + ", " + errorThrown);
                },
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
                }
            });
        }

        ui.setup = function (rspamd) {
            $("textarea").change(function () {
                if ($(this).val().length !== "") {
                    $(this).closest("form").find("button").removeAttr("disabled").removeClass("disabled");
                } else {
                    $(this).closest("form").find("button").attr("disabled").addClass("disabled");
                }
            });

            $("#scanClean").on("click", function () {
                $("#scanTextSource").val("");
                $("#scanResult").hide();
                $("#scanOutput tbody").remove();
                $("html, body").animate({scrollTop: 0}, 1000);
                return false;
            });
            // @init upload
            $("[data-upload]").on("click", function () {
                var source = $(this).data("upload");
                var data;
                var headers = {};
                data = $("#" + source + "TextSource").val();
                if (source === "fuzzy") {
                // To access the proper
                    headers.flag = $("#fuzzyFlagText").val();
                    headers.weight = $("#fuzzyWeightText").val();
                } else {
                    data = $("#" + source + "TextSource").val();
                }
                if (data.length > 0) {
                    if (source === "scan") {
                        scanText(rspamd, data);
                    } else {
                        uploadText(rspamd, data, source, headers);
                    }
                }
                return false;
            });
        };


        return ui;
    });
