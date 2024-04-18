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

define(["jquery", "app/common", "app/libft"],
    ($, common, libft) => {
        "use strict";
        const ui = {};
        let files = null;
        let filesIdx = null;
        let scanTextHeaders = {};

        function cleanTextUpload(source) {
            $("#" + source + "TextSource").val("");
        }

        function uploadText(data, source, headers) {
            let url = null;
            if (source === "spam") {
                url = "learnspam";
            } else if (source === "ham") {
                url = "learnham";
            } else if (source === "fuzzy") {
                url = "fuzzyadd";
            } else if (source === "scan") {
                url = "checkv2";
            }

            function server() {
                if (common.getSelector("selSrv") === "All SERVERS" &&
                    common.getSelector("selLearnServers") === "random") {
                    const servers = $("#selSrv option").slice(1).map((_, o) => o.value);
                    return servers[Math.floor(Math.random() * servers.length)];
                }
                return null;
            }

            common.query(url, {
                data: data,
                params: {
                    processData: false,
                },
                method: "POST",
                headers: headers,
                success: function (json, jqXHR) {
                    cleanTextUpload(source);
                    common.alertMessage("alert-success", "Data successfully uploaded");
                    if (jqXHR.status !== 200) {
                        common.alertMessage("alert-info", jqXHR.statusText);
                    }
                },
                server: server()
            });
        }

        function enable_disable_scan_btn(disable) {
            $("#scan button:not(#cleanScanHistory, #scanOptionsToggle, .ft-columns-btn)")
                .prop("disabled", (disable || $.trim($("textarea").val()).length === 0));
        }

        function setFileInputFiles(i) {
            const dt = new DataTransfer();
            if (arguments.length) dt.items.add(files[i]);
            $("#formFile").prop("files", dt.files);
        }

        function readFile(callback, i) {
            const reader = new FileReader();
            reader.readAsText(files[(arguments.length === 1) ? 0 : i]);
            reader.onload = () => callback(reader.result);
        }

        function scanText(data) {
            enable_disable_scan_btn(true);
            common.query("checkv2", {
                data: data,
                params: {
                    processData: false,
                },
                method: "POST",
                headers: scanTextHeaders,
                success: function (neighbours_status) {
                    const json = neighbours_status[0].data;
                    if (json.action) {
                        common.alertMessage("alert-success", "Data successfully scanned");

                        const o = libft.process_history_v2({rows: [json]}, "scan");
                        const {items} = o;
                        common.symbols.scan.push(o.symbols[0]);

                        if (files) items[0].file = files[filesIdx].name;

                        if (Object.prototype.hasOwnProperty.call(common.tables, "scan")) {
                            common.tables.scan.rows.load(items, true);
                        } else {
                            require(["footable"], () => {
                                libft.initHistoryTable(data, items, "scan", libft.columns_v2("scan"), true,
                                    () => {
                                        if (files && filesIdx < files.length - 1) {
                                            readFile((result) => {
                                                if (filesIdx === files.length - 1) {
                                                    $("#scanMsgSource").val(result);
                                                    setFileInputFiles(filesIdx);
                                                }
                                                scanText(result);
                                            }, ++filesIdx);
                                        } else {
                                            enable_disable_scan_btn();
                                            $("#cleanScanHistory, #scan .ft-columns-dropdown .btn-dropdown-apply")
                                                .removeAttr("disabled");
                                            $("html, body").animate({
                                                scrollTop: $("#scanResult").offset().top
                                            }, 1000);
                                        }
                                    });
                            });
                        }
                    } else {
                        common.alertMessage("alert-error", "Cannot scan data");
                    }
                },
                error: enable_disable_scan_btn,
                errorMessage: "Cannot upload data",
                statusCode: {
                    404: function () {
                        common.alertMessage("alert-error", "Cannot upload data, no server found");
                    },
                    500: function () {
                        common.alertMessage("alert-error", "Cannot tokenize message: no text data");
                    },
                    503: function () {
                        common.alertMessage("alert-error", "Cannot tokenize message: no text data");
                    }
                },
                server: common.getServer()
            });
        }

        function getFuzzyHashes(data) {
            function fillHashTable(rules) {
                $("#hashTable tbody").empty();
                for (const [rule, hashes] of Object.entries(rules)) {
                    hashes.forEach((hash, i) => {
                        $("#hashTable tbody").append("<tr>" +
                          (i === 0 ? '<td rowspan="' + Object.keys(hashes).length + '">' + rule + "</td>" : "") +
                          "<td>" + hash + "</td></tr>");
                    });
                }
                $("#hash-card").slideDown();
            }

            common.query("plugins/fuzzy/hashes?flag=" + $("#fuzzy-flag").val(), {
                data: data,
                params: {
                    processData: false,
                },
                method: "POST",
                success: function (neighbours_status) {
                    const json = neighbours_status[0].data;
                    if (json.success) {
                        common.alertMessage("alert-success", "Message successfully processed");
                        fillHashTable(json.hashes);
                    } else {
                        common.alertMessage("alert-error", "Unexpected error processing message");
                    }
                },
                server: common.getServer()
            });
        }


        libft.set_page_size("scan", $("#scan_page_size").val());
        libft.bindHistoryTableEventHandlers("scan", 3);

        $("#cleanScanHistory").off("click");
        $("#cleanScanHistory").on("click", (e) => {
            e.preventDefault();
            if (!confirm("Are you sure you want to clean scan history?")) { // eslint-disable-line no-alert
                return;
            }
            libft.destroyTable("scan");
            common.symbols.scan.length = 0;
            $("#cleanScanHistory").attr("disabled", true);
        });

        enable_disable_scan_btn();
        $("textarea").on("input", () => {
            enable_disable_scan_btn();
            if (files) {
                files = null;
                setFileInputFiles();
            }
        });

        $("#scanClean").on("click", () => {
            enable_disable_scan_btn(true);
            $("#scanForm")[0].reset();
            $("html, body").animate({scrollTop: 0}, 1000);
            return false;
        });

        $(".card-close-btn").on("click", function () {
            $(this).closest(".card").slideUp();
        });

        function getScanTextHeaders() {
            scanTextHeaders = ["IP", "User", "From", "Rcpt", "Helo", "Hostname"].reduce((o, header) => {
                const value = $("#scan-opt-" + header.toLowerCase()).val();
                if (value !== "") o[header] = value;
                return o;
            }, {});
            if ($("#scan-opt-pass-all").prop("checked")) scanTextHeaders.Pass = "all";
        }

        $("[data-upload]").on("click", function () {
            const source = $(this).data("upload");
            const data = $("#scanMsgSource").val();
            if ($.trim(data).length > 0) {
                if (source === "scan") {
                    getScanTextHeaders();
                    scanText(data);
                } else if (source === "compute-fuzzy") {
                    getFuzzyHashes(data);
                } else {
                    let headers = {};
                    if (source === "fuzzy") {
                        headers = {
                            flag: $("#fuzzyFlagText").val(),
                            weight: $("#fuzzyWeightText").val()
                        };
                    }
                    uploadText(data, source, headers);
                }
            } else {
                common.alertMessage("alert-error", "Message source field cannot be blank");
            }
            return false;
        });

        function fileInputHandler(obj) {
            ({files} = obj);
            filesIdx = 0;

            if (files.length === 1) {
                setFileInputFiles(0);
                enable_disable_scan_btn();
                readFile((result) => {
                    $("#scanMsgSource").val(result);
                    enable_disable_scan_btn();
                });
            // eslint-disable-next-line no-alert
            } else if (files.length < 10 || confirm("Are you sure you want to scan " + files.length + " files?")) {
                getScanTextHeaders();
                readFile((result) => scanText(result));
            }
        }

        const dragoverClassList = "outline-dashed-primary bg-primary-subtle";
        $("#scanMsgSource")
            .on("dragenter dragover dragleave drop", (e) => {
                e.preventDefault();
                e.stopPropagation();
            })
            .on("dragenter dragover", () => {
                $("#scanMsgSource").addClass(dragoverClassList);
            })
            .on("dragleave drop", () => {
                $("#scanMsgSource").removeClass(dragoverClassList);
            })
            .on("drop", (e) => fileInputHandler(e.originalEvent.dataTransfer));

        $("#formFile").on("change", (e) => fileInputHandler(e.target));

        return ui;
    });
