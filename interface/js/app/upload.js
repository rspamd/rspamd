/*
 * Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>
 */

/* global require */

define(["jquery", "app/common", "app/libft"],
    ($, common, libft) => {
        "use strict";
        const ui = {};
        const fileSet = {files: null, index: null};
        const lastReqContext = {
            classifiers: {config_id: null, server: null},
            storages: {config_id: null, server: null}
        };
        let scanTextHeaders = {};

        function uploadText(data, url, headers, method = "POST") {
            const deferred = new $.Deferred();

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
                method: method,
                headers: headers,
                success: function (json, jqXHR) {
                    common.alertMessage("alert-success", "Data successfully uploaded");
                    if (jqXHR.status !== 200) {
                        common.alertMessage("alert-info", jqXHR.statusText);
                    }
                    deferred.resolve();
                },
                complete: () => deferred.resolve(),
                server: server()
            });

            return deferred.promise();
        }

        function enable_disable_scan_btn(disable) {
            $("#scan button:not(#cleanScanHistory, #deleteHashesBtn, #scanOptionsToggle, .ft-columns-btn)")
                .prop("disabled", (disable || $.trim($("#scanMsgSource").val()).length === 0));
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

                    // Extract fuzzy_hashes from milter headers if available
                    const fuzzyHeader = json.milter?.add_headers?.["X-Rspamd-Fuzzy"];
                    if (fuzzyHeader?.value) {
                        json.fuzzy_hashes = fuzzyHeader.value
                            .split(",")
                            .map((h) => h.trim())
                            .filter((h) => h.length > 0);
                    }

                    if (json.action) {
                        common.alertMessage("alert-success", "Data successfully scanned");

                        const o = libft.process_history_v2({rows: [json]}, "scan");
                        const {items} = o;
                        common.symbols.scan.push(o.symbols[0]);

                        if (fileSet.files) items[0].file = fileSet.files[fileSet.index].name;

                        if (Object.prototype.hasOwnProperty.call(common.tables, "scan")) {
                            common.tables.scan.rows.load(items, true);
                        } else {
                            require(["footable"], () => {
                                libft.initHistoryTable(data, items, "scan", libft.columns_v2("scan"), true,
                                    () => {
                                        const {files} = fileSet;
                                        if (files && fileSet.index < files.length - 1) {
                                            common.fileUtils.readFile(files, (result) => {
                                                const {index} = fileSet;
                                                if (index === files.length - 1) {
                                                    $("#scanMsgSource").val(result);
                                                    common.fileUtils.setFileInputFiles("#formFile", files, index);
                                                }
                                                scanText(result);
                                            }, ++fileSet.index);
                                        } else {
                                            enable_disable_scan_btn();
                                            $("#cleanScanHistory, #scan .ft-columns-dropdown .btn-dropdown-apply")
                                                .removeAttr("disabled");
                                            libft.bindFuzzyHashButtons("scan");
                                            $("html, body").animate({
                                                scrollTop: $("#scanResult").offset().top
                                            }, 1000);
                                        }
                                    });
                            });
                        }
                    } else {
                        common.alertMessage("alert-danger", "Cannot scan data");
                    }
                },
                error: enable_disable_scan_btn,
                errorMessage: "Cannot upload data",
                statusCode: {
                    404: function () {
                        common.logError({
                            server: common.getServer(),
                            endpoint: "checkv2",
                            message: "Cannot upload data, no server found",
                            httpStatus: 404,
                            errorType: "http_error"
                        });
                    },
                    500: function () {
                        common.alertMessage("alert-danger", "Cannot tokenize message: no text data");
                    },
                    503: function () {
                        common.alertMessage("alert-danger", "Cannot tokenize message: no text data");
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
                common.show("#hash-card", true);
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
                        common.alertMessage("alert-danger", "Unexpected error processing message");
                    }
                },
                server: common.getServer()
            });
        }


        libft.set_page_size("scan", $("#scan_page_size").val());
        libft.bindHistoryTableEventHandlers("scan", 5);

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

        $("#scanClean").on("click", () => {
            enable_disable_scan_btn(true);
            $("#scanForm")[0].reset();
            $("html, body").animate({scrollTop: 0}, 1000);
            return false;
        });

        $(".card-close-btn").on("click", function () {
            common.hide($(this).closest(".card"), true);
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
                if (source === "checkv2") {
                    getScanTextHeaders();
                    scanText(data);
                } else if (source === "compute-fuzzy") {
                    getFuzzyHashes(data);
                } else {
                    const headers = {};
                    const isBayesLearn = source === "learnham" || source === "learnspam" || source === "learnclass";

                    if (isBayesLearn) {
                        const classifier = $("#classifier").val();
                        if (classifier) headers.classifier = classifier;
                    }

                    if (source === "learnclass") {
                        const bayesClass = $("#bayes-class").val();
                        if (!bayesClass) {
                            common.alertMessage("alert-danger", "Classifier has no classes configured");
                            return false;
                        }
                        headers.class = bayesClass;
                    }

                    if (source === "fuzzyadd") {
                        headers.flag = $("#fuzzyFlagText").val();
                        headers.weight = $("#fuzzyWeightText").val();
                    }

                    if (source === "fuzzydel") {
                        headers.flag = $("#fuzzyFlagText").val();
                    }

                    uploadText(data, source, headers);
                }
            } else {
                common.alertMessage("alert-danger", "Message source field cannot be blank");
            }
            return false;
        });


        function setDelhashButtonsDisabled(disabled = true) {
            ["#deleteHashesBtn", "#clearHashesBtn"].forEach((s) => $(s).prop("disabled", disabled));
        }

        /**
         * Parse a textarea (or any input) value into an array of non-empty tokens.
         * Splits on commas, semicolons or any whitespace (space, tab, newline).
         *
         * @param {string} selector - jQuery selector for the input element.
         * @returns {string[]} - Trimmed, non-empty tokens.
         */
        function parseHashes(selector) {
            return $(selector).val()
                .split(/[,\s;]+/)
                .map((t) => t.trim())
                .filter((t) => t.length > 0);
        }

        $("#fuzzyDelList").on("input", () => {
            const hasTokens = parseHashes("#fuzzyDelList").length > 0;
            setDelhashButtonsDisabled(!hasTokens);
        });

        $("#deleteHashesBtn").on("click", () => {
            $("#fuzzyDelList").prop("disabled", true);
            setDelhashButtonsDisabled();
            $("#deleteHashesBtn").find(".btn-label").text("Deleting…");

            const hashes = parseHashes("#fuzzyDelList");
            const promises = hashes.map((h) => {
                const headers = {
                    flag: $("#fuzzyFlagText").val(),
                    Hash: h
                };
                return uploadText(null, "fuzzydelhash", headers, "GET");
            });

            $.when.apply($, promises).always(() => {
                $("#fuzzyDelList").prop("disabled", false);
                setDelhashButtonsDisabled(false);
                $("#deleteHashesBtn").find(".btn-label").text("Delete hashes");
            });
        });

        $("#clearHashesBtn").on("click", () => {
            $("#fuzzyDelList").val("").focus();
            setDelhashButtonsDisabled();
        });


        function multiple_files_cb(files) {
            // eslint-disable-next-line no-alert
            if (files.length < 10 || confirm("Are you sure you want to scan " + files.length + " files?")) {
                getScanTextHeaders();
                common.fileUtils.readFile(files, (result) => scanText(result));
            }
        }

        common.fileUtils.setupFileHandling("#scanMsgSource", "#formFile", fileSet, enable_disable_scan_btn, multiple_files_cb);


        /**
         * Returns `true` if we should skip the request as configuration is not changed,
         * otherwise bumps the request context cache and returns `false`.
         *
         * @param {string} server
         *   Name of the currently selected Rspamd neighbour.
         * @param {"classifiers"|"storages"} key
         *   Which endpoint’s cache to check.
         * @returns {boolean}
         */
        function shouldSkipRequest(server, key) {
            const servers = JSON.parse(sessionStorage.getItem("Credentials") || "{}");
            const config_id = servers[server]?.data?.config_id;
            const last = lastReqContext[key];

            if ((config_id && config_id === last.config_id) ||
                (!config_id && server === last.server)) {
                return true;
            }

            lastReqContext[key] = {config_id, server};
            return false;
        }

        // Switch UI mode based on selected classifier type
        function updateBayesUI() {
            const $classifier = $("#classifier");
            const $class = $("#bayes-class");
            const $binaryButtons = $("#binary-learn-buttons");
            const $learnClassBtn = $("#learn-class-btn");

            const selectedOption = $classifier.find("option:selected");
            const classifierType = selectedOption.data("type");
            const classes = selectedOption.data("classes");

            if (classifierType === "multi-class") {
                // Multi-class mode: show class dropdown and Learn button
                $class.empty();
                if (Array.isArray(classes) && classes.length > 0) {
                    classes.forEach((cls) => {
                        $class.append($("<option>", {value: cls, text: cls}));
                    });
                } else {
                    // No classes available - this shouldn't happen with valid config
                    $class.append($("<option>", {value: "", text: "No classes available"}));
                }
                $class.removeClass("d-none");
                $binaryButtons.addClass("d-none");
                $learnClassBtn.removeClass("d-none");
            } else {
                // Binary mode: show HAM/SPAM buttons
                $class.addClass("d-none");
                $binaryButtons.removeClass("d-none");
                $learnClassBtn.addClass("d-none");
            }
        }

        ui.getClassifiers = function () {
            if (!common.read_only) {
                const server = common.getServer();
                const sel = $("#classifier");
                const hadOptions = sel.children().length > 0; // remember pre-state

                // Skip request only if we already had options populated for this config/server
                if (shouldSkipRequest(server, "classifiers") && hadOptions) return;

                sel.empty();

                common.query("bayes/classifiers", {
                    success: function (data) {
                        const response = data[0].data;
                        // eslint-disable-next-line no-useless-assignment
                        let classifiers = [];

                        // Handle both old and new response formats
                        if (Array.isArray(response)) {
                            // Old format: ["classifier1", "classifier2"] - all binary
                            classifiers = response.map((name) => ({
                                name: name,
                                type: "binary",
                                per_user: false,
                                classes: ["spam", "ham"]
                            }));
                        } else if (response?.classifiers) {
                            // New format: {classifiers: [{name, type, per_user, classes}]}
                            ({classifiers} = response);
                        } else {
                            // Unexpected response format
                            common.alertMessage("alert-warning", "Unable to load classifiers list");
                            return;
                        }

                        // Add "All classifiers" only if no multi-class classifiers present
                        const hasMultiClass = classifiers.some((cl) => cl.type === "multi-class");
                        if (!hasMultiClass) sel.append($("<option>", {value: "", text: "All classifiers"}));

                        classifiers.forEach((cl) => {
                            const badges = [];
                            if (cl.type === "multi-class") badges.push("[multi-class]");
                            if (cl.per_user) badges.push("[per-user]");
                            const label = cl.name + (badges.length ? " " + badges.join(" ") : "");

                            const $option = $("<option>", {
                                value: cl.name,
                                text: label
                            });
                            // Store metadata in jQuery data cache (not as DOM attributes)
                            $option.data("type", cl.type);
                            $option.data("per-user", cl.per_user);
                            $option.data("classes", cl.classes || []);
                            sel.append($option);
                        });

                        // Initialize UI state for the first classifier
                        updateBayesUI();
                    },
                    server: server
                });
            }
        };


        const fuzzyWidgets = [
            {
                picker: "#fuzzy-flag-picker",
                input: "#fuzzy-flag",
                container: ($picker) => $picker.parent(),
                includeReadOnly: true,
                requiresWritable: false,
                emptyText: "No fuzzy storages"
            },
            {
                picker: "#fuzzyFlagText-picker",
                input: "#fuzzyFlagText",
                container: ($picker) => $picker.closest("div.card"),
                includeReadOnly: false,
                requiresWritable: true,
                emptyText: "No writable storages"
            }
        ];

        function toggleWidgets(showPicker, showInput) {
            fuzzyWidgets.forEach(({picker, input}) => {
                (showPicker ? common.show : common.hide)(picker);
                (showInput ? common.show : common.hide)(input);
            });
        }

        function setWidgetsDisabled(disable, predicate = () => true) {
            fuzzyWidgets.forEach((widget) => {
                if (!predicate(widget)) return;
                const {picker, container} = widget;
                container($(picker))[disable ? "addClass" : "removeClass"]("disabled");
            });
        }

        ui.getFuzzyStorages = function () {
            const server = common.getServer();
            if (shouldSkipRequest(server, "storages")) return;

            fuzzyWidgets.forEach(({picker, container}) => container($(picker)).removeAttr("title"));

            common.query("plugins/fuzzy/storages", {
                success: function (data) {
                    const storages = data[0].data.storages || {};
                    const hasWritableStorages = Object.keys(storages).some((name) => !storages[name].read_only);

                    toggleWidgets(true, false);
                    setWidgetsDisabled(!hasWritableStorages, (widget) => widget.requiresWritable);

                    fuzzyWidgets.forEach((widget) => {
                        const {picker, input, includeReadOnly, emptyText} = widget;
                        const $sel = $(picker);

                        $sel.empty();

                        const applicableStorages = Object.entries(storages)
                            .filter(([, info]) => includeReadOnly || !info.read_only);

                        applicableStorages.forEach(([name, info]) => {
                            Object.entries(info.flags).forEach(([symbol, val]) => {
                                $sel.append($("<option>", {value: val, text: `${name}:${symbol} (${val})`}));
                            });
                        });

                        if ($sel.children().length > 0) {
                            $(input).val($sel.val());
                            $sel.off("change").on("change", () => $(input).val($sel.val()));
                        } else {
                            $sel.append($("<option>", {value: "", text: emptyText}));
                            $(input).val("");
                            $sel.off("change");
                        }
                    });
                },
                error: function (_result, _jqXHR, _textStatus, errorThrown) {
                    if (errorThrown === "fuzzy_check is not enabled") {
                        toggleWidgets(true, false);
                        setWidgetsDisabled(true);

                        fuzzyWidgets.forEach(({picker, container}) => {
                            const $picker = $(picker);
                            $picker
                                .empty()
                                .append($("<option>", {value: "", text: "fuzzy_check disabled"}));
                            common.show($picker);
                            container($picker)
                                .attr("title", "fuzzy_check module is not enabled in server configuration.");
                        });
                    } else {
                        toggleWidgets(false, true);
                        setWidgetsDisabled(false);
                    }
                },
                server: server
            });
        };

        // Initialize classifier dropdown change handler
        $("#classifier").on("change", updateBayesUI);

        return ui;
    });
