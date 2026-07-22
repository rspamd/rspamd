/*
 * Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>
 */

define(["app/common", "app/libft"],
    (common, libft) => {
        "use strict";
        const ui = {};
        const fileSet = {files: null, index: null};
        const lastReqContext = {
            classifiers: {config_id: null, server: null},
            storages: {config_id: null, server: null}
        };
        let scanTextHeaders = {};

        // Smooth-scroll the window to `top` via a requestAnimationFrame tween,
        // as the former jQuery .animate({scrollTop}) did. Unlike the native
        // scrollTo({behavior:"smooth"}), this is not interrupted by the reflows
        // Tabulator triggers while rendering, and — like the rest of the UI's
        // animations (the show/hide slides, the refresh spinner) — does not
        // honour prefers-reduced-motion, preserving the always-smooth scroll.
        function smoothScrollTo(top) {
            const start = window.scrollY;
            const distance = top - start;
            if (!distance) return;
            const duration = 400; // ms; matches the former jQuery default
            let startTime = null;
            function step(now) {
                if (startTime === null) startTime = now;
                const progress = Math.min((now - startTime) / duration, 1);
                // easeInOutQuad, approximating jQuery's default "swing" easing
                const eased = progress < 0.5
                    ? 2 * progress * progress
                    : 1 - ((-2 * progress + 2) ** 2) / 2;
                window.scrollTo(0, start + distance * eased);
                if (progress < 1) requestAnimationFrame(step);
            }
            requestAnimationFrame(step);
        }

        function uploadText(data, url, headers, method = "POST") {
            return new Promise((resolve) => {
                function server() {
                    if (common.getSelector("selSrv") === "All SERVERS" &&
                        common.getSelector("selLearnServers") === "random") {
                        const servers = Array.from(document.getElementById("selSrv").options)
                            .slice(1)
                            .map((o) => o.value);
                        return servers[Math.floor(Math.random() * servers.length)];
                    }
                    return null;
                }

                common.query(url, {
                    data: data,
                    method: method,
                    headers: headers,
                    success: function (json, jqXHR) {
                        common.alertMessage("alert-success", "Data successfully uploaded");
                        if (jqXHR.status !== 200) {
                            common.alertMessage("alert-info", jqXHR.statusText);
                        }
                    },
                    complete: () => resolve(),
                    server: server()
                });
            });
        }

        function enable_disable_scan_btn(disable) {
            const scanBtns = "#scan button:not(#cleanScanHistory, #deleteHashesBtn, #scanOptionsToggle, .tab-columns-btn)";
            const empty = document.getElementById("scanMsgSource").value.trim().length === 0;
            const isDisabled = disable || empty;
            document.querySelectorAll(scanBtns).forEach((btn) => { btn.disabled = isDisabled; });
        }

        function scanText(data) {
            enable_disable_scan_btn(true);
            common.query("checkv2", {
                data: data,
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
                            common.tables.scan.addData(items);
                        } else {
                            libft.initHistoryTable(data, items, "scan", libft.columns_v2("scan"), true,
                                () => {
                                    const {files} = fileSet;
                                    if (files && fileSet.index < files.length - 1) {
                                        common.fileUtils.readFile(files, (result) => {
                                            const {index} = fileSet;
                                            if (index === files.length - 1) {
                                                document.getElementById("scanMsgSource").value = result;
                                                common.fileUtils.setFileInputFiles("#formFile", files, index);
                                            }
                                            scanText(result);
                                        }, ++fileSet.index);
                                    } else {
                                        enable_disable_scan_btn();
                                        const applyBtns = "#cleanScanHistory, #scan .tab-columns-dropdown .btn-dropdown-apply";
                                        document.querySelectorAll(applyBtns).forEach((el) => { el.disabled = false; });
                                        libft.bindFuzzyHashButtons("scan");
                                        const scanResult = document.getElementById("scanResult");
                                        const top = scanResult.getBoundingClientRect().top + window.scrollY;
                                        smoothScrollTo(top);
                                    }
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
                const tbody = document.querySelector("#hashTable tbody");
                tbody.replaceChildren();
                for (const [rule, hashes] of Object.entries(rules)) {
                    const rowspan = hashes.length;
                    hashes.forEach((hash, i) => {
                        const tr = common.el("tr", null);
                        if (i === 0) tr.append(common.el("td", {rowspan, text: rule}));
                        tr.append(common.el("td", {text: hash}));
                        tbody.append(tr);
                    });
                }
                common.show("#hash-card", true);
            }

            common.query("plugins/fuzzy/hashes?flag=" + document.getElementById("fuzzy-flag").value, {
                data: data,
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


        libft.set_page_size("scan", document.getElementById("scan_page_size").value);
        libft.bindHistoryTableEventHandlers("scan", 5);

        document.getElementById("cleanScanHistory").addEventListener("click", (e) => {
            e.preventDefault();
            if (!confirm("Are you sure you want to clean scan history?")) { // eslint-disable-line no-alert
                return;
            }
            libft.destroyTable("scan");
            common.symbols.scan.length = 0;
            document.getElementById("cleanScanHistory").disabled = true;
        });

        enable_disable_scan_btn();

        document.getElementById("scanClean").addEventListener("click", (e) => {
            e.preventDefault();
            enable_disable_scan_btn(true);
            document.getElementById("scanForm").reset();
            smoothScrollTo(0);
        });

        document.querySelectorAll(".card-close-btn").forEach((btn) => {
            btn.addEventListener("click", (e) => {
                common.hide(e.currentTarget.closest(".card"), true);
            });
        });

        function getScanTextHeaders() {
            scanTextHeaders = ["IP", "User", "From", "Rcpt", "Helo", "Hostname"].reduce((o, header) => {
                const {value} = document.getElementById("scan-opt-" + header.toLowerCase());
                if (value !== "") o[header] = value;
                return o;
            }, {});
            if (document.getElementById("scan-opt-pass-all").checked) scanTextHeaders.Pass = "all";
        }

        document.querySelectorAll("[data-upload]").forEach((btn) => {
            btn.addEventListener("click", (e) => {
                e.preventDefault();
                const {upload: source} = e.currentTarget.dataset;
                const data = document.getElementById("scanMsgSource").value;
                if (data.trim().length > 0) {
                    if (source === "checkv2") {
                        getScanTextHeaders();
                        scanText(data);
                    } else if (source === "compute-fuzzy") {
                        getFuzzyHashes(data);
                    } else {
                        const headers = {};
                        const isBayesLearn = source === "learnham" || source === "learnspam" || source === "learnclass";

                        if (isBayesLearn) {
                            const classifier = document.getElementById("classifier").value;
                            if (classifier) headers.classifier = classifier;
                        }

                        if (source === "learnclass") {
                            const bayesClass = document.getElementById("bayes-class").value;
                            if (!bayesClass) {
                                common.alertMessage("alert-danger", "Classifier has no classes configured");
                                return;
                            }
                            headers.class = bayesClass;
                        }

                        if (source === "fuzzyadd") {
                            headers.flag = document.getElementById("fuzzyFlagText").value;
                            headers.weight = document.getElementById("fuzzyWeightText").value;
                        }

                        if (source === "fuzzydel") {
                            headers.flag = document.getElementById("fuzzyFlagText").value;
                        }

                        uploadText(data, source, headers);
                    }
                } else {
                    common.alertMessage("alert-danger", "Message source field cannot be blank");
                }
            });
        });


        function setDelhashButtonsDisabled(disabled = true) {
            ["#deleteHashesBtn", "#clearHashesBtn"].forEach((s) => {
                document.querySelector(s).disabled = disabled;
            });
        }

        /**
         * Parse a textarea (or any input) value into an array of non-empty tokens.
         * Splits on commas, semicolons or any whitespace (space, tab, newline).
         *
         * @param {string} selector - CSS selector for the input element.
         * @returns {string[]} - Trimmed, non-empty tokens.
         */
        function parseHashes(selector) {
            return document.querySelector(selector).value
                .split(/[,\s;]+/)
                .map((t) => t.trim())
                .filter((t) => t.length > 0);
        }

        document.getElementById("fuzzyDelList").addEventListener("input", () => {
            const hasTokens = parseHashes("#fuzzyDelList").length > 0;
            setDelhashButtonsDisabled(!hasTokens);
        });

        document.getElementById("deleteHashesBtn").addEventListener("click", () => {
            document.getElementById("fuzzyDelList").disabled = true;
            setDelhashButtonsDisabled();
            document.querySelector("#deleteHashesBtn .btn-label").textContent = "Deleting…";

            const hashes = parseHashes("#fuzzyDelList");
            const promises = hashes.map((h) => {
                const headers = {
                    flag: document.getElementById("fuzzyFlagText").value,
                    Hash: h
                };
                return uploadText(null, "fuzzydelhash", headers, "GET");
            });

            Promise.all(promises).finally(() => {
                document.getElementById("fuzzyDelList").disabled = false;
                setDelhashButtonsDisabled(false);
                document.querySelector("#deleteHashesBtn .btn-label").textContent = "Delete hashes";
            });
        });

        document.getElementById("clearHashesBtn").addEventListener("click", () => {
            const delList = document.getElementById("fuzzyDelList");
            delList.value = "";
            delList.focus();
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
            const classifierSel = document.getElementById("classifier");
            const classSel = document.getElementById("bayes-class");
            const binaryButtons = document.getElementById("binary-learn-buttons");
            const learnClassBtn = document.getElementById("learn-class-btn");

            const selectedOption = classifierSel.options[classifierSel.selectedIndex];
            const classifierType = selectedOption ? common.data(selectedOption, "type") : null;
            const classes = selectedOption ? common.data(selectedOption, "classes") ?? [] : [];

            if (classifierType === "multi-class") {
                // Multi-class mode: show class dropdown and Learn button
                classSel.replaceChildren();
                if (Array.isArray(classes) && classes.length > 0) {
                    classes.forEach((cls) => {
                        classSel.append(common.el("option", {value: cls, text: cls}));
                    });
                } else {
                    // No classes available - this shouldn't happen with valid config
                    classSel.append(common.el("option", {value: "", text: "No classes available"}));
                }
                classSel.classList.remove("d-none");
                binaryButtons.classList.add("d-none");
                learnClassBtn.classList.remove("d-none");
            } else {
                // Binary mode: show HAM/SPAM buttons
                classSel.classList.add("d-none");
                binaryButtons.classList.remove("d-none");
                learnClassBtn.classList.add("d-none");
            }
        }

        ui.getClassifiers = function () {
            if (!common.read_only) {
                const server = common.getServer();
                const sel = document.getElementById("classifier");
                const hadOptions = sel.children.length > 0; // remember pre-state

                // Skip request only if we already had options populated for this config/server
                if (shouldSkipRequest(server, "classifiers") && hadOptions) return;

                sel.replaceChildren();

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
                        if (!hasMultiClass) sel.append(common.el("option", {value: "", text: "All classifiers"}));

                        classifiers.forEach((cl) => {
                            const badges = [];
                            if (cl.type === "multi-class") badges.push("[multi-class]");
                            if (cl.per_user) badges.push("[per-user]");
                            const label = cl.name + (badges.length ? " " + badges.join(" ") : "");

                            const option = common.el("option", {value: cl.name, text: label});
                            // Store metadata in a WeakMap (not as DOM attributes)
                            common.data(option, "type", cl.type);
                            common.data(option, "per-user", cl.per_user);
                            common.data(option, "classes", cl.classes || []);
                            sel.append(option);
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
                container: (picker) => picker.parentElement,
                includeReadOnly: true,
                requiresWritable: false,
                emptyText: "No fuzzy storages"
            },
            {
                picker: "#fuzzyFlagText-picker",
                input: "#fuzzyFlagText",
                container: (picker) => picker.closest("div.card"),
                includeReadOnly: false,
                requiresWritable: true,
                emptyText: "No writable storages"
            }
        ];

        let fuzzyChangeBound = false;

        function toggleWidgets(showPicker, showInput) {
            fuzzyWidgets.forEach(({picker, input}) => {
                (showPicker ? common.show : common.hide)(picker);
                (showInput ? common.show : common.hide)(input);
            });
        }

        function setWidgetsDisabled(disable, predicate = () => true) {
            fuzzyWidgets.forEach((widget) => {
                if (!predicate(widget)) return;
                const pickerEl = document.querySelector(widget.picker);
                widget.container(pickerEl)?.classList.toggle("disabled", disable);
            });
        }

        ui.getFuzzyStorages = function () {
            const server = common.getServer();
            if (shouldSkipRequest(server, "storages")) return;

            fuzzyWidgets.forEach(({picker, container}) => {
                container(document.querySelector(picker))?.removeAttribute("title");
            });

            common.query("plugins/fuzzy/storages", {
                success: function (data) {
                    const storages = data[0].data.storages || {};
                    const hasWritableStorages = Object.keys(storages).some((name) => !storages[name].read_only);

                    toggleWidgets(true, false);
                    setWidgetsDisabled(!hasWritableStorages, (widget) => widget.requiresWritable);

                    // The change handler just mirrors the picker value into its
                    // paired input; the widgets are static, so bind it once.
                    if (!fuzzyChangeBound) {
                        fuzzyWidgets.forEach(({picker, input}) => {
                            const selEl = document.querySelector(picker);
                            const inputEl = document.querySelector(input);
                            selEl.addEventListener("change", () => { inputEl.value = selEl.value; });
                        });
                        fuzzyChangeBound = true;
                    }

                    fuzzyWidgets.forEach((widget) => {
                        const {picker, input, includeReadOnly, emptyText} = widget;
                        const selEl = document.querySelector(picker);

                        selEl.replaceChildren();

                        const applicableStorages = Object.entries(storages)
                            .filter(([, info]) => includeReadOnly || !info.read_only);

                        applicableStorages.forEach(([name, info]) => {
                            Object.entries(info.flags).forEach(([symbol, val]) => {
                                selEl.append(common.el("option", {value: val, text: `${name}:${symbol} (${val})`}));
                            });
                        });

                        const inputEl = document.querySelector(input);
                        if (selEl.children.length > 0) {
                            inputEl.value = selEl.value;
                        } else {
                            selEl.append(common.el("option", {value: "", text: emptyText}));
                            inputEl.value = "";
                        }
                    });
                },
                error: function (_result, _jqXHR, _textStatus, errorThrown) {
                    if (errorThrown === "fuzzy_check is not enabled") {
                        toggleWidgets(true, false);
                        setWidgetsDisabled(true);

                        fuzzyWidgets.forEach(({picker, container}) => {
                            const pickerEl = document.querySelector(picker);
                            pickerEl.replaceChildren();
                            pickerEl.append(common.el("option", {value: "", text: "fuzzy_check disabled"}));
                            common.show(pickerEl);
                            container(pickerEl)
                                ?.setAttribute("title", "fuzzy_check module is not enabled in server configuration.");
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
        document.getElementById("classifier").addEventListener("change", updateBayesUI);

        return ui;
    });
