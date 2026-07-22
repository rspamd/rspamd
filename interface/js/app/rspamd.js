/*
 * Copyright (C) 2012-2013 Anton Simonov <untone@gmail.com>
 * Copyright (C) 2014-2017 Vsevolod Stakhov <vsevolod@highsecure.ru>
 */

/* global require, Visibility */

define(["app/common", "bootstrap", "visibility",
    "fontawesome"],
(common, bootstrap) => {
    "use strict";
    const ui = {};

    const defaultAjaxTimeout = 20000;

    const ajaxTimeoutBox = ".popover #settings-popover #ajax-timeout";
    const graphs = {};
    let checked_server = "All SERVERS";
    const timer_id = [];
    let stickyTabsHandle = null;

    function ajaxSetup(ajax_timeout, setFieldValue, saveToLocalStorage) {
        const timeout = (ajax_timeout && ajax_timeout >= 0) ? ajax_timeout : defaultAjaxTimeout;
        if (saveToLocalStorage) localStorage.setItem("ajax_timeout", timeout);
        if (setFieldValue) document.querySelector(ajaxTimeoutBox).value = timeout;

        common.setAjaxTimeout(timeout);
    }

    function cleanCredentials() {
        sessionStorage.clear();
        document.getElementById("statWidgets").replaceChildren();
        const listMapsTbody = document.querySelector("#listMaps tbody");
        if (listMapsTbody) listMapsTbody.replaceChildren();
        document.getElementById("modalBody").replaceChildren();
    }

    function stopTimers() {
        for (const key in timer_id) {
            if (!{}.hasOwnProperty.call(timer_id, key)) continue;
            Visibility.stop(timer_id[key]);
        }
    }

    // Sticky Tabs: keep the active tab in sync with the URL hash so that the
    // selected tab survives reload and is shareable. Vanilla rewrite of the
    // former jquery.stickytabs plugin; uses the BS5 Tab API directly.
    function initStickyTabs(navSelector, initialTab) {
        const nav = document.querySelector(navSelector);
        function showByHash() {
            const selector = location.hash
                ? `a[href="${location.hash}"]`
                : initialTab;
            const link = selector ? nav.querySelector(selector) : null;
            if (link) bootstrap.Tab.getOrCreateInstance(link).show();
        }

        showByHash();
        window.addEventListener("hashchange", showByHash);

        function onClick(e) {
            const [, hash] = e.currentTarget.href.split("#");
            if (history.pushState) {
                history.pushState(null, "", location.pathname + location.search + "#" + hash);
            }
        }
        nav.querySelectorAll("a").forEach((link) => link.addEventListener("click", onClick));

        return {
            destroy() {
                window.removeEventListener("hashchange", showByHash);
                nav.querySelectorAll("a").forEach((link) => link.removeEventListener("click", onClick));
                nav.querySelectorAll(".nav-link.active").forEach((link) => link.classList.remove("active"));
            }
        };
    }

    function disconnect() {
        [graphs, common.tables].forEach((o) => {
            Object.keys(o).forEach((key) => {
                o[key].destroy();
                delete o[key];
            });
        });

        // Remove sticky-tabs listeners and reset active tab state
        if (stickyTabsHandle) {
            stickyTabsHandle.destroy();
            stickyTabsHandle = null;
        }

        stopTimers();
        cleanCredentials();
        ui.connect();
    }

    // Bootstrap disables non-button nav items (li/a) via the `disabled` attribute
    // + `.disabled` class together; buttons additionally honour the attribute.
    function disableNav(el) {
        el.setAttribute("disabled", "disabled");
        el.classList.add("disabled");
    }
    function enableNav(el) {
        el.removeAttribute("disabled");
        el.classList.remove("disabled");
    }
    // Active dropdown item's numeric data-value (jQuery .data() coerced to number).
    function activeMenuValue(menuClass) {
        const el = document.querySelector(".dropdown-menu a.active." + menuClass);
        return el ? parseInt(el.dataset.value, 10) : null;
    }

    function tabClick(id) {
        let tab_id = id;
        if (document.querySelector(id)?.hasAttribute("disabled")) return;
        let navBarControls = Array.from(document.querySelectorAll("#selSrv, #navBar li, #navBar a, #navBar button"));
        if (id !== "#autoRefresh") navBarControls.forEach(disableNav);

        stopTimers();

        if (id === "#refresh" || id === "#autoRefresh") {
            const active = document.querySelector(".nav-link.active");
            if (active) tab_id = "#" + active.id;
        }

        document.getElementById("autoRefresh").classList.add("invisible");
        document.getElementById("refresh").classList.add("radius-right");

        function setAutoRefresh(refreshInterval, timer, callback) {
            const refreshBtn = document.getElementById("refresh");
            function countdown(interval) {
                Visibility.stop(timer_id.countdown);
                if (!interval) {
                    document.getElementById("countdown").textContent = "--:--";
                    return;
                }

                let timeLeft = interval;
                document.getElementById("countdown").textContent = "00:00";
                timer_id.countdown = Visibility.every(1000, 1000, () => {
                    timeLeft -= 1000;
                    document.getElementById("countdown").textContent = new Date(timeLeft).toISOString().substr(14, 5);
                    if (timeLeft <= 0) Visibility.stop(timer_id.countdown);
                });
            }

            refreshBtn.classList.remove("radius-right");
            document.getElementById("autoRefresh").classList.remove("invisible");

            countdown(refreshInterval);
            if (!refreshInterval) return;
            timer_id[timer] = Visibility.every(refreshInterval, () => {
                countdown(refreshInterval);
                if (refreshBtn.hasAttribute("disabled")) return;
                disableNav(refreshBtn);
                callback();
            });
        }

        if (["#scan_nav", "#selectors_nav", "#disconnect"].indexOf(tab_id) !== -1) {
            document.getElementById("refresh").classList.add("invisible");
        } else {
            document.getElementById("refresh").classList.remove("invisible");
        }

        switch (tab_id) {
            case "#status_nav":
                require(["app/stats"], (module) => {
                    const refreshInterval = activeMenuValue("preset");
                    setAutoRefresh(refreshInterval, "status",
                        () => module.statWidgets(graphs, checked_server));
                    if (id !== "#autoRefresh") module.statWidgets(graphs, checked_server);

                    common.show(".preset");
                    common.hide(".history");
                    common.hide(".dynamic");
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
                    document.getElementById("dynamic-item").textContent = (refreshInterval / 60000) + " min";

                    if (!activeMenuValue("dynamic")) {
                        refreshInterval = null;
                    }
                    setAutoRefresh(refreshInterval, "throughput",
                        () => module.draw(graphs, common.neighbours, checked_server, selData));
                    if (id !== "#autoRefresh") module.draw(graphs, common.neighbours, checked_server, selData);

                    common.hide(".preset");
                    common.hide(".history");
                    common.show(".dynamic");
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
                require(["app/upload"], (module) => {
                    module.getClassifiers();
                    module.getFuzzyStorages();
                });
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
                    const refreshInterval = activeMenuValue("history");
                    setAutoRefresh(refreshInterval, "history",
                        () => getHistoryAndErrors());
                    if (id !== "#autoRefresh") getHistoryAndErrors();

                    common.hide(".preset");
                    common.show(".history");
                    common.hide(".dynamic");

                    module.updateHistoryControlsState();
                });
                break;
            case "#disconnect":
                disconnect();
                break;
            default:
        }

        setTimeout(() => {
            // Do not enable Refresh button until AJAX requests to all neighbours are finished
            if (tab_id === "#history_nav") navBarControls = navBarControls.filter((el) => el.id !== "refresh");

            navBarControls.forEach(enableNav);
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
                const selSrv = document.getElementById("selSrv");
                selSrv.replaceChildren();
                selSrv.append(common.el("option", {value: "All SERVERS", text: "All SERVERS"}));
                neighbours_status.forEach((e) => {
                    const selected = checked_server === e.name;
                    const disabled = !selected && !e.status;
                    selSrv.insertAdjacentHTML("beforeend",
                        '<option value="' + common.escapeHTML(e.name) + '"' +
                        (selected ? " selected" : "") + (disabled ? " disabled" : "") + ">" +
                        common.escapeHTML(e.name) + "</option>");
                });
            },
            complete: function () {
                ajaxSetup(localStorage.getItem("ajax_timeout"));

                if (require.defined("app/upload")) require(["app/upload"], (module) => module.getClassifiers());

                document.querySelectorAll(".ro-disable").forEach((el) => { el.disabled = common.read_only; });
                if (common.read_only) {
                    common.hide(".ro-hide");
                } else {
                    common.show(".ro-hide");
                }

                document.getElementById("preloader").classList.add("d-none");
                document.querySelectorAll("#navBar, #mainUI").forEach((el) => el.classList.remove("d-none"));

                stickyTabsHandle = initStickyTabs(".nav-tabs-sticky", "#status_nav");
            },
            errorMessage: "Cannot get server status",
            server: "All SERVERS"
        });
    }

    // Show the connect (login) dialog and wire its form submission.
    function showConnectDialog() {
        const connectDialog = document.getElementById("connectDialog");
        const connectForm = document.getElementById("connectForm");
        const connectPassword = document.getElementById("connectPassword");

        function clearFeedback() {
            connectPassword.oninput = null;
            connectPassword.classList.remove("is-invalid");
            common.hide("#authInvalidCharFeedback,#authUnauthorizedFeedback");
        }

        connectDialog.addEventListener("show.bs.modal", () => clearFeedback(), {once: true});
        connectDialog.addEventListener("shown.bs.modal", () => connectPassword.focus(), {once: true});
        bootstrap.Modal.getOrCreateInstance(connectDialog).show();

        connectForm.onsubmit = (e) => {
            e.preventDefault();
            const password = connectPassword.value;

            function invalidFeedback(tooltip) {
                connectPassword.classList.add("is-invalid");
                connectPassword.oninput = () => clearFeedback();
                common.show(tooltip);
            }

            if (!(/^[ -~]*$/).test(password)) {
                invalidFeedback("#authInvalidCharFeedback");
                connectPassword.focus();
                return;
            }

            common.query("auth", {
                headers: {
                    Password: password
                },
                success: function (json) {
                    const [{data}] = json;
                    connectPassword.value = "";
                    if (data.auth === "ok") {
                        sessionStorage.setItem("read_only", data.read_only);
                        saveCredentials(password);
                        connectForm.onsubmit = null;
                        bootstrap.Modal.getOrCreateInstance(connectDialog).hide();
                        displayUI();
                    }
                },
                error: function (_result, xhr, textStatus) {
                    if (xhr.statusText === "Unauthorized") {
                        invalidFeedback("#authUnauthorizedFeedback");
                    } else {
                        common.alertMessage("alert-modal alert-danger",
                            textStatus === "timeout" ? "Request timeout" : xhr.statusText);
                    }
                    connectPassword.value = "";
                    connectPassword.focus();
                },
                params: {
                    global: false,
                },
                server: "local"
            });
        };
    }


    // Public functions

    ui.connect = function () {
        // Prevent locking out of the WebUI if timeout is too low.
        let timeout = localStorage.getItem("ajax_timeout");
        if (timeout < defaultAjaxTimeout) timeout = defaultAjaxTimeout;
        ajaxSetup(timeout);

        // Query "/stat" to check if user is already logged in or client ip matches "secure_ip"
        const xhr = new XMLHttpRequest();
        xhr.open("GET", "stat", true);
        const ajaxTimeout = common.getAjaxTimeout();
        if (ajaxTimeout > 0) xhr.timeout = ajaxTimeout;
        xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    const data = JSON.parse(xhr.responseText);
                    sessionStorage.setItem("read_only", data.read_only);
                    displayUI();
                } catch (err) {
                    // A 2xx /stat whose body isn't JSON means a broken response
                    // (truncated by a proxy, a captive-portal page, etc.): show
                    // the login dialog rather than an empty, half-loaded UI.
                    showConnectDialog();
                }
            } else {
                showConnectDialog();
            }
        };
        xhr.onerror = () => showConnectDialog();
        xhr.ontimeout = () => showConnectDialog();
        xhr.send();
    };

    function updateThemeIcon(theme) {
        const icon = document.getElementById("theme-icon");
        icon.classList.remove("fa-moon", "fa-sun", "fa-display");

        const iconMap = {light: "fa-sun", dark: "fa-moon", auto: "fa-display"};
        icon.classList.add(iconMap[theme] || "fa-display");
    }

    // Check the radio within `selector` whose value matches.
    function checkRadio(selector, value) {
        document.querySelectorAll(selector).forEach((radio) => {
            radio.checked = radio.value === value;
        });
    }

    (function initSettings() {
        let selected_locale = null;
        let custom_locale = null;
        const localeTextbox = ".popover #settings-popover #locale";
        const historyCountDef = 1000;
        const historyCountSelector = ".popover #settings-popover #settings-history-count";

        function validateLocale(saveToLocalStorage) {
            const localeInput = document.querySelector(localeTextbox);
            function toggle_form_group_class(remove, add) {
                localeInput.classList.remove("is-" + remove);
                localeInput.classList.add("is-" + add);
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
                localeInput.classList.remove("is-valid", "is-invalid");
            }

            // Display date example
            document.querySelector(".popover #settings-popover #date-example").textContent =
                (common.locale)
                    ? now.toLocaleString(common.locale)
                    : now.toLocaleString();
        }

        const settingsBtn = document.getElementById("settings");
        bootstrap.Popover.getOrCreateInstance(settingsBtn, {
            container: "body",
            placement: "bottom",
            html: true,
            sanitize: false,
            content: function () {
                // Using .clone() has the side-effect of producing elements with duplicate id attributes.
                return document.getElementById("settings-popover").cloneNode(true);
            }
        });
        // Restore the tooltip of the element that the popover is attached to.
        const originalTitle = settingsBtn.getAttribute("data-original-title");
        if (originalTitle !== null) settingsBtn.setAttribute("title", originalTitle);
        settingsBtn.addEventListener("click", (e) => {
            e.preventDefault();
        });
        settingsBtn.addEventListener("inserted.bs.popover", () => {
            selected_locale = localStorage.getItem("selected_locale") || "browser";
            custom_locale = localStorage.getItem("custom_locale") || "";
            validateLocale();

            checkRadio('.popover #settings-popover input[type="radio"][name="locale"]', selected_locale);
            document.querySelector(localeTextbox).value = custom_locale;

            ajaxSetup(localStorage.getItem("ajax_timeout"), true);

            document.querySelector(historyCountSelector).value =
                parseInt(localStorage.getItem("historyCount"), 10) || historyCountDef;

            // Restore theme selection
            const savedTheme = localStorage.getItem("theme") || "auto";
            checkRadio('.popover #settings-popover input[type="radio"][name="theme"]', savedTheme);
        });
        common.delegate(document, "change", '.popover #settings-popover input[type="radio"][name="locale"]',
            (event, target) => {
                selected_locale = target.value;
                localStorage.setItem("selected_locale", selected_locale);
                validateLocale();
            });
        common.delegate(document, "input", localeTextbox, (event, target) => {
            custom_locale = target.value;
            validateLocale(true);
        });
        common.delegate(document, "change", '.popover #settings-popover input[type="radio"][name="theme"]',
            (event, target) => {
                const theme = target.value;
                if (window.rspamd && window.rspamd.theme) {
                    window.rspamd.theme.applyPreference(theme);
                }
                updateThemeIcon(theme || "auto");
            });
        updateThemeIcon(localStorage.getItem("theme") || "auto");
        common.delegate(document, "input", ajaxTimeoutBox, (event, target) => {
            ajaxSetup(target.value, false, true);
        });
        common.delegate(document, "click", ".popover #settings-popover #ajax-timeout-restore", () => {
            ajaxSetup(null, true, true);
        });

        common.delegate(document, "input", historyCountSelector, (event, target) => {
            const v = parseInt(target.value, 10);
            if (v > 0) {
                localStorage.setItem("historyCount", v);
                target.classList.remove("is-invalid");
                const historyCount = document.getElementById("history-count");
                historyCount.value = v;
                historyCount.dispatchEvent(new Event("change", {bubbles: true}));
            } else {
                target.classList.add("is-invalid");
            }
        });
        common.delegate(document, "click", ".popover #settings-popover #settings-history-count-restore",
            () => {
                localStorage.removeItem("historyCount");
                document.querySelector(historyCountSelector).value = historyCountDef;
            });

        // Dismiss Bootstrap popover by clicking outside
        document.body.addEventListener("click", (e) => {
            document.querySelectorAll(".popover").forEach((popover) => {
                const triggerBtn = e.target.closest("button");
                if (popover.contains(e.target) ||
                    (triggerBtn && triggerBtn.getAttribute("aria-describedby") === popover.id)) return;
                bootstrap.Popover.getOrCreateInstance(settingsBtn).hide();
            });
        });
    }());

    document.getElementById("selData").addEventListener("change", () => {
        tabClick("#throughput_nav");
    });

    function refreshSpinStart() {
        document.querySelectorAll("#refresh > svg").forEach((el) => el.classList.add("fa-spin"));
    }
    function refreshSpinStop() {
        setTimeout(() => {
            document.querySelectorAll("#refresh > svg").forEach((el) => el.classList.remove("fa-spin"));
        }, 1000);
    }

    // Drive the refresh spinner from common.query (XHR) requests.
    common.onAjaxStart(refreshSpinStart);
    common.onAjaxComplete(refreshSpinStop);

    document.querySelectorAll('a[data-bs-toggle="tab"]').forEach((link) => {
        link.addEventListener("shown.bs.tab", (e) => {
            tabClick("#" + e.currentTarget.id);
        });
    });
    document.querySelectorAll("#refresh, #disconnect").forEach((btn) => {
        btn.addEventListener("click", (e) => {
            e.preventDefault();
            tabClick("#" + e.currentTarget.id);
        });
    });
    document.querySelectorAll(".dropdown-menu a").forEach((item) => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const match = (/\b(?:dynamic|history|preset)\b/).exec(e.currentTarget.className);
            if (!match) return;
            const [menuClass] = match;
            document.querySelectorAll(".dropdown-menu a.active." + menuClass)
                .forEach((el) => el.classList.remove("active"));
            e.currentTarget.classList.add("active");
            tabClick("#autoRefresh");
        });
    });

    document.getElementById("theme-toggle").addEventListener("click", (e) => {
        e.preventDefault();
        const currentTheme = localStorage.getItem("theme") || "auto";
        // Cycle through: light -> dark -> auto -> light
        const themeMap = {light: "dark", dark: "auto", auto: "light"};
        const newTheme = themeMap[currentTheme] || "light";

        if (window.rspamd && window.rspamd.theme) {
            window.rspamd.theme.applyPreference(newTheme);
        }
        updateThemeIcon(newTheme);

        // Update radio button in settings popover if it's open
        checkRadio('.popover #settings-popover input[type="radio"][name="theme"]', newTheme);
    });

    document.getElementById("selSrv").addEventListener("change", (e) => {
        checked_server = e.currentTarget.value;
        if (checked_server === "All SERVERS") {
            document.getElementById("learnServers").classList.remove("invisible");
        } else {
            document.getElementById("learnServers").classList.add("invisible");
        }
        const active = document.querySelector("#tablist > .nav-item > .nav-link.active");
        if (active) tabClick("#" + active.id);
    });

    // Radio buttons
    common.delegate(document, "click", 'input[type="radio"][name="clusterName"]', (event, target) => {
        if (!target.disabled) {
            checked_server = target.value;
            tabClick("#status_nav");
        }
    });

    document.getElementById("loading").classList.add("d-none");

    return ui;
});
