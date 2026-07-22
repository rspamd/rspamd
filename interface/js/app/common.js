define(["nprogress"],
    (NProgress) => {
        "use strict";
        const ui = {
            breakpoints: {
                xs: 0,
                sm: 576,
                md: 768,
                lg: 992,
                xl: 1200,
                xxl: 1400
            },
            chartLegend: [
                {label: "reject", color: "#FF0000"},
                {label: "soft reject", color: "#BF8040"},
                {label: "rewrite subject", color: "#FF6600"},
                {label: "add header", color: "#FFAD00"},
                {label: "greylist", color: "#436EEE"},
                {label: "no action", color: "#66CC00"}
            ],
            locale: (localStorage.getItem("selected_locale") === "custom") ? localStorage.getItem("custom_locale") : null,
            neighbours: [],
            page_size: {
                scan: 25,
                errors: 25,
                history: 25
            },
            symbols: {
                scan: [],
                history: []
            },
            tables: {}
        };


        NProgress.configure({
            minimum: 0.01,
            showSpinner: false,
        });

        // --- AJAX plumbing (replaces $.ajaxSetup + $(document).ajaxStart/Complete) ---

        let ajaxTimeout = 0; // milliseconds; 0 disables the per-request timeout
        let activeAjaxCount = 0;
        const ajaxStartCallbacks = [];
        const ajaxCompleteCallbacks = [];

        // Mirrors jQuery's global ajax events: ajaxStart fires only on the first
        // outstanding request (0 -> 1); ajaxComplete fires once per completed
        // request. Requests with params.global === false are invisible to both.
        function fireAjaxStart() {
            if (activeAjaxCount === 0) {
                ajaxStartCallbacks.forEach((cb) => cb());
            }
            activeAjaxCount++;
        }

        function fireAjaxComplete() {
            activeAjaxCount = Math.max(0, activeAjaxCount - 1);
            ajaxCompleteCallbacks.forEach((cb) => cb());
        }

        ui.setAjaxTimeout = function (ms) {
            ajaxTimeout = ms;
        };

        // Read by callers that issue direct XHRs (outside common.query) and need
        // to honour the configured AJAX timeout.
        ui.getAjaxTimeout = function () {
            return ajaxTimeout;
        };

        ui.onAjaxStart = function (callback) {
            ajaxStartCallbacks.push(callback);
        };

        ui.onAjaxComplete = function (callback) {
            ajaxCompleteCallbacks.push(callback);
        };

        // --- Shared vanilla DOM helpers ---

        // True for null/undefined without the `undefined` literal (no-undefined)
        // or == null (eqeqeq / no-eq-null).
        function isNil(value) {
            return value === null || typeof value === "undefined";
        }

        // Resolve a string selector, Element, NodeList, Array, or jQuery wrapper
        // into a plain Array of Element. Accepts jQuery objects during the staged
        // removal so callers still passing $(...) keep working.
        function toElements(selector) {
            if (!selector) return [];
            if (typeof selector === "string") {
                return Array.from(document.querySelectorAll(selector));
            }
            // A single Element node — including <select>/<form>, which expose a
            // numeric .length — must not be mistaken for a collection.
            if (selector.nodeType === 1) return [selector];
            if (typeof selector.length === "number") {
                return Array.from(selector).filter(Boolean);
            }
            return [selector];
        }

        /**
         * Create an element, apply attributes/properties/listeners, and append
         * children. Recognised attrs keys: class, text, html, dataset, any DOM
         * property, any attribute, and event names (click, change, input, ...)
         * given as functions. Replaces the $("<tag>", {...}) idiom.
         */
        ui.el = function (tag, attrs, ...children) {
            const node = document.createElement(tag);
            if (attrs) {
                for (const [key, value] of Object.entries(attrs)) {
                    if (isNil(value)) continue;
                    switch (key) {
                        case "class": node.className = value; break;
                        case "text": node.textContent = value; break;
                        case "html": node.innerHTML = value; break;
                        case "dataset": Object.assign(node.dataset, value); break;
                        default:
                            if (typeof value === "function") {
                                node.addEventListener(key, value);
                            } else if (key in node) {
                                node[key] = value;
                            } else {
                                node.setAttribute(key, value);
                            }
                    }
                }
            }
            for (const child of children) {
                if (isNil(child)) continue;
                node.append(child);
            }
            return node;
        };

        /**
         * Event delegation: bind a single listener on `root` that invokes `fn`
         * for the closest ancestor of the event target matching `selector`.
         * `this` and the second argument are set to the matched element.
         * Returns a cleanup function. Replaces $(root).on(type, selector, fn).
         */
        ui.delegate = function (root, type, selector, fn) {
            const rootEl = (typeof root === "string") ? document.querySelector(root) : root;
            function handler(event) {
                const target = event.target.closest(selector);
                if (target && rootEl.contains(target)) {
                    fn.call(target, event, target);
                }
            }
            rootEl.addEventListener(type, handler);
            return function () {
                rootEl.removeEventListener(type, handler);
            };
        };

        // WeakMap-backed data store for values that cannot live in dataset
        // (objects, arrays). Mirrors jQuery's .data() get/set for the few call
        // sites that store non-string values.
        const dataStore = new WeakMap();
        ui.data = function (el, key, value) {
            const node = (typeof el === "string") ? document.querySelector(el) : el;
            if (!node) return null;
            if (!dataStore.has(node)) dataStore.set(node, {});
            const store = dataStore.get(node);
            if (arguments.length >= 3) {
                store[key] = value;
                return node;
            }
            return store[key];
        };

        function getPassword() {
            return sessionStorage.getItem("Password");
        }

        function alertMessage(alertClass, alertText) {
            const a = document.createElement("div");
            a.className = "alert " + alertClass + " alert-dismissible fade in show";
            a.innerHTML = "<button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"alert\" title=\"Dismiss\"></button>" +
                "<strong>" + alertText + "</strong>";
            document.querySelector(".notification-area").append(a);

            // Fade out, then collapse the height so siblings slide up, then remove.
            setTimeout(() => {
                a.animate(
                    [{opacity: 1}, {opacity: 0}],
                    {duration: 500, fill: "forwards"}
                ).onfinish = () => {
                    a.style.overflow = "hidden";
                    a.animate(
                        [{height: a.offsetHeight + "px"}, {height: 0}],
                        {duration: 500, easing: "ease", fill: "forwards"}
                    ).onfinish = () => {
                        a.remove();
                    };
                };
            }, 5000);
        }

        // Forward declare updateErrorBadge to resolve circular dependency
        // This function is called by errorLog methods but uses errorLog data
        // Safe due to hoisting: function is called AFTER errorLog initialization
        function updateErrorBadge() {
            const unseenCount = errorLog.getUnseenCount(); // eslint-disable-line no-use-before-define
            const totalCount = errorLog.errors.length; // eslint-disable-line no-use-before-define
            const badge = document.getElementById("error-log-badge");
            const counter = document.getElementById("error-count");

            // Show badge if there are any errors
            if (totalCount > 0) {
                badge.classList.remove("d-none");
                // Show counter only if there are unseen errors
                if (unseenCount > 0) {
                    counter.classList.remove("d-none");
                    counter.textContent = unseenCount;
                } else {
                    counter.classList.add("d-none");
                }
            } else {
                badge.classList.add("d-none");
            }
        }

        // Error log storage
        const errorLog = {
            errors: [],
            maxSize: 50,
            lastViewedIndex: -1, // Track last viewed error for "unseen" counter

            add(entry) {
                this.errors.push({
                    timestamp: new Date(),
                    server: entry.server ?? "Unknown",
                    endpoint: entry.endpoint ?? "",
                    message: entry.message ?? "Unknown error",
                    httpStatus: entry.httpStatus ?? null,
                    errorType: entry.errorType ?? "unknown"
                });

                // Keep last 50 errors
                if (this.errors.length > this.maxSize) {
                    this.errors.shift();
                    // Adjust lastViewedIndex after shift
                    if (this.lastViewedIndex >= 0) {
                        this.lastViewedIndex--;
                    }
                }

                updateErrorBadge();
            },

            clear() {
                this.errors = [];
                this.lastViewedIndex = -1;
                updateErrorBadge();
            },

            getAll() {
                return this.errors;
            },

            markAsViewed() {
                // Mark all current errors as viewed
                this.lastViewedIndex = this.errors.length - 1;
                updateErrorBadge();
            },

            getUnseenCount() {
                // Return count of errors added since last view
                return Math.max(0, this.errors.length - this.lastViewedIndex - 1);
            }
        };

        function updateErrorLogTable() {
            const table = document.getElementById("errorLogTable");
            const tbody = table.querySelector("tbody");
            const noErrors = document.getElementById("noErrorsMessage");
            const copyBtn = document.getElementById("copyErrorLog");
            const clearBtn = document.getElementById("clearErrorLog");

            tbody.replaceChildren();

            const hasErrors = errorLog.errors.length > 0;

            if (!hasErrors) {
                table.style.display = "none";
                noErrors.style.display = "";
                copyBtn.disabled = true;
                clearBtn.disabled = true;
                return;
            }

            table.style.display = "";
            noErrors.style.display = "none";
            copyBtn.disabled = false;
            clearBtn.disabled = false;

            // Show errors in reverse chronological order (newest first)
            errorLog.errors.slice().reverse().forEach((err) => {
                const time = ui.locale
                    ? err.timestamp.toLocaleString(ui.locale)
                    : err.timestamp.toLocaleString();
                const status = err.httpStatus ?? "-";
                const row = document.createElement("tr");

                // Map error types to Bootstrap badge colors
                const errorTypeColors = {
                    auth: "text-bg-danger",
                    network: "text-bg-primary",
                    timeout: "text-bg-info",
                    http_error: "text-bg-warning",
                    data_inconsistency: "text-bg-secondary"
                };
                const badgeClass = errorTypeColors[err.errorType] || "text-bg-secondary";

                // Column order: Time | Error | Server | Endpoint | HTTP Status | Type
                row.append(ui.el("td", {class: "text-nowrap", text: time}));
                row.append(ui.el("td", {text: err.message}));
                row.append(ui.el("td", {class: "d-none d-sm-table-cell", text: err.server}));
                row.append(ui.el("td", {class: "d-none d-md-table-cell"},
                    ui.el("code", {class: "small", text: err.endpoint})));
                row.append(ui.el("td", {class: "d-none d-lg-table-cell text-center", text: status}));
                row.append(ui.el("td", {class: "d-none d-lg-table-cell"},
                    ui.el("span", {class: "badge " + badgeClass, text: err.errorType})));
                tbody.append(row);
            });
        }

        /**
         * Log error and optionally show alert message
         *
         * @param {Object} options - Error details
         * @param {string} options.server - Server name or "Multi-server" for cluster-wide issues
         * @param {string} [options.endpoint=""] - API endpoint or empty string
         * @param {string} options.message - Error message
         * @param {number} [options.httpStatus=null] - HTTP status code or null
         * @param {string} options.errorType - Error type: timeout|auth|http_error|network|data_inconsistency
         * @param {boolean} [options.showAlert=true] - Whether to show alert message
         */
        function logError({httpStatus, endpoint, errorType, message, server, showAlert}) {
            errorLog.add({httpStatus, endpoint, errorType, message, server});

            if (showAlert !== false) {
                const fullMessage = (server !== "Multi-server")
                    ? server + " > " + message
                    : message;
                alertMessage("alert-danger", fullMessage);
            }
        }

        /**
         * Perform a request to a single Rspamd neighbour server over XHR.
         *
         * @param {Array.<Object>} neighbours_status
         *   Array of neighbour status objects.
         * @param {number} ind
         *   Index of this neighbour in the `neighbours_status` array.
         * @param {string} req_url
         *   Relative controller endpoint with optional query string.
         * @param {Object} o
         *   The same `options` object passed into `ui.query`.
         *
         * @returns {void}
         */
        // Callers pre-stringify JSON bodies, so we never form-encode (jQuery's
        // $.param). Normalise any stray object to a JSON string.
        function normalizeRequestBody(rawBody) {
            const isFormData = (typeof FormData !== "undefined") && (rawBody instanceof FormData);
            if (!isNil(rawBody) && typeof rawBody === "object" && !isFormData) {
                return {body: JSON.stringify(rawBody), isFormData};
            }
            return {body: rawBody, isFormData};
        }

        function hasContentType(headers) {
            return ("Content-Type" in headers) || ("content-type" in headers);
        }

        // jQuery appends object data to the URL as a query string for GET/HEAD
        // requests. Pre-encoded strings are returned unchanged. Only flat
        // string/number values are supported (no arrays or nested objects);
        // no current caller needs more — extend it if that changes.
        function buildQueryString(data) {
            if (typeof data === "string") return data;
            if (!isNil(data) && typeof data === "object") {
                return Object.entries(data)
                    .map(([key, value]) => encodeURIComponent(key) + "=" + encodeURIComponent(value))
                    .join("&");
            }
            return "";
        }

        function queryServer(neighbours_status, ind, req_url, o) {
            neighbours_status[ind].checked = false;
            neighbours_status[ind].data = {};
            neighbours_status[ind].status = false;

            const params = o.params || {};
            const isGlobal = params.global !== false;
            const method = (params.method || o.method || "GET").toUpperCase();
            const timeout = (typeof params.timeout === "number") ? params.timeout : ajaxTimeout;
            const {dataType} = params;
            const headers = {Password: getPassword(), ...(o.headers || {})};
            const url = neighbours_status[ind].url + req_url;
            const rawBody = !isNil(params.data) ? params.data : o.data;
            const isGet = method === "GET" || method === "HEAD";
            const queryString = isGet ? buildQueryString(rawBody) : "";
            const separator = url.indexOf("?") === -1 ? "?" : "&";
            const requestUrl = url + (queryString ? separator + queryString : "");

            // jQuery appends data to the URL for GET/HEAD and sends it as the
            // body otherwise.
            let body = null;
            let isFormData = false;
            if (!isGet) {
                ({body, isFormData} = normalizeRequestBody(rawBody));
            }

            const xhr = new XMLHttpRequest();
            xhr.open(method, requestUrl, true);

            Object.keys(headers).forEach((name) => xhr.setRequestHeader(name, headers[name]));

            // jQuery's default Content-Type for non-FormData bodies. FormData is
            // sent untouched so the browser sets the multipart boundary.
            if (!isFormData && !isNil(body) && body !== "" && !hasContentType(headers)) {
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            }

            if (timeout > 0) xhr.timeout = timeout;

            // Download progress -> NProgress (skip the neighbours probe, as before)
            if (req_url !== "neighbours") {
                xhr.addEventListener("progress", (e) => {
                    if (e.lengthComputable) {
                        neighbours_status[ind].percentComplete = e.loaded / e.total;
                        const percentComplete = neighbours_status
                            .reduce((prev, curr) => (curr.percentComplete ? curr.percentComplete + prev : prev), 0);
                        NProgress.set(percentComplete / neighbours_status.length);
                    }
                }, false);
            }

            function parseBody() {
                if (dataType === "text") return xhr.responseText;
                if (dataType === "json") return xhr.responseText ? JSON.parse(xhr.responseText) : null;
                const contentType = xhr.getResponseHeader("Content-Type") || "";
                if (contentType.indexOf("application/json") === 0 ||
                    contentType.indexOf("text/javascript") === 0) {
                    return xhr.responseText ? JSON.parse(xhr.responseText) : null;
                }
                return xhr.responseText;
            }

            // jQuery fires statusCode handlers once per request for the final
            // status, in addition to success/error. Unlike jQuery, which passed
            // (jqXHR, textStatus, errorThrown), the handler here is invoked as
            // (responseText, statusText, xhr).
            function runStatusCode() {
                if (o.statusCode && typeof o.statusCode[xhr.status] === "function") {
                    o.statusCode[xhr.status](xhr.responseText, xhr.statusText, xhr);
                }
            }

            function finish() {
                runStatusCode();
                if (neighbours_status.every((elt) => elt.checked)) {
                    if (neighbours_status.some((elt) => elt.status)) {
                        if (o.success) {
                            o.success(neighbours_status, xhr);
                        } else {
                            alertMessage("alert-success", "Request completed");
                        }
                    } else {
                        alertMessage("alert-danger", "Request failed");
                    }
                    if (o.complete) o.complete();
                    NProgress.done();
                }
                // Decrement after the success/complete callbacks (matching
                // jQuery): a fan-out started inside success must bump the
                // counter before this request's decrement, otherwise the
                // in-flight count dips to 0 between the neighbours probe and
                // the per-neighbour queries, re-firing ajaxStart and restarting
                // the refresh spinner's animation mid-flight.
                if (isGlobal) fireAjaxComplete();
            }

            function handleError(textStatus, errorThrown) {
                neighbours_status[ind].checked = true;

                // Determine error type and create detailed message
                let errorType = "network";
                let detailedMessage = errorThrown || "Request failed";

                if (textStatus === "timeout") {
                    errorType = "timeout";
                    detailedMessage = "Request timeout";
                } else if (xhr.status === 401 || xhr.status === 403) {
                    errorType = "auth";
                    detailedMessage = "Authentication failed";
                } else if (xhr.status >= 400 && xhr.status < 600) {
                    errorType = "http_error";
                    detailedMessage = "HTTP " + xhr.status + (errorThrown ? ": " + errorThrown : "");
                } else if (textStatus === "error" && xhr.status === 0) {
                    errorType = "network";
                    detailedMessage = "Network error";
                }

                // Log error and show alert
                const shouldShowAlert = !o.error &&
                    !(o.errorOnceId && (o.errorOnceId + neighbours_status[ind].name) in sessionStorage);
                if (o.errorOnceId && shouldShowAlert) {
                    sessionStorage.setItem(o.errorOnceId + neighbours_status[ind].name, true);
                }
                logError({
                    server: neighbours_status[ind].name,
                    endpoint: req_url,
                    message: o.errorMessage ? o.errorMessage + ": " + detailedMessage : detailedMessage,
                    httpStatus: xhr.status,
                    errorType: errorType,
                    showAlert: shouldShowAlert
                });

                // Call custom error handler if provided
                if (o.error) o.error(neighbours_status[ind], xhr, textStatus, errorThrown);
                finish();
            }

            xhr.onload = function () {
                const ok = xhr.status >= 200 && xhr.status < 300;
                if (!ok) {
                    handleError("error", xhr.statusText);
                    return;
                }
                try {
                    neighbours_status[ind].data = parseBody();
                } catch (err) {
                    handleError("parsererror", err && err.message ? err.message : "Parse error");
                    return;
                }
                neighbours_status[ind].checked = true;
                neighbours_status[ind].status = true;
                finish();
            };
            xhr.onerror = function () {
                handleError("error", "");
            };
            xhr.ontimeout = function () {
                handleError("timeout", "timeout");
            };
            xhr.onabort = function () {
                handleError("abort", "abort");
            };

            if (isGlobal) fireAjaxStart();
            xhr.send(!isNil(body) ? body : null);
        }


        // Public functions

        ui.alertMessage = alertMessage;
        ui.getPassword = getPassword;
        ui.logError = logError;

        // Get selectors' current state
        ui.getSelector = function (id) {
            const e = document.getElementById(id);
            return e.options[e.selectedIndex].value;
        };

        ui.getServer = function () {
            const checked_server = ui.getSelector("selSrv");
            return (checked_server === "All SERVERS") ? "local" : checked_server;
        };

        /**
         * Perform an HTTP request to one or all Rspamd neighbours.
         *
         * @param {string} url
         *   Relative URL, including with optional query string (e.g. "plugins/selectors/check_selector?selector=from").
         * @param {Object} [options]
         *   Request configuration options.
         * @param {Object|string|Array} [options.data]
         *   Request body for POST endpoints. Callers must pre-stringify JSON;
         *   FormData is sent untouched.
         * @param {Object} [options.headers]
         *   Additional HTTP headers.
         * @param {"GET"|"POST"} [options.method]
         *   HTTP method (defaults to "GET").
         * @param {string} [options.server]
         *   Name or base-URL of the target server (defaults to the currently selected Rspamd neighbour).
         * @param {Object} [options.params]
         *   Extra request settings: global, timeout, dataType ("json"|"text"),
         *   statusCode, etc.
         * @param {string} [options.errorMessage]
         *   Text to show inside a Bootstrap alert on generic errors (e.g. network failure).
         * @param {string} [options.errorOnceId]
         *   Prefix for an alert ID stored in session storage to ensure
         *   `errorMessage` is shown only once per server each session.
         * @param {function(Array.<Object>, Object)} [options.success]
         *   Called on HTTP success. Receives:
         *     1. results: Array of per-server status objects:
         *        {
         *          name: string,
         *          host: string,
         *          url: string,           // full URL base for this neighbour
         *          checked: boolean,      // whether this server was attempted
         *          status: boolean,       // HTTP success (<400)
         *          data: any,             // parsed JSON or raw text
         *          percentComplete: number
         *        }
         *     2. xhr: XMLHttpRequest (jqXHR-compatible: status, statusText,
         *        responseText, readyState).
         * @param {function(Object, Object, string, string)} [options.error]
         *   Called on HTTP error or network failure. Receives:
         *     1. result: a per-server status object (status:false, data:{}).
         *     2. xhr: XMLHttpRequest (status, statusText, responseText).
         *     3. textStatus: "error" | "timeout" | "abort" | "parsererror".
         *     4. errorThrown: HTTP statusText or exception message.
         * @param {function()} [options.complete]
         *   Called once all servers have been tried; takes no arguments.
         *
         * @returns {void}
         */
        ui.query = function (url, options) {
            // Force options to be an object
            const o = options || {};
            Object.keys(o).forEach((option) => {
                if (["complete", "data", "error", "errorMessage", "errorOnceId", "headers", "method", "params", "server",
                    "statusCode", "success"]
                    .indexOf(option) < 0) {
                    throw new Error("Unknown option: " + option);
                }
            });

            let neighbours_status = [{
                name: "local",
                host: "local",
                url: "",
            }];
            o.server = o.server || ui.getSelector("selSrv");
            if (o.server === "All SERVERS") {
                queryServer(neighbours_status, 0, "neighbours", {
                    success: function (json) {
                        const [{data}] = json;
                        if (!data || Object.keys(data).length === 0) {
                            ui.neighbours = {
                                local: {
                                    host: window.location.host,
                                    url: window.location.origin + window.location.pathname
                                }
                            };
                        } else {
                            ui.neighbours = data;
                        }
                        neighbours_status = Object.keys(ui.neighbours).map((name) => ({
                            name: name,
                            host: ui.neighbours[name].host,
                            url: ui.neighbours[name].url,
                        }));
                        for (let ind = 0; ind < neighbours_status.length; ind++) {
                            queryServer(neighbours_status, ind, url, o);
                        }
                    },
                    errorMessage: "Cannot receive neighbours data"
                });
            } else {
                if (o.server !== "local") {
                    neighbours_status = [{
                        name: o.server,
                        host: ui.neighbours[o.server].host,
                        url: ui.neighbours[o.server].url,
                    }];
                }
                queryServer(neighbours_status, 0, url, o);
            }
        };

        ui.escapeHTML = function (string) {
            const htmlEscaper = /[&<>"'/`=]/g;
            const htmlEscapes = {
                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                "\"": "&quot;",
                "'": "&#39;",
                "/": "&#x2F;",
                "`": "&#x60;",
                "=": "&#x3D;"
            };
            return String(string).replace(htmlEscaper, (match) => htmlEscapes[match]);
        };

        /**
         * Hide one or more elements using Bootstrap's d-none class
         * @param {string|Element|NodeList|Array} selector - CSS selector or element(s)
         * @param {boolean} anim - Whether to animate (slide up)
         */
        ui.hide = function (selector, anim = false) {
            for (const el of toElements(selector)) {
                if (anim) {
                    const height = el.offsetHeight;
                    el.style.overflow = "hidden";
                    const fx = el.animate(
                        [{height: height + "px"}, {height: 0}],
                        {duration: 400, easing: "ease", fill: "forwards"}
                    );
                    fx.onfinish = () => {
                        el.classList.add("d-none");
                        el.style.height = "";
                        el.style.overflow = "";
                        fx.cancel();
                    };
                } else {
                    el.classList.add("d-none");
                }
            }
        };

        /**
         * Show one or more elements using Bootstrap's d-none class
         * @param {string|Element|NodeList|Array} selector - CSS selector or element(s)
         * @param {boolean} anim - Whether to animate (slide down)
         */
        ui.show = function (selector, anim = false) {
            for (const el of toElements(selector)) {
                if (anim) {
                    el.classList.remove("d-none");
                    const height = el.offsetHeight; // measure natural height now visible
                    el.style.overflow = "hidden";
                    el.style.height = "0";
                    const fx = el.animate(
                        [{height: 0}, {height: height + "px"}],
                        {duration: 400, easing: "ease", fill: "forwards"}
                    );
                    fx.onfinish = () => {
                        el.style.height = "";
                        el.style.overflow = "";
                        fx.cancel();
                    };
                } else {
                    el.classList.remove("d-none");
                }
            }
        };

        /**
         * Toggle visibility of one or more elements using Bootstrap's d-none class
         * @param {string|Element|NodeList|Array} selector - CSS selector or element(s)
         * @param {boolean} anim - Whether to animate
         */
        ui.toggle = function (selector, anim = false) {
            for (const el of toElements(selector)) {
                if (el.classList.contains("d-none")) {
                    ui.show(el, anim);
                } else {
                    ui.hide(el, anim);
                }
            }
        };

        ui.fileUtils = {
            readFile(files, callback, index = 0) {
                const file = files[index];
                const reader = new FileReader();
                reader.onerror = () => alertMessage("alert-danger", `Error reading file: ${file.name}`);
                reader.onloadend = () => callback(reader.result);
                reader.readAsText(file);
            },

            setFileInputFiles(fileInput, files, i) {
                const dt = new DataTransfer();
                if (arguments.length > 2) dt.items.add(files[i]);
                const input = (typeof fileInput === "string") ? document.querySelector(fileInput) : fileInput;
                input.files = dt.files;
            },

            setupFileHandling(textArea, fileInput, fileSet, enable_btn_cb, multiple_files_cb) {
                const dragoverClassList = "outline-dashed-primary bg-primary-subtle";
                const {readFile, setFileInputFiles} = ui.fileUtils;
                const ta = (typeof textArea === "string") ? document.querySelector(textArea) : textArea;
                const fi = (typeof fileInput === "string") ? document.querySelector(fileInput) : fileInput;

                function handleFileInput(fileSource) {
                    fileSet.files = fileSource.files;
                    fileSet.index = 0;
                    const {files} = fileSet;

                    if (files.length === 1) {
                        setFileInputFiles(fileInput, files, 0);
                        enable_btn_cb();
                        readFile(files, (result) => {
                            ta.value = result;
                            enable_btn_cb();
                        });
                    } else if (multiple_files_cb) {
                        multiple_files_cb(files);
                    } else {
                        alertMessage("alert-warning", "Multiple files processing is not supported.");
                    }
                }

                ["dragenter", "dragover", "dragleave", "drop"].forEach((evt) => {
                    ta.addEventListener(evt, (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                    });
                });
                ["dragenter", "dragover"].forEach((evt) => {
                    ta.addEventListener(evt, () => ta.classList.add(...dragoverClassList.split(" ")));
                });
                ["dragleave", "drop"].forEach((evt) => {
                    ta.addEventListener(evt, () => ta.classList.remove(...dragoverClassList.split(" ")));
                });
                ta.addEventListener("drop", (e) => handleFileInput(e.dataTransfer));
                ta.addEventListener("input", () => {
                    enable_btn_cb();
                    if (fileSet.files) {
                        fileSet.files = null;
                        setFileInputFiles(fileInput, fileSet.files);
                    }
                });

                fi.addEventListener("change", (e) => handleFileInput(e.target));
            }
        };

        ui.copyToClipboard = function (text) {
            // Try modern Clipboard API first (HTTPS only)
            const clip = navigator.clipboard;
            if (clip && clip.writeText) return clip.writeText(text);

            // Fallback for HTTP or older browsers using execCommand
            return new Promise((resolve, reject) => {
                const textarea = document.createElement("textarea");
                textarea.value = text;

                // Check if any modal is currently open
                const modal = document.querySelector(".modal.show");

                const modalBody = modal?.querySelector(".modal-body");
                if (modalBody) {
                    // Inside open modal: use fixed positioning to avoid focus trap
                    textarea.style.position = "fixed";
                    textarea.style.top = "50%";
                    textarea.style.left = "50%";
                    textarea.style.opacity = "0";
                    modalBody.appendChild(textarea);
                } else {
                    // Outside modal: use absolute positioning off-screen
                    textarea.style.position = "absolute";
                    textarea.style.left = "-9999px";
                    document.body.appendChild(textarea);
                }

                try {
                    textarea.focus({preventScroll: true});
                    textarea.select();
                    const successful = document.execCommand("copy");
                    textarea.remove();

                    if (successful) {
                        resolve();
                    } else {
                        reject(new Error("Copy command failed"));
                    }
                } catch (err) {
                    textarea.remove();
                    reject(err);
                }
            });
        };

        // Error log event handlers (bound once the DOM is ready)
        function onReady(fn) {
            if (document.readyState !== "loading") {
                fn();
            } else {
                document.addEventListener("DOMContentLoaded", fn);
            }
        }

        onReady(() => {
            const errorLogModal = document.getElementById("errorLogModal");
            const clearBtn = document.getElementById("clearErrorLog");
            const copyBtn = document.getElementById("copyErrorLog");

            // Update error log table when modal is shown
            errorLogModal.addEventListener("show.bs.modal", () => {
                updateErrorLogTable();
                // Mark all errors as viewed when modal is opened
                errorLog.markAsViewed();
            });

            // Clear error log
            clearBtn.addEventListener("click", () => {
                errorLog.clear();
                updateErrorLogTable();
            });

            // Copy error log to clipboard
            copyBtn.addEventListener("click", () => {
                if (errorLog.errors.length === 0) return;

                const selection = window.getSelection();
                let textToCopy = "";

                // Check if user has selected text in the table
                if (selection.toString().trim().length > 0) {
                    textToCopy = selection.toString();
                } else {
                    // Copy entire log
                    const headers = ["Time", "Error", "Server", "Endpoint", "HTTP Status", "Type"];
                    textToCopy = headers.join("\t") + "\n";

                    errorLog.errors.slice().reverse().forEach((err) => {
                        const time = ui.locale
                            ? err.timestamp.toLocaleString(ui.locale)
                            : err.timestamp.toLocaleString();
                        const status = err.httpStatus ?? "-";
                        const row = [time, err.message, err.server, err.endpoint, status, err.errorType];
                        textToCopy += row.join("\t") + "\n";
                    });
                }

                ui.copyToClipboard(textToCopy)
                    .then(() => {
                        // Show success feedback
                        const originalHtml = copyBtn.innerHTML;
                        copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                        setTimeout(() => {
                            copyBtn.innerHTML = originalHtml;
                        }, 2000);
                    })
                    .catch((err) => alertMessage("alert-danger", "Failed to copy to clipboard: " + err.message));
            });
        });

        return ui;
    });
