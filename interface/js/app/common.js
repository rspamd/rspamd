/* global jQuery */

define(["jquery", "nprogress"],
    ($, NProgress) => {
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

        function getPassword() {
            return sessionStorage.getItem("Password");
        }

        function alertMessage(alertClass, alertText) {
            const a = $("<div class=\"alert " + alertClass + " alert-dismissible fade in show\">" +
                "<button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"alert\" title=\"Dismiss\"></button>" +
                "<strong>" + alertText + "</strong>");
            $(".notification-area").append(a);

            setTimeout(() => {
                $(a).fadeTo(500, 0).slideUp(500, function () {
                    $(this).alert("close");
                });
            }, 5000);
        }

        // Forward declare updateErrorBadge to resolve circular dependency
        // This function is called by errorLog methods but uses errorLog data
        // Safe due to hoisting: function is called AFTER errorLog initialization
        function updateErrorBadge() {
            const unseenCount = errorLog.getUnseenCount(); // eslint-disable-line no-use-before-define
            const totalCount = errorLog.errors.length; // eslint-disable-line no-use-before-define
            const badge = $("#error-log-badge");
            const counter = $("#error-count");

            // Show badge if there are any errors
            if (totalCount > 0) {
                badge.removeClass("d-none");
                // Show counter only if there are unseen errors
                if (unseenCount > 0) {
                    counter.removeClass("d-none");
                    counter.text(unseenCount);
                } else {
                    counter.addClass("d-none");
                }
            } else {
                badge.addClass("d-none");
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
            const tbody = $("#errorLogTable tbody");
            const noErrors = $("#noErrorsMessage");
            const copyBtn = $("#copyErrorLog");
            const clearBtn = $("#clearErrorLog");

            tbody.empty();

            const hasErrors = errorLog.errors.length > 0;

            if (!hasErrors) {
                $("#errorLogTable").hide();
                noErrors.show();
                copyBtn.prop("disabled", true);
                clearBtn.prop("disabled", true);
                return;
            }

            $("#errorLogTable").show();
            noErrors.hide();
            copyBtn.prop("disabled", false);
            clearBtn.prop("disabled", false);

            // Show errors in reverse chronological order (newest first)
            errorLog.errors.slice().reverse().forEach((err) => {
                const time = ui.locale
                    ? err.timestamp.toLocaleString(ui.locale)
                    : err.timestamp.toLocaleString();
                const status = err.httpStatus ?? "-";
                const row = $("<tr></tr>");

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
                row.append($('<td class="text-nowrap"></td>').text(time));
                row.append($("<td></td>").text(err.message));
                row.append($('<td class="d-none d-sm-table-cell"></td>').text(err.server));
                row.append($('<td class="d-none d-md-table-cell"></td>')
                    .append($('<code class="small"></code>').text(err.endpoint)));
                row.append($('<td class="d-none d-lg-table-cell text-center"></td>').text(status));
                row.append($('<td class="d-none d-lg-table-cell"></td>')
                    .append($(`<span class="badge ${badgeClass}"></span>`).text(err.errorType)));
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
         * Perform a request to a single Rspamd neighbour server.
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
        function queryServer(neighbours_status, ind, req_url, o) {
            neighbours_status[ind].checked = false;
            neighbours_status[ind].data = {};
            neighbours_status[ind].status = false;
            const req_params = {
                jsonp: false,
                data: o.data,
                headers: $.extend({Password: getPassword()}, o.headers),
                url: neighbours_status[ind].url + req_url,
                xhr: function () {
                    const xhr = $.ajaxSettings.xhr();
                    // Download progress
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
                    return xhr;
                },
                success: function (json) {
                    neighbours_status[ind].checked = true;
                    neighbours_status[ind].status = true;
                    neighbours_status[ind].data = json;
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    neighbours_status[ind].checked = true;

                    // Determine error type and create detailed message
                    let errorType = "network";
                    let detailedMessage = errorThrown || "Request failed";

                    if (textStatus === "timeout") {
                        errorType = "timeout";
                        detailedMessage = "Request timeout";
                    } else if (jqXHR.status === 401 || jqXHR.status === 403) {
                        errorType = "auth";
                        detailedMessage = "Authentication failed";
                    } else if (jqXHR.status >= 400 && jqXHR.status < 600) {
                        errorType = "http_error";
                        detailedMessage = "HTTP " + jqXHR.status + (errorThrown ? ": " + errorThrown : "");
                    } else if (textStatus === "error" && jqXHR.status === 0) {
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
                        httpStatus: jqXHR.status,
                        errorType: errorType,
                        showAlert: shouldShowAlert
                    });

                    // Call custom error handler if provided
                    if (o.error) o.error(neighbours_status[ind], jqXHR, textStatus, errorThrown);
                },
                complete: function (jqXHR) {
                    if (neighbours_status.every((elt) => elt.checked)) {
                        if (neighbours_status.some((elt) => elt.status)) {
                            if (o.success) {
                                o.success(neighbours_status, jqXHR);
                            } else {
                                alertMessage("alert-success", "Request completed");
                            }
                        } else {
                            alertMessage("alert-danger", "Request failed");
                        }
                        if (o.complete) o.complete();
                        NProgress.done();
                    }
                },
                statusCode: o.statusCode
            };
            if (o.method) {
                req_params.method = o.method;
            }
            if (o.params) {
                $.each(o.params, (k, v) => {
                    req_params[k] = v;
                });
            }
            $.ajax(req_params);
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
         *   Ajax request configuration options.
         * @param {Object|string|Array} [options.data]
         *   Request body for POST endpoints.
         * @param {Object} [options.headers]
         *   Additional HTTP headers.
         * @param {"GET"|"POST"} [options.method]
         *   HTTP method (defaults to "GET").
         * @param {string} [options.server]
         *   Name or base-URL of the target server (defaults to the currently selected Rspamd neighbour).
         * @param {Object} [options.params]
         *   Extra jQuery.ajax() settings (e.g. timeout, dataType).
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
         *     2. jqXHR: jQuery XHR object with properties
         *        { readyState, status, statusText, responseText, responseJSON, … }
         * @param {function(Object, Object, string, string)} [options.error]
         *   Called on HTTP error or network failure. Receives:
         *     1. result: a per-server status object (status:false, data:{}).
         *     2. jqXHR: jQuery XHR object (responseText, responseJSON, status, statusText).
         *     3. textStatus: string describing error type ("error", "timeout", etc.).
         *     4. errorThrown: exception message or HTTP statusText.
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
                        if (jQuery.isEmptyObject(data)) {
                            ui.neighbours = {
                                local: {
                                    host: window.location.host,
                                    url: window.location.origin + window.location.pathname
                                }
                            };
                        } else {
                            ui.neighbours = data;
                        }
                        neighbours_status = [];
                        $.each(ui.neighbours, (ind) => {
                            neighbours_status.push({
                                name: ind,
                                host: ui.neighbours[ind].host,
                                url: ui.neighbours[ind].url,
                            });
                        });
                        $.each(neighbours_status, (ind) => {
                            queryServer(neighbours_status, ind, url, o);
                        });
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
         * @param {string|jQuery} selector - CSS selector or jQuery object
         * @param {boolean} anim - Whether to use animation (slideUp)
         */
        ui.hide = function (selector, anim = false) {
            const $el = (typeof selector === "string") ? $(selector) : selector;
            if (anim) {
                $el.slideUp(400, function () {
                    $(this).addClass("d-none");
                });
            } else {
                $el.addClass("d-none");
            }
        };

        /**
         * Show one or more elements using Bootstrap's d-none class
         * @param {string|jQuery} selector - CSS selector or jQuery object
         * @param {boolean} anim - Whether to use animation (slideDown)
         */
        ui.show = function (selector, anim = false) {
            const $el = (typeof selector === "string") ? $(selector) : selector;
            if (anim) {
                $el.removeClass("d-none").hide().slideDown(400);
            } else {
                $el.removeClass("d-none");
            }
        };

        /**
         * Toggle visibility of one or more elements using Bootstrap's d-none class
         * @param {string|jQuery} selector - CSS selector or jQuery object
         * @param {boolean} anim - Whether to use animation
         */
        ui.toggle = function (selector, anim = false) {
            const $el = (typeof selector === "string") ? $(selector) : selector;
            if ($el.hasClass("d-none")) {
                ui.show($el, anim);
            } else {
                ui.hide($el, anim);
            }
        };

        ui.appendButtonsToFtFilterDropdown = (ftFilter) => {
            function button(text, classes, check) {
                return $("<button/>", {
                    type: "button",
                    class: "btn btn-xs " + classes,
                    text: text,
                    click: () => {
                        const checkboxes = ftFilter.$dropdown.find(".checkbox input");
                        return (check) ? checkboxes.attr("checked", "checked") : checkboxes.removeAttr("checked");
                    }
                });
            }

            $("<div/>", {class: "d-flex justify-content-between footable-dropdown-btn-group"}).append(
                button("Check all", "btn-secondary", true),
                button("Uncheck all", "btn-outline-secondary ms-1")
            ).appendTo(ftFilter.$dropdown);
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
                $(fileInput).prop("files", dt.files);
            },

            setupFileHandling(textArea, fileInput, fileSet, enable_btn_cb, multiple_files_cb) {
                const dragoverClassList = "outline-dashed-primary bg-primary-subtle";
                const {readFile, setFileInputFiles} = ui.fileUtils;

                function handleFileInput(fileSource) {
                    fileSet.files = fileSource.files;
                    fileSet.index = 0;
                    const {files} = fileSet;

                    if (files.length === 1) {
                        setFileInputFiles(fileInput, files, 0);
                        enable_btn_cb();
                        readFile(files, (result) => {
                            $(textArea).val(result);
                            enable_btn_cb();
                        });
                    } else if (multiple_files_cb) {
                        multiple_files_cb(files);
                    } else {
                        alertMessage("alert-warning", "Multiple files processing is not supported.");
                    }
                }

                $(textArea)
                    .on("dragenter dragover dragleave drop", (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                    })
                    .on("dragenter dragover", () => $(textArea).addClass(dragoverClassList))
                    .on("dragleave drop", () => $(textArea).removeClass(dragoverClassList))
                    .on("drop", (e) => handleFileInput(e.originalEvent.dataTransfer))
                    .on("input", () => {
                        enable_btn_cb();
                        if (fileSet.files) {
                            fileSet.files = null;
                            setFileInputFiles(fileInput, fileSet.files);
                        }
                    });

                $(fileInput).on("change", (e) => handleFileInput(e.target));
            }
        };

        // Error log event handlers
        $(document).ready(() => {
            // Update error log table when modal is shown
            $("#errorLogModal").on("show.bs.modal", () => {
                updateErrorLogTable();
                // Mark all errors as viewed when modal is opened
                errorLog.markAsViewed();
            });

            // Clear error log
            $("#clearErrorLog").on("click", () => {
                errorLog.clear();
                updateErrorLogTable();
            });

            // Copy to clipboard
            $("#copyErrorLog").on("click", () => {
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

                // Copy to clipboard with fallback for HTTP
                function copyToClipboard(text) {
                    // Try modern Clipboard API first (HTTPS only)
                    const clip = navigator.clipboard;
                    if (clip && clip.writeText) return clip.writeText(text);

                    // Fallback for HTTP or older browsers using execCommand
                    return new Promise((resolve, reject) => {
                        let textarea = null;
                        function cleanup(o) {
                            if (o && o.parentNode) o.parentNode.removeChild(o);
                        }

                        try {
                            textarea = document.createElement("textarea");
                            textarea.value = text;

                            // Critical: must be visible and in viewport for some browsers
                            textarea.style.position = "fixed";
                            textarea.style.top = "50%";
                            textarea.style.left = "50%";
                            textarea.style.width = "1px";
                            textarea.style.height = "1px";
                            textarea.style.padding = "0";
                            textarea.style.border = "none";
                            textarea.style.outline = "none";
                            textarea.style.boxShadow = "none";
                            textarea.style.background = "transparent";
                            textarea.style.zIndex = "99999";

                            // Add to modal body instead of document.body to avoid focus trap
                            const modalBody = document.querySelector("#errorLogModal .modal-body");
                            if (modalBody) {
                                modalBody.appendChild(textarea);
                            } else {
                                document.body.appendChild(textarea);
                            }

                            // Force reflow to ensure textarea is rendered
                            textarea.offsetHeight; // eslint-disable-line no-unused-expressions

                            // Select all text
                            textarea.focus();
                            textarea.select();
                            textarea.setSelectionRange(0, textarea.value.length);

                            // Execute copy immediately while focused
                            const successful = document.execCommand("copy");

                            cleanup(textarea);

                            if (successful) {
                                resolve();
                            } else {
                                reject(new Error("Copy command failed (execCommand returned false)"));
                            }
                        } catch (err) {
                            cleanup(textarea);
                            reject(err);
                        }
                    });
                }

                copyToClipboard(textToCopy)
                    .then(() => {
                        // Show success feedback
                        const btn = $("#copyErrorLog");
                        const originalHtml = btn.html();
                        btn.html('<i class="fas fa-check"></i> Copied!');
                        setTimeout(() => btn.html(originalHtml), 2000);
                    })
                    .catch((err) => alertMessage("alert-danger", "Failed to copy to clipboard: " + err.message));
            });
        });

        return ui;
    });
