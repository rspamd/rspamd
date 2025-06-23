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
                    function errorMessage() {
                        alertMessage("alert-error", neighbours_status[ind].name + " > " +
                            (o.errorMessage ? o.errorMessage : "Request failed") +
                            (errorThrown ? ": " + errorThrown : ""));
                    }
                    if (o.error) {
                        o.error(neighbours_status[ind],
                            jqXHR, textStatus, errorThrown);
                    } else if (o.errorOnceId) {
                        const alert_status = o.errorOnceId + neighbours_status[ind].name;
                        if (!(alert_status in sessionStorage)) {
                            sessionStorage.setItem(alert_status, true);
                            errorMessage();
                        }
                    } else {
                        errorMessage();
                    }
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
                            alertMessage("alert-error", "Request failed");
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
                reader.onerror = () => alertMessage("alert-error", `Error reading file: ${file.name}`);
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

        return ui;
    });
