/* global jQuery */

define(["jquery", "nprogress"],
    ($, NProgress) => {
        "use strict";
        const ui = {
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
         * @param {string} url - A string containing the URL to which the request is sent
         * @param {Object} [options] - A set of key/value pairs that configure the Ajax request. All settings are optional.
         *
         * @param {Function} [options.complete] - A function to be called when the requests to all neighbours complete.
         * @param {Object|string|Array} [options.data] - Data to be sent to the server.
         * @param {Function} [options.error] - A function to be called if the request fails.
         * @param {string} [options.errorMessage] - Text to display in the alert message if the request fails.
         * @param {string} [options.errorOnceId] - A prefix of the alert ID to be added to the session storage. If the
         *     parameter is set, the error for each server will be displayed only once per session.
         * @param {Object} [options.headers] - An object of additional header key/value pairs to send along with requests
         *     using the XMLHttpRequest transport.
         * @param {string} [options.method] - The HTTP method to use for the request.
         * @param {Object} [options.params] - An object of additional jQuery.ajax() settings key/value pairs.
         * @param {string} [options.server] - A server to which send the request.
         * @param {Function} [options.success] - A function to be called if the request succeeds.
         *
         * @returns {undefined}
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

        return ui;
    });
