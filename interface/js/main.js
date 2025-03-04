/* global d3:writable, require, requirejs */ // eslint-disable-line no-unused-vars

requirejs.config({
    baseUrl: "js/lib",
    paths: {
        app: "../app",
        jquery: "jquery-3.7.1.min",
        visibility: "visibility.min",
        bootstrap: "bootstrap.bundle.min",
        codejar: "codejar.min",
        d3: "d3.min",
        d3evolution: "d3evolution.min",
        d3pie: "d3pie.min",
        footable: "footable.min",
        linenumbers: "codejar-linenumbers.min",
        nprogress: "nprogress.min",
        prism: "prism",
        stickytabs: "jquery.stickytabs.min"
    },
    shim: {
        app: {deps: ["jquery"]},
        codejar: {exports: "CodeJar", deps: ["linenumbers"]},
        bootstrap: {exports: "bootstrap", deps: ["jquery"]}, // Popovers require jQuery
        d3: {exports: "d3"},
        d3evolution: {exports: "D3Evolution", deps: ["d3.global", "jquery"]},
        d3pie: {exports: "D3Pie", deps: ["d3.global", "jquery"]},
        footable: {deps: ["bootstrap", "jquery"]},
        linenumbers: {exports: "withLineNumbers", deps: ["prism"]},
        prism: {exports: "Prism"},
        stickytabs: {deps: ["jquery"]}
    },
    waitSeconds: 30,
});

document.title = window.location.hostname +
    (window.location.port ? ":" + window.location.port : "") +
    (window.location.pathname !== "/" ? window.location.pathname : "") +
    " - Rspamd Web Interface";

// Ugly hack to get d3pie work with requirejs
define("d3.global", ["d3"], (d3global) => { // eslint-disable-line strict
    d3 = d3global;
});

// Notify user on module loading failure
requirejs.onError = function (e) {
    "use strict";
    document.getElementById("loading").classList.add("d-none");
    document.getElementsByClassName("notification-area")[0].innerHTML =
        "<div class=\"alert alert-error\">" +
            "<strong>Module loading error: " + e.requireType + ", module: " + e.requireModules + "</strong>" +
            "<button type=\"button\" class=\"btn btn-info btn-xs float-end\" " +
                "onClick=\"window.location.reload(); this.parentNode.parentNode.removeChild(this.parentNode);\" " +
                "title=\"Reload current page\">" +
                "<i class=\"fas fa-sync-alt\"></i> Reload" +
            "</button>" +
        "</div>";
    throw e;
};

// Load main UI
require(["app/rspamd"], (rspamd) => {
    "use strict";
    rspamd.connect();
});
