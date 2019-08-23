/* global d3:true, require:false, requirejs:false */ // eslint-disable-line no-unused-vars

requirejs.config({
    baseUrl: "js/lib",
    paths: {
        app: "../app",
        jquery: "jquery-3.4.1.min",
        visibility: "visibility.min",
        humanize: "humanize.min",
        bootstrap: "bootstrap.min",
        d3: "d3.min",
        d3evolution: "d3evolution.min",
        d3pie: "d3pie.min",
        footable: "footable.min",
        nprogress: "nprogress.min",
        stickytabs: "jquery.stickytabs.min"
    },
    shim: {
        bootstrap: {exports:"bootstrap", deps:["jquery"]},
        d3pie: {exports:"d3pie", deps:["d3.global", "jquery"]},
        d3evolution: {exports:"D3Evolution", deps:["d3", "jquery"]},
        footable: {deps:["bootstrap", "jquery"]},
        stickytabs: {deps:["jquery"]}
    },
    waitSeconds: 30,
});

document.title = window.location.hostname +
    (window.location.port ? ":" + window.location.port : "") +
    (window.location.pathname !== "/" ? window.location.pathname : "") +
    " - Rspamd Web Interface";

// Ugly hack to get d3pie work with requirejs
define("d3.global", ["d3"], function (d3global) { // eslint-disable-line strict
    d3 = d3global;
});

// Notify user on module loading failure
requirejs.onError = function (e) {
    "use strict";
    document.getElementsByClassName("notification-area")[0].innerHTML =
        "<div class=\"alert alert-error\">" +
            "<strong>Module loading error: " + e.requireType + ", module: " + e.requireModules + "</strong>" +
            "<button type=\"button\" class=\"btn btn-info btn-xs pull-right\" " +
                "onClick=\"window.location.reload(); this.parentNode.parentNode.removeChild(this.parentNode);\" " +
                "title=\"Reload current page\">" +
                "<i class=\"glyphicon glyphicon-repeat\"></i> Reload" +
            "</button>" +
        "</div>";
    throw e;
};

// Load main UI
require(["app/rspamd"],
    function (rspamd) {
        "use strict";
        rspamd.setup();
        rspamd.connect();
    }
);
