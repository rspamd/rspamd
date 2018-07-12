/* global d3:false, require:false, requirejs:false */ // eslint-disable-line no-unused-vars

requirejs.config({
    baseUrl: "js/lib",
    paths: {
        app: "../app",
        jquery: "jquery-3.3.1.min",
        visibility: "visibility.min",
        humanize: "humanize.min",
        bootstrap: "bootstrap.min",
        d3: "d3.min",
        d3evolution: "d3evolution.min",
        d3pie: "d3pie.min",
        footable: "footable.min",
    },
    shim: {
        d3: {exports: "d3"},
        bootstrap: {exports: "bootstrap", deps: ["jquery"]},
        d3pie: {exports: "d3pie", deps: ["d3.global", "jquery"]},
        d3evolution: {exports: "D3Evolution", deps: ["d3", "d3pie", "jquery"]},
        footable: {deps: ["bootstrap", "jquery"]}
    }
});

document.title = window.location.hostname +
    (window.location.port ? ":" + window.location.port : "") +
    (window.location.pathname !== "/" ? window.location.pathname : "") +
    " - Rspamd Web Interface";

define("d3.global", ["d3"], function (_) { // eslint-disable-line strict
    d3 = _; // eslint-disable-line no-global-assign
});

// Load main UI
require(["domReady"],
    function (domReady) {
        "use strict";
        domReady(function () {
            require(["jquery", "d3", "app/rspamd"],
                function ($, d3, rspamd) {
                    rspamd.setup();
                    rspamd.connect();
                });
        });
    });
