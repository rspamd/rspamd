requirejs.config({
    baseUrl: 'js/lib',
    paths: {
        app: '../app',
        jquery: 'jquery-3.2.1.min',
        visibility: 'visibility.min',
        humanize: 'humanize.min',
        bootstrap: 'bootstrap.min',
        d3: 'd3.min',
        d3evolution: 'd3evolution.min',
        d3pie: 'd3pie.min',
        footable: 'footable.min',
        bootstrap: 'bootstrap.min',
    },
    shim: {
        d3: {exports: 'd3'},
        bootstrap: {exports: 'bootstrap', deps: ['jquery']},
        d3pie: {exports: 'd3pie', deps: ['d3.global', 'jquery']},
        d3evolution: {exports: 'D3Evolution', deps: ['d3', 'd3pie', 'jquery']},
        footable: {deps: ['bootstrap', 'jquery']}
    }
});

document.title = window.location.hostname +
    (window.location.port ? ":" + window.location.port : "") +
    (window.location.pathname !== "/" ? window.location.pathname : "") +
    " - Rspamd Web Interface";

define("d3.global", ["d3"], function(_) {
  d3 = _;
});

// Load main UI
require(['domReady'],
function(domReady) {
    domReady(function () {
        require(['jquery', 'd3', 'app/rspamd'],
            function ($, d3, rspamd) {
                rspamd.setup();
                rspamd.connect();
            });
    });
});
