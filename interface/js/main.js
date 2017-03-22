requirejs.config({
    baseUrl: 'js/lib',
    paths: {
        app: '../app',
        jquery: 'jquery-3.1.1.min',
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
        d3pie: {exports: 'd3pie', deps: ['d3', 'jquery']},
        d3evolution: {exports: 'D3Evolution', deps: ['d3', 'd3pie', 'jquery']},
        footable: {deps: ['bootstrap', 'jquery']}
    }
});

// Load main UI
require(['domReady'],
function(domReady) {
    domReady(function () {
        require(['jquery', 'app/rspamd'],
            function ($, rspamd) {
                rspamd.setup();
                rspamd.connect();
            });
    });
});
