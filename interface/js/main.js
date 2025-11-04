/* global d3:writable, require, requirejs */ // eslint-disable-line no-unused-vars

/**
 * Theme initialization and management
 *
 * Initializes theme as early as possible, before loading any modules.
 * Provides automatic theme detection and switching based on user preference
 * and system settings. Invalid or missing preferences default to "auto" mode,
 * which follows the system's color scheme preference.
 *
 * @exports window.rspamd.theme.applyPreference - Apply theme preference with listener management
 * @exports window.rspamd.theme.getEffectiveTheme - Get effective theme for a given preference
 */
(function () {
    "use strict";

    const mq = window.matchMedia("(prefers-color-scheme: dark)");

    function normalizeTheme(value) {
        const pref = (typeof value === "string") ? value.trim().toLowerCase() : "";
        const allowed = new Set(["light", "dark", "auto"]);
        return {
            isAuto: !pref || !allowed.has(pref) || pref === "auto",
            pref: pref
        };
    }

    /**
     * Get effective theme based on preference
     * @param {string} themePref - Theme preference ("light", "dark", "auto", or invalid)
     * @returns {string} Effective theme: "light" or "dark"
     */
    function getEffectiveTheme(themePref) {
        const {isAuto, pref} = normalizeTheme(themePref);
        // eslint-disable-next-line no-nested-ternary
        return isAuto ? (mq.matches ? "dark" : "light") : pref;
    }

    function apply(theme) {
        document.documentElement.setAttribute("data-bs-theme", theme);
        document.body.setAttribute("data-theme", theme);
    }

    function handler() {
        apply(getEffectiveTheme(localStorage.getItem("theme")));
    }

    // Apply theme immediately on page load
    handler();

    // Set up listener for system theme changes if in auto mode
    const {isAuto: initialIsAuto} = normalizeTheme(localStorage.getItem("theme"));
    if (initialIsAuto && typeof mq.addEventListener === "function") {
        mq.addEventListener("change", handler);
    }


    // Export theme API to window.rspamd namespace
    if (!window.rspamd) window.rspamd = {};

    /**
     * Theme management API
     * @namespace
     *
     * @property {Function} applyPreference - Apply theme preference (handles auto mode and listener management)
     * @property {Function} getEffectiveTheme - Get effective theme for a given preference
     */
    window.rspamd.theme = {

        /**
         * Apply theme preference (handles auto mode and listener management)
         * @param {string} themePref - Theme preference to apply
         */
        applyPreference: (themePref) => {
            localStorage.setItem("theme", themePref);
            apply(getEffectiveTheme(themePref));

            const {isAuto} = normalizeTheme(themePref);
            // Safe to call even if listener isn't attached (MDN doc)
            mq.removeEventListener("change", handler);
            if (isAuto) {
                mq.addEventListener("change", handler);
            }
        },

        getEffectiveTheme: getEffectiveTheme
    };
}());

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
        fontawesome: "fontawesome.min",
        fontawesome_solid: "solid.min",
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
        fontawesome: {exports: "FontAwesome", deps: ["fontawesome_solid"]},
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
        "<div class=\"alert alert-danger\">" +
            "<strong>Module loading error: " + e.requireType + ", module: " + e.requireModules + "</strong>" +
            "<button type=\"button\" class=\"btn btn-info btn-xs float-end\" " +
                "onClick=\"window.location.reload(); this.parentNode.parentNode.removeChild(this.parentNode);\" " +
                "title=\"Reload current page\">" +
                "Reload" +
            "</button>" +
        "</div>";
    throw e;
};

// Load main UI
require(["app/rspamd"], (rspamd) => {
    "use strict";
    rspamd.connect();
});
