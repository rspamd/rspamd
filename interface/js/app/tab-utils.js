/*
 * Tabulator UI helpers shared across tables.
 * Extracted from history.js Phase 0. Depends only on common (for
 * common.tables); no jQuery, no FooTable.
 */

define(["app/common"],
    (common) => {
        "use strict";
        const tabUtils = {};

        let scrollIntoViewPatched = false;

        /**
         * Patch Element.prototype.scrollIntoView once so that calls for elements
         * inside ANY Tabulator table (.tabulator container) are no-ops. Guarded
         * by a module-level flag so the prototype is patched only once regardless
         * of how many tables call this.
         */
        tabUtils.patchScrollIntoViewOnce = function () {
            if (scrollIntoViewPatched) return;
            const native = Element.prototype.scrollIntoView;
            Element.prototype.scrollIntoView = function (...args) {
                if (!this.closest(".tabulator")) {
                    native.apply(this, args);
                }
            };
            scrollIntoViewPatched = true;
        };

        /**
         * Remove tabindex from the tableholder and keep it removed (Tabulator
         * re-adds it on render). Prevents focus-scroll when clicking body cells.
         */
        tabUtils.stripTableholderTabindex = function (table) {
            const holder = common.tables[table].element.querySelector(".tabulator-tableholder");
            if (!holder) return;
            holder.removeAttribute("tabindex");
            new MutationObserver(() => holder.removeAttribute("tabindex"))
                .observe(holder, {attributes: true, attributeFilter: ["tabindex"]});
        };

        /**
         * Hide the pagination footer when the table has only one page (FooTable
         * parity). Registers a renderComplete handler.
         */
        tabUtils.hideFooterOnSinglePage = function (table) {
            common.tables[table].on("renderComplete", () => {
                const t = common.tables[table];
                const footer = t.element.querySelector(".tabulator-footer");
                if (footer) footer.style.display = t.getPageMax() > 1 ? "" : "none";
            });
        };

        /**
         * Allow clicking anywhere on a row to toggle responsive-collapse
         * (instead of just the tiny toggle icon). Skips when selecting text
         * and when collapse is not active (toggle hidden).
         */
        tabUtils.bindRowClickToggle = function (table) {
            common.tables[table].element.addEventListener("click", (e) => {
                const row = e.target.closest(".tabulator-row");
                if (!row) return;
                const sel = window.getSelection && window.getSelection();
                if (sel && sel.toString()) return;
                const toggle = row.querySelector(".tabulator-responsive-collapse-toggle");
                if (toggle && toggle.offsetParent) toggle.click();
            });
        };

        /**
         * Install scroll-position preservation for a table. Tabulator scrolls
         * the page on interactions; this restores the position synchronously
         * (before paint) so the jump is never visible.
         *
         * @param {string} table - Key in common.tables
         * @param {Object} options - { armTriggers: HTMLElement[], clickMs?: 250, renderMs?: 400 }
         */
        tabUtils.installScrollPreservation = function (table, options) {
            const t = common.tables[table];
            const {clickMs = 250, renderMs = 400, armTriggers = []} = options || {};
            let preserveY = 0;
            let preserveUntil = 0;
            let clickArmed = false;

            function arm() {
                const y = window.scrollY;
                preserveY = y;
                preserveUntil = performance.now() + clickMs;
                clickArmed = true;
                Promise.resolve().then(() => {
                    // Microtask (after sync handlers, before paint): catch sync scrolls.
                    if (window.scrollY !== y) window.scrollTo(0, y);
                    // rAF queued from the microtask lands AFTER Tabulator's render rAF
                    // (queued during the click), in the same frame after the render-
                    // scroll but before paint.
                    requestAnimationFrame(() => {
                        if (window.scrollY !== y) window.scrollTo(0, y);
                    });
                });
            }

            t.element.addEventListener("click", arm, true);
            armTriggers.forEach((el) => el.addEventListener("click", arm, true));

            t.on("renderStarted", () => {
                if (clickArmed) preserveUntil = performance.now() + renderMs;
            });
            t.on("renderComplete", () => {
                clickArmed = false;
            });

            window.addEventListener("scroll", () => {
                if (performance.now() >= preserveUntil) return;
                if (window.scrollY !== preserveY) window.scrollTo(0, preserveY);
            }, true);
        };

        return tabUtils;
    });
