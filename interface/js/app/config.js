/*
 * Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>
 */

/* global require */

define(["app/common", "app/icons", "bootstrap"],
    (common, icons, bootstrap) => {
        "use strict";
        const ui = {};

        ui.getActions = function getActions() {
            common.query("actions", {
                success: function (data) {
                    const form = document.getElementById("actionsFormField");
                    const items = [];
                    data[0].data.forEach((item) => {
                        const actionsOrder = ["greylist", "add header", "rewrite subject", "reject"];
                        const idx = actionsOrder.indexOf(item.action);
                        if (idx >= 0) {
                            items.push({
                                idx: idx,
                                node: common.el("div", {class: "mb-3"},
                                    common.el("label", {class: "col-form-label col-md-2 float-start", text: item.action}),
                                    common.el("div", {class: "controls slider-controls col-md-10"},
                                        common.el("input", {
                                            class: "action-scores form-control",
                                            dataset: {id: "action"},
                                            type: "number",
                                            value: item.value,
                                        })
                                    )
                                )
                            });
                        }
                    });

                    items.sort((a, b) => a.idx - b.idx);
                    form.replaceChildren(...items.map((e) => e.node));
                },
                server: common.getServer()
            });
        };

        ui.saveActions = function (server) {
            function descending(arr) {
                let desc = true;
                const filtered = arr.filter((el) => el !== null);
                for (let i = 0; i < filtered.length - 1; i++) {
                    if (filtered[i + 1] >= filtered[i]) {
                        desc = false;
                        break;
                    }
                }
                return desc;
            }

            const elts = (function () {
                const values = [];
                const inputs = document.querySelectorAll("#actionsForm input[data-id=\"action\"]");
                // Rspamd order: [spam, rewrite_subject, probable_spam, greylist]
                values[0] = parseFloat(inputs[3].value);
                values[1] = parseFloat(inputs[2].value);
                values[2] = parseFloat(inputs[1].value);
                values[3] = parseFloat(inputs[0].value);

                return JSON.stringify(values);
            }());
            // String to array for comparison
            const eltsArray = JSON.parse(elts);
            if (eltsArray[0] < 0) {
                common.alertMessage("alert-modal alert-danger", "Spam can not be negative");
            } else if (eltsArray[1] < 0) {
                common.alertMessage("alert-modal alert-danger", "Rewrite subject can not be negative");
            } else if (eltsArray[2] < 0) {
                common.alertMessage("alert-modal alert-danger", "Probable spam can not be negative");
            } else if (eltsArray[3] < 0) {
                common.alertMessage("alert-modal alert-danger", "Greylist can not be negative");
            } else if (descending(eltsArray)) {
                common.query("saveactions", {
                    method: "POST",
                    params: {
                        data: elts,
                        dataType: "json"
                    },
                    server: server
                });
            } else {
                common.alertMessage("alert-modal alert-danger", "Incorrect order of actions thresholds");
            }
        };

        ui.getMaps = function () {
            const listmaps = document.getElementById("listMaps");
            const card = listmaps.closest(".card");
            common.hide(card);
            common.query("maps", {
                success: function (json) {
                    const [{data}] = json;
                    const tbody = listmaps.querySelector("tbody");
                    tbody.replaceChildren();

                    data.forEach((item) => {
                        const td = common.el("td");
                        const badges = [
                            {text: "Not loaded", cls: "text-bg-warning", cond: !item.loaded},
                            {text: "Cached", cls: "text-bg-info", cond: item.cached},
                            {text: "Writable", cls: "text-bg-success", cond: !(item.editable === false || common.read_only)}
                        ];
                        badges.forEach((b) => {
                            if (b.cond) td.append(common.el("span", {class: "badge me-1 " + b.cls, text: b.text}));
                        });

                        const tr = common.el("tr", null, td, common.el("td", {text: item.type}));
                        if (!item.loaded) tr.classList.add("table-active", "opacity-50");

                        const span = common.el("span", {class: "map-link", text: item.uri});
                        common.data(span, "item", item);
                        tr.append(common.el("td", null, span));
                        tr.append(common.el("td", {text: item.description}));
                        tbody.append(tr);
                    });
                    common.show(card);
                },
                server: common.getServer()
            });
        };


        let jar = {};
        const editor = {
            advanced: {
                codejar: true,
                elt: "div",
                class: "editor language-clike",
                readonly_attr: {contenteditable: false},
            },
            basic: {
                elt: "textarea",
                class: "form-control map-textarea",
                readonly_attr: {readonly: true},
            }
        };
        let mode = "advanced";

        // Modal form for maps
        common.delegate(document, "click", ".map-link", (event, span) => {
            const item = common.data(span, "item");
            common.query("getmap", {
                headers: {
                    Map: item.map
                },
                success: function (data) {
                    // Highlighting a large amount of text is unresponsive
                    const checkedMode = document.querySelector("input[name=\"editorMode\"]:checked")?.value;
                    mode = (new Blob([data[0].data]).size > 5120) ? "basic" : checkedMode;

                    const editorElt = common.el(editor[mode].elt, {
                        id: "editor",
                        class: editor[mode].class,
                        dataset: {id: item.map}
                    });
                    document.getElementById("modalBody").replaceChildren(editorElt);

                    if (editor[mode].codejar) {
                        require(["codejar", "linenumbers", "prism"], (CodeJar, withLineNumbers, Prism) => {
                            jar = new CodeJar(
                                document.querySelector("#editor"),
                                withLineNumbers((el) => Prism.highlightElement(el))
                            );
                            jar.updateCode(data[0].data);
                        });
                    } else {
                        editorElt.innerHTML = common.escapeHTML(data[0].data);
                    }

                    let icon = "fa-pen-to-square";
                    if (item.editable === false || common.read_only) {
                        Object.entries(editor[mode].readonly_attr).forEach(([attr, value]) => {
                            editorElt.setAttribute(attr, value);
                        });
                        icon = "fa-eye";
                        common.hide("#modalSaveGroup");
                    } else {
                        common.show("#modalSaveGroup");
                    }
                    // The map-modal header holds a single icon (<i class="fas my-auto">);
                    // setIcon swaps it (or its already-rendered <svg>) for `icon`.
                    const header = document.querySelector("#modalDialog .modal-header");
                    const headerIcon = header?.querySelector("svg[data-icon], i.fas");
                    if (headerIcon) {
                        icons.setIcon(headerIcon, icon);
                    }
                    document.getElementById("modalTitle").textContent = item.uri;

                    bootstrap.Modal.getOrCreateInstance(document.getElementById("modalDialog")).show();
                },
                errorMessage: "Cannot receive maps data",
                server: common.getServer()
            });
        });
        document.getElementById("modalDialog").addEventListener("hidden.bs.modal", () => {
            if (editor[mode].codejar && jar && typeof jar.destroy === "function") {
                jar.destroy();
                document.querySelectorAll(".codejar-wrap").forEach((el) => el.remove());
            } else {
                document.getElementById("editor")?.remove();
            }
        });

        document.getElementById("saveActionsBtn").addEventListener("click", () => ui.saveActions());
        document.getElementById("saveActionsClusterBtn").addEventListener("click", () => ui.saveActions("All SERVERS"));

        function saveMap(server) {
            common.query("savemap", {
                success: function () {
                    common.alertMessage("alert-success", "Map data successfully saved");
                    bootstrap.Modal.getOrCreateInstance(document.getElementById("modalDialog")).hide();
                },
                errorMessage: "Save map error",
                method: "POST",
                headers: {
                    Map: document.getElementById("editor").dataset.id,
                },
                params: {
                    data: editor[mode].codejar ? jar.toString() : document.getElementById("editor").value,
                    dataType: "text",
                },
                server: server
            });
        }
        document.getElementById("modalSave").addEventListener("click", () => saveMap());
        document.getElementById("modalSaveAll").addEventListener("click", () => saveMap("All SERVERS"));

        return ui;
    });
