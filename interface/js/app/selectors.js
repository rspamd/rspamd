define(["app/common"],
    (common) => {
        "use strict";
        const ui = {};
        const fileSet = {files: null, index: null};

        function enable_disable_check_btn() {
            const msgArea = document.getElementById("selectorsMsgArea");
            const selArea = document.getElementById("selectorsSelArea");
            document.getElementById("selectorsChkMsgBtn").disabled =
                msgArea.value.trim().length === 0 || !selArea.classList.contains("is-valid");
        }

        function checkMsg(data) {
            const selector = document.getElementById("selectorsSelArea").value;
            common.query("plugins/selectors/check_message?selector=" + encodeURIComponent(selector), {
                data: data,
                method: "POST",
                success: function (neighbours_status) {
                    const json = neighbours_status[0].data;
                    if (json.success) {
                        common.alertMessage("alert-success", "Message successfully processed");
                        document.getElementById("selectorsResArea").value =
                            Object.prototype.hasOwnProperty.call(json, "data") ? json.data.toString() : "";
                    } else {
                        common.alertMessage("alert-danger", "Unexpected error processing message");
                    }
                },
                server: common.getServer()
            });
        }

        function checkSelectors() {
            const selArea = document.getElementById("selectorsSelArea");
            function toggle_form_group_class(remove, add) {
                selArea.classList.remove("is-" + remove);
                selArea.classList.add("is-" + add);
                enable_disable_check_btn();
            }
            const selector = selArea.value;
            if (selector.length && !common.read_only) {
                common.query("plugins/selectors/check_selector?selector=" + encodeURIComponent(selector), {
                    method: "GET",
                    success: function (json) {
                        if (json[0].data.success) {
                            toggle_form_group_class("invalid", "valid");
                        } else {
                            toggle_form_group_class("valid", "invalid");
                        }
                    },
                    server: common.getServer()
                });
            } else {
                selArea.classList.remove("is-valid", "is-invalid");
                enable_disable_check_btn();
            }
        }

        function buildLists() {
            function build_table_from_json(json, table_id) {
                Object.keys(json).forEach((key) => {
                    const tr = common.el("tr", null,
                        common.el("td", null, common.el("code", {text: key})),
                        common.el("td", {text: json[key].description})
                    );
                    document.querySelector(table_id + " tbody").append(tr);
                });
            }

            function getList(list) {
                common.query("plugins/selectors/list_" + list, {
                    method: "GET",
                    success: function (neighbours_status) {
                        const json = neighbours_status[0].data;
                        build_table_from_json(json, "#selectorsTable-" + list);
                    },
                    server: common.getServer()
                });
            }

            getList("extractors");
            getList("transforms");
        }

        ui.displayUI = function () {
            if (!common.read_only &&
                !document.querySelector("#selectorsTable-extractors>tbody>tr") &&
                !document.querySelector("#selectorsTable-transforms>tbody>tr")) buildLists();
            if (!document.getElementById("selectorsSelArea").matches(".is-valid, .is-invalid")) checkSelectors();
        };


        function toggleSidebar(side) {
            document.getElementById("sidebar-" + side).classList.toggle("collapsed");
            const openSidebarsCount = document.getElementById("sidebar-left").classList.contains("collapsed") +
                document.getElementById("sidebar-right").classList.contains("collapsed");
            const layoutMap = {1: "col-lg-9", 2: "col-lg-12"};
            const contentClass = layoutMap[openSidebarsCount] || "col-lg-6";
            const content = document.getElementById("content");
            content.classList.remove("col-lg-12", "col-lg-9", "col-lg-6");
            content.classList.add(contentClass);
        }
        document.querySelector("#sidebar-tab-left > a").addEventListener("click", (e) => {
            e.preventDefault();
            toggleSidebar("left");
        });
        document.querySelector("#sidebar-tab-right > a").addEventListener("click", (e) => {
            e.preventDefault();
            toggleSidebar("right");
        });

        document.getElementById("selectorsMsgClean").addEventListener("click", (e) => {
            e.preventDefault();
            document.getElementById("selectorsChkMsgBtn").disabled = true;
            document.getElementById("selectorsMsgArea").value = "";
            document.getElementById("selectorsFile").value = "";
        });
        document.getElementById("selectorsClean").addEventListener("click", (e) => {
            e.preventDefault();
            document.getElementById("selectorsSelArea").value = "";
            checkSelectors();
        });
        document.getElementById("selectorsChkMsgBtn").addEventListener("click", (e) => {
            e.preventDefault();
            document.getElementById("selectorsResArea").value = "";
            checkMsg(document.getElementById("selectorsMsgArea").value);
        });

        document.getElementById("selectorsSelArea").addEventListener("input", () => {
            checkSelectors();
        });

        common.fileUtils.setupFileHandling("#selectorsMsgArea", "#selectorsFile", fileSet, enable_disable_check_btn);

        return ui;
    });
