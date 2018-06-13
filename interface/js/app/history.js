/*
 The MIT License (MIT)

 Copyright (C) 2017 Vsevolod Stakhov <vsevolod@highsecure.ru>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 */

define(['jquery', 'footable', 'humanize'],
function($, _, Humanize) {
    var interface = {};
    var ft = {};
    var htmlEscapes = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '/': '&#x2F;',
      '`': '&#x60;',
      '=': '&#x3D;'
    };
    var htmlEscaper = /[&<>"'\/`=]/g;
    var symbolDescriptions = {};

    EscapeHTML = function(string) {
      return ('' + string).replace(htmlEscaper, function(match) {
        return htmlEscapes[match];
      });
    };

    escape_HTML_array = function (arr) {
        arr.forEach(function (d, i) { arr[i] = EscapeHTML(d) });
    };

    function unix_time_format(tm) {
        var date = new Date(tm ? tm * 1000 : 0);
        return date.toLocaleString();
    }

    function preprocess_item(item) {
        for (var prop in item) {
            switch (prop) {
                case "rcpt_mime":
                case "rcpt_smtp":
                    escape_HTML_array(item[prop]);
                    break;
                case "symbols":
                    Object.keys(item.symbols).map(function(key) {
                        var sym = item.symbols[key];
                        if (!sym.name) {
                            sym.name = key;
                        }
                        sym.name = EscapeHTML(key);
                        if (sym.description) {
	                        sym.description = EscapeHTML(sym.description);
                        }

                        if (sym.options) {
                            escape_HTML_array(sym.options);
                        }
                    });
                    break;
                default:
                    if (typeof (item[prop]) == "string") {
                        item[prop] = EscapeHTML(item[prop]);
                    }
            }
        }

        if (item.action === 'clean' || item.action === 'no action') {
            item.action = "<div style='font-size:11px' class='label label-success'>" + item.action + "</div>";
        } else if (item.action === 'rewrite subject' || item.action === 'add header' || item.action === 'probable spam') {
            item.action = "<div style='font-size:11px' class='label label-warning'>" + item.action + "</div>";
        } else if (item.action === 'spam' || item.action === 'reject') {
            item.action = "<div style='font-size:11px' class='label label-danger'>" + item.action + "</div>";
        } else {
            item.action = "<div style='font-size:11px' class='label label-info'>" + item.action + "</div>";
        }

        var score_content;
        if (item.score < item.required_score) {
            score_content = "<span class='text-success'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>";
        } else {
            score_content = "<span class='text-danger'>" + item.score.toFixed(2) + " / " + item.required_score + "</span>";
        }

        item.score = {
            "options": {
                "sortValue": item.score
            },
            "value": score_content
        };

        if (item.user == null) {
            item.user = "none";
        }
    }

    function process_history_v2(data) {
        // Display no more than rcpt_lim recipients
        const rcpt_lim = 3;
        var items = [];

        function getSelector(id) {
            var e = document.getElementById(id);
            return e.options[e.selectedIndex].value;
        }
        var compare = (getSelector("selSymOrder") === "score")
            ? function (e1, e2) {
                return Math.abs(e1.score) < Math.abs(e2.score);
            }
            : function (e1, e2) {
                return e1.name.localeCompare(e2.name);
            };

        $.each(data.rows,
          function (i, item) {
            function more(p) {
                const l = item[p].length;
                return (l > rcpt_lim) ? " … (" + l + ")" : "";
            }
            function format_rcpt(smtp, mime) {
                var full = shrt = "";
                if (smtp) {
                    full = "[" + item.rcpt_smtp.join(", ") + "] ";
                    shrt = "[" + item.rcpt_smtp.slice(0,rcpt_lim).join(",&#8203;") + more("rcpt_smtp")  + "]";
                    if (mime) {
                        full += " ";
                        shrt += " ";
                    }
                }
                if (mime) {
                    full += item.rcpt_mime.join(", ");
                    shrt += item.rcpt_mime.slice(0,rcpt_lim).join(",&#8203;") + more("rcpt_mime");
                }
                return {full: full, shrt: shrt};
            }

            preprocess_item(item);
            Object.keys(item.symbols).map(function(key) {
                var sym = item.symbols[key];

                if (sym.description) {
	                var str = '<strong><abbr data-sym-key="' + key + '">' + sym.name + '</abbr></strong>' + "(" + sym.score + ")";

	                // Store description for tooltip
	                symbolDescriptions[key] = sym.description;
                } else {
	                var str = '<strong>' + sym.name + '</strong>' + "(" + sym.score + ")";
                }

               if (sym.options) {
                   str += '[' + sym.options.join(",") + "]";
               }
               item.symbols[key].str = str;
            });
            item.symbols = Object.keys(item.symbols).
                map(function(key) {
                    return item.symbols[key];
                }).
                sort(compare).
                map(function(e) { return e.str; }).
                join("<br>\n");
            item.time = {
                "value": unix_time_format(item.unix_time),
                "options": {
                    "sortValue": item.unix_time
                }
            };
            var scan_time = item.time_real.toFixed(3) + ' / ' +
                item.time_virtual.toFixed(3);
            item.scan_time = {
                "options": {
                    "sortValue": item.time_real
                },
                "value": scan_time
            };
            item.id = item['message-id'];

            var rcpt = {};
            if (!item.rcpt_mime.length) {
                rcpt = format_rcpt(true, false);
            } else if ($(item.rcpt_mime).not(item.rcpt_smtp).length !== 0 || $(item.rcpt_smtp).not(item.rcpt_mime).length !== 0) {
                rcpt = format_rcpt(true, true);
            } else {
                rcpt = format_rcpt(false, true);
            }
            item.rcpt_mime_short = rcpt.shrt;
            item.rcpt_mime = rcpt.full;

            if (item.sender_mime !== item.sender_smtp) {
                item.sender_mime = "[" + item.sender_smtp + "] " + item.sender_mime;
            }
            items.push(item);
        });

        return items;
    }

    function process_history_legacy(data) {
        var items = [];

        $.each(data, function (i, item) {
            item.time = unix_time_format(item.unix_time);
            preprocess_item(item);
            item.scan_time = {
                "options": {
                    "sortValue": item.scan_time
                },
                "value": item.scan_time
            };
            item.time = {
                "value": unix_time_format(item.unix_time),
                "options": {
                    "sortValue": item.unix_time
                }
            };

            items.push(item)
        });

        return items;
    }

    function columns_v2() {
        return [{
                "name": "id",
                "title": "ID",
                "style": {
                    "font-size": "11px",
                    "minWidth": 130,
                    "overflow": "hidden",
                    "textOverflow": "ellipsis",
                    "wordBreak": "break-all",
                    "whiteSpace": "normal"
                }
            }, {
                "name": "ip",
                "title": "IP address",
                "breakpoints": "xs sm md",
                "style": {
                    "font-size": "11px",
                    "minWidth": 88
                }
            }, {
                "name": "sender_mime",
                "title": "[Envelope From] From",
                "breakpoints": "xs sm md",
                "style": {
                    "font-size": "11px",
                    "minWidth": 100,
                    "maxWidth": 200,
                    "word-wrap": "break-word"
                }
            }, {
                "name": "rcpt_mime_short",
                "title": "[Envelope To] To/Cc/Bcc",
                "breakpoints": "xs sm md",
                "style": {
                    "font-size": "11px",
                    "minWidth": 100,
                    "maxWidth": 200,
                    "word-wrap": "break-word"
                }
            }, {
                "name": "rcpt_mime",
                "title": "[Envelope To] To/Cc/Bcc",
                "breakpoints": "all",
                "style": {
                    "font-size": "11px",
                    "word-wrap": "break-word"
                }
            }, {
                "name": "subject",
                "title": "Subject",
                "breakpoints": "xs sm md",
                "style": {
                    "font-size": "11px",
                    "word-break": "break-all",
                    "minWidth": 150
                }
            }, {
                "name": "action",
                "title": "Action",
                "style": {
                    "font-size": "11px",
                    "minwidth": 82
                }
            }, {
                "name": "score",
                "title": "Score",
                "style": {
                    "font-size": "11px",
                    "maxWidth": 110
                },
                "sortValue": function(val) { return Number(val.options.sortValue); }
            }, {
                "name": "symbols",
                "title": "Symbols",
                "breakpoints": "all",
                "style": {
                    "font-size": "11px",
                    "width": 550,
                    "maxWidth": 550
                }
            }, {
                "name": "size",
                "title": "Msg size",
                "breakpoints": "xs sm md",
                "style": {
                    "font-size": "11px",
                    "minwidth": 50,
                },
                "formatter": Humanize.compactInteger
            }, {
                "name": "scan_time",
                "title": "Scan time",
                "breakpoints": "xs sm md",
                "style": {
                    "font-size": "11px",
                    "maxWidth": 72
                },
                "sortValue": function(val) { return Number(val.options.sortValue); }
            }, {
                "sorted": true,
                "direction": "DESC",
                "name": "time",
                "title": "Time",
                "style": {
                    "font-size": "11px"
                },
                "sortValue": function(val) { return Number(val.options.sortValue); }
            }, {
                "name": "user",
                "title": "Authenticated user",
                "breakpoints": "xs sm md",
                "style": {
                    "font-size": "11px",
                    "minWidth": 100,
                    "maxWidth": 130,
                    "word-wrap": "break-word"
                }
            }];
    }

    function columns_legacy() {
        return [{
                "name": "id",
                "title": "ID",
                "style": {
                    "font-size": "11px",
                    "width": 300,
                    "maxWidth": 300,
                    "overflow": "hidden",
                    "textOverflow": "ellipsis",
                    "wordBreak": "keep-all",
                    "whiteSpace": "nowrap"
                }
            }, {
                "name": "ip",
                "title": "IP address",
                "breakpoints": "xs sm",
                "style": {
                    "font-size": "11px",
                    "width": 150,
                    "maxWidth": 150
                }
            }, {
                "name": "action",
                "title": "Action",
                "style": {
                    "font-size": "11px",
                    "width": 110,
                    "maxWidth": 110
                }
            }, {
                "name": "score",
                "title": "Score",
                "style": {
                    "font-size": "11px",
                    "maxWidth": 110
                },
                "sortValue": function(val) { return Number(val.options.sortValue); }
            }, {
                "name": "symbols",
                "title": "Symbols",
                "breakpoints": "all",
                "style": {
                    "font-size": "11px",
                    "width": 550,
                    "maxWidth": 550
                }
            }, {
                "name": "size",
                "title": "Message size",
                "breakpoints": "xs sm",
                "style": {
                    "font-size": "11px",
                    "width": 120,
                    "maxWidth": 120
                },
                "formatter": Humanize.compactInteger
            }, {
                "name": "scan_time",
                "title": "Scan time",
                "breakpoints": "xs sm",
                "style": {
                    "font-size": "11px",
                    "maxWidth": 80
                },
                "sortValue": function(val) { return Number(val.options.sortValue); }
            }, {
                "sorted": true,
                "direction": "DESC",
                "name": "time",
                "title": "Time",
                "style": {
                    "font-size": "11px"
                },
                "sortValue": function(val) { return Number(val.options.sortValue); }
            }, {
                "name": "user",
                "title": "Authenticated user",
                "breakpoints": "xs sm",
                "style": {
                    "font-size": "11px",
                    "width": 200,
                    "maxWidth": 200
                }
            }];
    }

    var process_functions = {
       "2": process_history_v2,
       "legacy": process_history_legacy
    };

    var columns = {
       "2": columns_v2,
       "legacy": columns_legacy
    };

    function process_history_data(data) {
        var pf = process_functions.legacy;

        if (data.version) {
           var strkey = data.version.toString();
           if (process_functions[strkey]) {
               pf = process_functions[strkey];
           }
        }

        return pf(data);
    }

    function get_history_columns(data) {
        var func = columns.legacy;

        if (data.version) {
            var strkey = data.version.toString();
            if (columns[strkey]) {
                func = columns[strkey];
            }
        }

        return func();
    }

    interface.getHistory = function (rspamd, tables, neighbours, checked_server) {
        FooTable.actionFilter = FooTable.Filtering.extend({
        construct : function(instance) {
            this._super(instance);
            this.actions = [ 'reject', 'add header', 'greylist',
                    'no action', 'soft reject', 'rewrite subject' ];
            this.def = 'Any action';
            this.$action = null;
        },
        $create : function() {
            this._super();
            var self = this, $form_grp = $('<div/>', {
                'class' : 'form-group'
            }).append($('<label/>', {
                'class' : 'sr-only',
                text : 'Action'
            })).prependTo(self.$form);

            self.$action = $('<select/>', {
                'class' : 'form-control'
            }).on('change', {
                self : self
            }, self._onStatusDropdownChanged).append(
                    $('<option/>', {
                        text : self.def
                    })).appendTo($form_grp);

            $.each(self.actions, function(i, action) {
                self.$action.append($('<option/>').text(action));
            });
        },
        _onStatusDropdownChanged : function(e) {
            var self = e.data.self, selected = $(this).val();
            if (selected !== self.def) {
                if(selected === "reject"){
		  self.addFilter('action', 'reject -soft', [ 'action' ]);
                } else {
		  self.addFilter('action', selected, [ 'action' ]);
		}
            } else {
                self.removeFilter('action');
            }
            self.filter();
        },
        draw : function() {
            this._super();
            var action = this.find('action');
            if (action instanceof FooTable.Filter) {
                if(action.query.val() === 'reject -soft'){
                    this.$action.val('reject');
                } else {
                    this.$action.val(action.query.val());
                }
            } else {
                this.$action.val(this.def);
            }
        }
        });

        var drawTooltips = function() {
            // Update symbol description tooltips
            $.each(symbolDescriptions, function (key, description) {
                $('abbr[data-sym-key=' + key + ']').tooltip({
                    "placement": "bottom",
                    "html": true,
                    "title": description
                });
            });
        }

        if (checked_server === "All SERVERS") {
            rspamd.queryNeighbours("history", function (req_data) {
                function differentVersions() {
                    const dv = neighbours_data.some(function (e) {
                        return e.version !== neighbours_data[0].version;
                    });
                    if (dv) {
                        rspamd.alertMessage('alert-error',
                            'Neighbours history backend versions do not match. Cannot display history.');
                        return true;
                    }
                }

                var neighbours_data = req_data
                    .filter(function (d) { return d.status }) // filter out unavailable neighbours
                    .map(function (d){ return d.data; });
                if (neighbours_data.length && !differentVersions()) {
                    var data = {};
                    if (neighbours_data[0].version) {
                        data.rows = [].concat.apply([], neighbours_data
                            .map(function (e) {
                                return e.rows;
                            }));
                        data.version = neighbours_data[0].version;
                    }
                    else {
                        // Legacy version
                        data = [].concat.apply([], neighbours_data);
                    }

                    var items = process_history_data(data);
                    ft.history = FooTable.init("#historyTable", {
                        "columns": get_history_columns(data),
                        "rows": items,
                        "paging": {
                            "enabled": true,
                            "limit": 5,
                            "size": 25
                        },
                        "filtering": {
                            "enabled": true,
                            "position": "left",
                            "connectors": false
                        },
                        "sorting": {
                            "enabled": true
                        },
                        "components": {
                            "filtering": FooTable.actionFilter
                        },
                        "on": {
	                    "ready.ft.table": drawTooltips,
	                    "after.ft.sorting": drawTooltips,
	                    "after.ft.paging": drawTooltips,
	                    "after.ft.filtering": drawTooltips
                        }
                    });
                } else {
                    if (ft.history) {
                        ft.history.destroy();
                        ft.history = undefined;
                    }
                }
            });
        }
        else {
            $.ajax({
                dataType: 'json',
                url: neighbours[checked_server].url + 'history',
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', rspamd.getPassword());
                },
                error: function () {
                    rspamd.alertMessage('alert-error', 'Cannot receive history');
                },
                success: function (data) {
                    var items = process_history_data(data);
                    ft.history = FooTable.init("#historyTable", {
                        "columns": get_history_columns(data),
                        "rows": items,
                        "paging": {
                            "enabled": true,
                            "limit": 5,
                            "size": 25
                        },
                        "filtering": {
                            "enabled": true,
                            "position": "left",
                            "connectors": false
                        },
                        "sorting": {
                            "enabled": true
                        },
                        "components": {
                            "filtering": FooTable.actionFilter
                        },
                        "on": {
	                    "ready.ft.table": drawTooltips,
	                    "after.ft.sorting": drawTooltips,
	                    "after.ft.paging": drawTooltips,
	                    "after.ft.filtering": drawTooltips
                        }
                    });
                }
            });
        }
        $('#updateHistory').off('click');
        $('#updateHistory').on('click', function (e) {
            e.preventDefault();
            interface.getHistory(rspamd, tables, neighbours, checked_server);
        });
        $("#selSymOrder").unbind().change(function() {
            interface.getHistory(rspamd, tables, neighbours, checked_server);
        });

        // @reset history log
        $('#resetHistory').off('click');
        $('#resetHistory').on('click', function (e) {
            e.preventDefault();
            if (!confirm("Are you sure you want to reset history log?")) {
                return;
            }
            if (ft.history) {
                ft.history.destroy();
                ft.history = undefined;
            }
            if (ft.errors) {
                ft.errors.destroy();
                ft.errors = undefined;
            }
            if (checked_server === "All SERVERS") {
                rspamd.queryNeighbours("errors", function (data) {
                    interface.getHistory(rspamd, tables, neighbours, checked_server);
                    interface.getErrors(rspamd, tables, neighbours, checked_server);
                });
            }
            else {
                $.ajax({
                    dataType: 'json',
                    type: 'GET',
                    jsonp: false,
                    url: neighbours[checked_server].url + 'historyreset',
                    beforeSend: function (xhr) {
                        xhr.setRequestHeader('Password', rspamd.getPassword());
                    },
                    success: function () {
                        interface.getHistory(rspamd, tables, neighbours, checked_server);
                        interface.getErrors(rspamd, tables, neighbours, checked_server);
                    },
                    error: function (data) {
                        rspamd.alertMessage('alert-modal alert-error', data.statusText);
                    }
                });
            }
        });
    };

    function drawErrorsTable(data) {
        var items = [];
        $.each(data, function (i, item) {
            items.push(
                item.ts = unix_time_format(item.ts)
            );
        });
        ft.errors = FooTable.init("#errorsLog", {
            "columns": [
                {"sorted": true,"direction": "DESC","name":"ts","title":"Time","style":{"font-size":"11px","width":300,"maxWidth":300}},
                {"name":"type","title":"Worker type","breakpoints":"xs sm","style":{"font-size":"11px","width":150,"maxWidth":150}},
                {"name":"pid","title":"PID","breakpoints":"xs sm","style":{"font-size":"11px","width":110,"maxWidth":110}},
                {"name":"module","title":"Module","style":{"font-size":"11px"}},
                {"name":"id","title":"Internal ID","style":{"font-size":"11px"}},
                {"name":"message","title":"Message","breakpoints":"xs sm","style":{"font-size":"11px"}},
            ],
            "rows": data,
            "paging": {
                "enabled": true,
                "limit": 5,
                "size": 25
            },
            "filtering": {
                "enabled": true,
                "position": "left",
                "connectors": false
            },
            "sorting": {
                "enabled": true
            }
        });
    }

    interface.getErrors = function(rspamd, tables, neighbours, checked_server) {
        if (rspamd.read_only) return;

        if (checked_server !== "All SERVERS") {
            $.ajax({
                dataType: 'json',
                url: neighbours[checked_server].url + 'errors',
                jsonp: false,
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Password', rspamd.getPassword());
                },
                error: function () {
                    rspamd.alertMessage('alert-error', 'Cannot receive errors');
                },
                success: function (data) {
                    drawErrorsTable(data);
                }
            });
        } else {
            rspamd.queryNeighbours("errors", function (req_data) {
                var neighbours_data = req_data
                    .filter(function (d) {
                        return d.status
                    }) // filter out unavailable neighbours
                    .map(function (d) {
                        return d.data;
                    });
                drawErrorsTable([].concat.apply([], neighbours_data));
            });
        }
        $('#updateErrors').off('click');
        $('#updateErrors').on('click', function (e) {
            e.preventDefault();
            interface.getErrors(rspamd, tables, neighbours, checked_server);
        });
    };

    interface.setup = function(rspamd, tables) {
    };
    return interface;
});
