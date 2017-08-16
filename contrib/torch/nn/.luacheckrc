-- -*- mode: lua; -*-
std = "luajit"

globals = {
    "torch",
    "nn",
    "include",
}

unused_args = false


files['test.lua'].redefined = false
