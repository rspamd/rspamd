#!/usr/bin/env node
/* eslint-disable no-console */
/* global process */

/**
 * Reports available updates for the WebUI third-party dependencies:
 *
 *  - Vendored libraries (interface/js/lib, interface/css): the current
 *    version is read from the banner comment of files[0] and compared
 *    against the latest npm dist-tag or GitHub release.
 *  - npm packages (lint tooling, Font Awesome, ...): checked with the
 *    locally installed npm-check-updates ("--target latest" includes
 *    major updates).
 *
 * Informational only: always exits 0, a failed lookup degrades to an inline
 * error for that entry. The vendored-libraries section works without
 * node_modules; the npm section is then skipped with a hint.
 *
 * Usage:  npm run check:deps   (or: node webui-deps-check.mjs)
 */
import {existsSync, readFileSync} from "node:fs";
import {join} from "node:path";
import {spawnSync} from "node:child_process";

const ROOT = import.meta.dirname;

// One entry per vendored library: the version is read from the banner of
// files[0], the remaining files are updated together with it. Either "npm"
// (package name) or "repo" (GitHub owner/name) defines the upstream source.
const LIBS = [
    {
        files: ["interface/js/lib/bootstrap.bundle.min.js", "interface/css/bootstrap.min.css"],
        name: "bootstrap",
        npm: "bootstrap",
        regex: /Bootstrap v(\d+(?:\.\d+)*)/u,
    },
    {
        files: ["interface/js/lib/codejar.min.js"],
        name: "codejar",
        npm: "codejar",
        regex: /CodeJar (\d+(?:\.\d+)*)/u,
    },
    {
        files: ["interface/js/lib/codejar-linenumbers.min.js", "interface/css/codejar-linenumbers.css"],
        name: "codejar-linenumbers",
        npm: "codejar-linenumbers",
        regex: /codejar-linenumbers v(\d+(?:\.\d+)*)/u,
    },
    {
        files: ["interface/js/lib/d3.min.js"],
        name: "d3",
        npm: "d3",
        regex: /d3js\.org v(\d+(?:\.\d+)*)/u,
    },
    {
        files: ["interface/js/lib/d3evolution.min.js", "interface/css/d3evolution.css"],
        name: "d3evolution",
        note: "not on npm, latest from github.com/moisseev/D3Evolution",
        regex: /D3Evolution (\d+(?:\.\d+)*)/u,
        repo: "moisseev/D3Evolution",
    },
    {
        files: ["interface/js/lib/d3pie.min.js", "interface/css/d3pie.css"],
        name: "d3pie",
        note: "not on npm, latest from github.com/moisseev/rspamd-D3Pie",
        regex: /rspamd-D3Pie (\d+(?:\.\d+)*)/u,
        repo: "moisseev/rspamd-D3Pie",
    },
    {
        files: ["interface/js/lib/nprogress.min.js", "interface/css/nprogress.css"],
        name: "nprogress",
        npm: "nprogress",
        regex: /@version (\d+(?:\.\d+)*)/u,
    },
    {
        files: ["interface/js/lib/prism.js", "interface/css/prism.css"],
        name: "prismjs",
        note: "custom prismjs.com download build, not the npm tarball (URL in the prism.css banner)",
        npm: "prismjs",
        regex: /PrismJS (\d+(?:\.\d+)*)/u,
    },
    {
        files: ["interface/js/lib/require.min.js"],
        name: "requirejs",
        npm: "requirejs",
        regex: /RequireJS (\d+(?:\.\d+)*)/u,
    },
    {
        files: ["interface/js/lib/tabulator.min.js", "interface/css/tabulator_bs5.min.css"],
        name: "tabulator",
        npm: "tabulator-tables",
        regex: /Tabulator v(\d+(?:\.\d+)*)/u,
    },
    {
        files: ["interface/js/lib/visibility.min.js"],
        name: "visibilityjs",
        npm: "visibilityjs",
        regex: /Visibility\.js (\d+(?:\.\d+)*)/u,
    },
];

// Split a version into numeric segments, ignoring a leading "v" and any
// prerelease suffix (e.g. "v1.2.3-beta.1" -> [1, 2, 3]).
function versionParts(version) {
    const match = version.replace(/^v/u, "").match(/\d+(?:\.\d+)*/u);

    return match === null ? [] : match[0].split(".").map(Number);
}

// Compare two versions: negative if a < b, positive if a > b, 0 if equal.
function cmpVersions(a, b) {
    const va = versionParts(a);
    const vb = versionParts(b);

    for (let i = 0; i < Math.max(va.length, vb.length); i++) {
        const diff = (va[i] ?? 0) - (vb[i] ?? 0);
        if (diff !== 0) {
            return diff;
        }
    }
    return 0;
}

// Fetch a JSON document with a timeout. GITHUB_TOKEN is honoured for the
// GitHub API (raises the unauthenticated 60 requests/hour limit).
async function fetchJson(url) {
    const headers = {};
    if (url.startsWith("https://api.github.com/") && process.env.GITHUB_TOKEN) {
        headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    }
    const res = await fetch(url, {headers, signal: AbortSignal.timeout(15000)});
    if (!res.ok) {
        throw new Error(`HTTP ${res.status} from ${url}`);
    }
    return res.json();
}

// The "latest" dist-tag never points at a prerelease.
async function latestNpm(pkg) {
    const tags = await fetchJson(`https://registry.npmjs.org/-/package/${pkg}/dist-tags`);

    return tags.latest;
}

// The latest non-prerelease, non-draft GitHub release.
async function latestGitHub(repo) {
    const release = await fetchJson(`https://api.github.com/repos/${repo}/releases/latest`);

    return release.tag_name;
}

// Read the library version from the banner comment of files[0].
function readBannerVersion(lib) {
    const banner = readFileSync(join(ROOT, lib.files[0])).subarray(0, 1024).toString("utf8");
    const match = banner.match(lib.regex);
    if (match === null) {
        throw new Error(`version banner not found in ${lib.files[0]}`);
    }
    return match[1];
}

// Check one vendored library; never throws.
async function checkLib(lib) {
    try {
        const current = readBannerVersion(lib);
        const latest = lib.npm
            ? await latestNpm(lib.npm)
            : await latestGitHub(lib.repo);
        const status = cmpVersions(current, latest) < 0 ? "UPDATE" : "ok";

        return {current, latest, name: lib.name, note: lib.note, status};
    } catch (err) {
        return {current: "?", latest: "?", name: lib.name, note: `ERROR: ${err.message}`, status: "error"};
    }
}

// Render rows (arrays of strings) as an aligned plain-text table, without
// ANSI escapes so the output is safe to embed into job summaries.
function renderTable(headers, rows) {
    const widths = headers.map((header, i) => Math.max(header.length, ...rows.map((row) => row[i].length)));

    function line(cells) {
        console.log(cells.map((cell, i) => cell.padEnd(widths[i])).join("  ").trimEnd());
    }

    line(headers);
    for (const row of rows) {
        line(row);
    }
}

// Report updatable npm dependencies via the locally installed
// npm-check-updates. Skipped with a hint when node_modules is absent.
function npmSection() {
    console.log("npm dependencies (npm-check-updates --target latest)");

    const ncuDir = join(ROOT, "node_modules", "npm-check-updates");
    if (!existsSync(join(ncuDir, "package.json"))) {
        console.log("skipped: npm-check-updates is not installed, run \"npm ci\" first");
        return;
    }

    // Resolve the bin via the package manifest and spawn it with the node
    // executable: spawning the ".cmd" shim directly fails on Windows.
    const {bin} = JSON.parse(readFileSync(join(ncuDir, "package.json"), "utf8"));
    const res = spawnSync(process.execPath, [join(ncuDir, bin.ncu), "--target", "latest", "--jsonUpgraded"], {
        cwd: ROOT,
        encoding: "utf8",
    });
    if (res.error) {
        console.log(`ERROR: ${res.error.message}`);
        return;
    }
    if (res.status !== 0) {
        console.log(`ERROR: npm-check-updates exited with ${res.status}${res.stderr ? `: ${res.stderr.trim()}` : ""}`);
        return;
    }

    const upgraded = JSON.parse(res.stdout);
    const names = Object.keys(upgraded).sort();
    if (names.length === 0) {
        console.log("All dependencies are up to date.");
        return;
    }

    const pkgJson = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
    const ranges = {...pkgJson.dependencies, ...pkgJson.devDependencies};
    renderTable(["package", "current", "latest"], names.map((name) => [name, ranges[name] ?? "?", upgraded[name]]));

    const total = Object.keys(ranges).length;
    console.log(`\n${names.length} of ${total} dependencies can be updated.`);
}

async function main() {
    console.log("Vendored WebUI libraries (interface/js/lib, interface/css)\n");
    const rows = await Promise.all(LIBS.map((lib) => checkLib(lib)));
    renderTable(["library", "current", "latest", "status"], rows.map((row) => [
        row.name,
        row.current,
        row.latest,
        row.status + (row.note ? "  (*)" : ""),
    ]));

    const notes = rows.filter((row) => row.note);
    if (notes.length) {
        console.log("\nNotes:");
        for (const row of notes) {
            console.log(`- ${row.name}: ${row.note}`);
        }
    }

    console.log();
    npmSection();
}

main();
