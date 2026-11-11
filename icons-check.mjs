#!/usr/bin/env node
/* eslint-disable no-console */
/* global process */

/**
 * Verifies the Font Awesome icon subset is in sync with the markup: every
 * fa-<name> referenced in the WebUI must be listed in icons-manifest.txt,
 * otherwise it renders as an empty <use>.
 *
 * Run in CI (after "npm ci") to catch icons added to the markup but missing
 * from the manifest. "npm run check:icons" additionally rebuilds and diffs
 * icons.svg/icons.css to catch stale generated files.
 */
import {dirname, join} from "node:path";
import {readFileSync, readdirSync} from "node:fs";
import {fileURLToPath} from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const MANIFEST = join(ROOT, "icons-manifest.txt");
const APP_DIR = join(ROOT, "interface", "js", "app");

// App code that references icons by class (excludes vendored js/lib).
const sources = [
    join(ROOT, "interface", "index.html"),
    ...readdirSync(APP_DIR)
        .filter((file) => file.endsWith(".js"))
        .map((file) => join(APP_DIR, file)),
];

// fa-* tokens that are not icon names (style prefixes, modifiers, utilities).
const nonIcons = new Set([
    "border",
    "bounce",
    "brands",
    "fade",
    "flip",
    "flip-horizontal",
    "flip-vertical",
    "fw",
    "inverse",
    "lg",
    "pulse",
    "pull-left",
    "pull-right",
    "regular",
    "sm",
    "solid",
    "spin",
    "stack",
    "stack-1x",
    "stack-2x",
    "xs",
]);

const iconClass = /\bfa-([a-z][a-z0-9-]+)\b/gu;

function readManifest(path) {
    return new Set(readFileSync(path, "utf8")
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#")));
}

const manifest = readManifest(MANIFEST);
const used = new Set();

for (const file of sources) {
    const text = readFileSync(file, "utf8");
    for (const match of text.matchAll(iconClass)) {
        const [, name] = match;
        if (!nonIcons.has(name)) {
            used.add(name);
        }
    }
}

const missing = [...used].filter((name) => !manifest.has(name)).sort();
const unused = [...manifest].filter((name) => !used.has(name)).sort();

if (missing.length) {
    console.error("Icons used in the markup but missing from icons-manifest.txt (would render empty):");
    for (const name of missing) {
        console.error(`  fa-${name}`);
    }
}
if (unused.length) {
    console.warn("Icons in icons-manifest.txt but not referenced in the markup (consider removing):");
    for (const name of unused) {
        console.warn(`  fa-${name}`);
    }
}
if (missing.length) {
    process.exit(1);
}
console.log(`icons-manifest.txt in sync: ${used.size} icons used, ${manifest.size} listed.`);
