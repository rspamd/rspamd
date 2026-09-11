import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

// The fuzzy table joins /stat's fuzzy_hashes (rule name -> hash count)
// with the plugins/fuzzy/storages config (read_only, server addresses,
// symbol/flag map) fetched once per page load. The mocking follows
// cluster.spec: the /neighbours map points at path prefixes on the same
// origin (keeps the Password-header XHRs free of CORS), and every /n<N>/stat
// reply is the real /stat body with fuzzy_hashes injected, so the schema
// stays in sync with the backend.
test("fuzzy table: per-server join, tooltips, read-only badge, raw numbers", async ({page, request}, testInfo) => {
    const {enablePassword, readOnlyPassword} = testInfo.project.use.rspamdPasswords;
    const baseStat = await (await request.get("/stat", {headers: {Password: readOnlyPassword}})).json();

    // n1: a unified servers list and a read-only rule; "local<b>" is absent
    // from the storages reply — escaping canary and missing-rule fallback in
    // one; "down.example" is configured but absent from fuzzy_hashes — the
    // unavailable row; "empty.example" reports a zero count — must render as
    // a plain 0, not unavailable. n2: the same rule name with different
    // addresses and flags — the join must not mix the two servers' configs.
    const fuzzyHashes = {
        n1: {"rspamd.com": 1234567, "local<b>": 7, "empty.example": 0},
        n2: {"rspamd.com": 42},
    };
    const storages = {
        n1: {
            "down.example": {
                flags: {RW_BL_2: 2},
                read_only: false,
                servers: ["fuzzy9.example.com:11335"]
            },
            "empty.example": {
                flags: {RW_WL_1: 3},
                read_only: false,
                servers: ["fuzzy2.example.com:11335"]
            },
            "rspamd.com": {
                flags: {FUZZY_DENIED: 1, FUZZY_PROB: 2},
                read_only: true,
                servers: ["fuzzy1.rspamd.com:11335"]
            }
        },
        n2: {
            "rspamd.com": {
                flags: {FUZZY_DENIED: 5},
                read_only: false,
                read_servers: ["127.0.0.1:11335"],
                write_servers: ["10.0.0.1:11335"]
            }
        }
    };

    await page.route("**/neighbours", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
            srv1: {host: "127.0.0.1", url: "http://localhost:11334/n1/"},
            srv2: {host: "127.0.0.1", url: "http://localhost:11334/n2/"},
        }),
    }));
    for (const n of ["n1", "n2"]) {
        await page.route(`**/${n}/stat`, (route) => route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({...baseStat, fuzzy_hashes: fuzzyHashes[n]}),
        }));
        // The login-time auth fan-out and the health probes must not 404
        for (const ep of ["auth", "healthy", "ready"]) {
            await page.route(`**/${n}/${ep}`, (route) => route.fulfill({
                status: 200,
                contentType: "application/json",
                body: JSON.stringify(ep === "auth"
                    ? {auth: "ok", version: baseStat.version}
                    : {}),
            }));
        }
        await page.route(`**/${n}/plugins/fuzzy/storages`, (route) => route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({storages: storages[n], success: true}),
        }));
    }

    // The login-time sticky-tabs activation of the status tab already runs
    // the first /stat cycle, so the storages probe may answer before this
    // test could observe the navBar — arm the listener before logging in
    const n1Storages = page.waitForResponse((r) => r.url().includes("/n1/plugins/fuzzy/storages"));
    await login(page, enablePassword);
    await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});
    // The storages config lands after the /stat render (second pass)
    await Promise.all([
        n1Storages,
        page.locator("#status_nav").click(),
    ]);

    const rows = page.locator("#fuzzyTable tbody tr");
    await expect(rows).toHaveCount(5);

    // Rowspan server cell on the first row of each group only; the rule
    // missing from the storages reply renders as text (escaping) and keeps
    // its raw count without a tooltip
    await expect(rows.nth(0).locator("td").nth(0)).toHaveText("srv1");
    await expect(rows.nth(0).locator("td").nth(0)).toHaveAttribute("rowspan", "4");
    await expect(rows.nth(1).locator("td").nth(0)).toHaveText("local<b>");
    await expect(rows.nth(1).locator("td").nth(0)).not.toHaveAttribute("title");
    await expect(rows.nth(4).locator("td").nth(0)).toHaveText("srv2");

    // A healthy storage with zero hashes renders a plain raw 0 — not an
    // unavailable row
    await expect(rows.nth(2).locator("td").nth(0)).toHaveText("empty.example");
    await expect(rows.nth(2).locator("td").nth(1)).toHaveText("0");
    await expect(rows.nth(2).locator(".badge")).toHaveCount(0);

    // One read-only badge (n1's rspamd.com) and one unavailable badge
    // (n1's down.example) — no badges for n2
    await expect(page.locator("#fuzzyTable .badge")).toHaveCount(2);
    await expect(rows.nth(0).locator(".badge")).toHaveText("read-only");
    await expect(rows.nth(0).locator(".badge"))
        .toHaveAttribute("title", "Storage is read-only: it cannot be learned to");
    await expect(rows.nth(3).locator(".badge")).toHaveText("unavailable");
    await expect(rows.nth(3).locator(".badge")).toHaveAttribute("title",
        "No reply to the statistics query; the storage may be down, rate-limited or access denied");

    // The configured-but-unreported rule keeps its config tooltip and
    // renders "-" instead of a count
    await expect(rows.nth(3).locator("td").nth(0)).toHaveAttribute("title",
        "Servers: fuzzy9.example.com:11335\nSymbols:\nRW_BL_2 (2)");
    await expect(rows.nth(3).locator("td").nth(1)).toHaveText("-");

    // n1: unified servers list plus the symbol/flag mapping in the tooltip
    await expect(rows.nth(0).locator("td").nth(1)).toHaveAttribute("title",
        "Servers: fuzzy1.rspamd.com:11335\nSymbols:\nFUZZY_DENIED (1)\nFUZZY_PROB (2)");

    // n2: its own split read/write lists and flags — no cross-server mixing
    await expect(rows.nth(4).locator("td").nth(1)).toHaveAttribute("title",
        "Read: 127.0.0.1:11335\nWrite: 10.0.0.1:11335\nSymbols:\nFUZZY_DENIED (5)");

    // Raw, copyable counts — no locale formatting
    await expect(rows.nth(0).locator("td").nth(2)).toHaveText("1234567");
    await expect(rows.nth(1).locator("td").nth(1)).toHaveText("7");
    await expect(rows.nth(4).locator("td").nth(2)).toHaveText("42");

    // Header tooltips, as in the bayes table
    const headers = page.locator("#fuzzyTable thead th");
    await expect(headers).toHaveCount(3);
    for (let i = 0; i < 3; i++) {
        await expect(headers.nth(i)).toHaveAttribute("title", /.+/);
    }
});

// An up server without fuzzy storages keeps its placeholder row, and a
// missing storages endpoint (older rspamd, fuzzy_check disabled) degrades
// silently: plain rows, no error-log badge.
test("fuzzy table: empty state and storages endpoint degradation", async ({page, request}, testInfo) => {
    const {enablePassword, readOnlyPassword} = testInfo.project.use.rspamdPasswords;
    const baseStat = await (await request.get("/stat", {headers: {Password: readOnlyPassword}})).json();

    const statNoFuzzy = {...baseStat};
    delete statNoFuzzy.fuzzy_hashes;

    await page.route("**/neighbours", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
            srv1: {host: "127.0.0.1", url: "http://localhost:11334/n1/"},
            srv2: {host: "127.0.0.1", url: "http://localhost:11334/n2/"},
        }),
    }));
    await page.route("**/n1/stat", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(statNoFuzzy),
    }));
    await page.route("**/n2/stat", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({...baseStat, fuzzy_hashes: {"rspamd.com": 42}}),
    }));
    for (const n of ["n1", "n2"]) {
        for (const ep of ["auth", "healthy", "ready"]) {
            await page.route(`**/${n}/${ep}`, (route) => route.fulfill({
                status: 200,
                contentType: "application/json",
                body: JSON.stringify(ep === "auth"
                    ? {auth: "ok", version: baseStat.version}
                    : {}),
            }));
        }
        await page.route(`**/${n}/plugins/fuzzy/storages`, (route) => route.fulfill({
            status: 404,
            contentType: "application/json",
            body: JSON.stringify({error: "fuzzy_check is not enabled"}),
        }));
    }

    // Arm before logging in: the storages probe may answer during the
    // login-time status activation (see the first test)
    const n1Storages = page.waitForResponse((r) => r.url().includes("/n1/plugins/fuzzy/storages"));
    await login(page, enablePassword);
    await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});
    await Promise.all([
        n1Storages,
        page.locator("#status_nav").click(),
    ]);

    // The server without fuzzy hashes stays visible with a spanning
    // placeholder; the other one renders its plain hash count
    const rows = page.locator("#fuzzyTable tbody tr");
    await expect(rows).toHaveCount(2);
    await expect(rows.nth(0).locator("td").nth(0)).toHaveText("srv1");
    await expect(rows.nth(0).locator('td[colspan="2"]')).toHaveText("No fuzzy storages");
    await expect(rows.nth(1).locator("td").nth(1)).toHaveText("rspamd.com");
    await expect(rows.nth(1).locator("td").nth(2)).toHaveText("42");

    // Silent degradation: no badges, no tooltips, no error-log badge
    await expect(page.locator("#fuzzyTable .badge")).toHaveCount(0);
    await expect(rows.nth(1).locator("td").nth(1)).not.toHaveAttribute("title");
    await expect(page.locator("#error-log-badge")).toHaveClass(/\bd-none\b/);
});

// A neighbour that was down at page load and recovers with the same
// config_id must get its storages metadata on a later refresh cycle: the
// cache signature tracks the up/down state, not just the configuration.
test("fuzzy table: a recovered neighbour gets its storages", async ({page, request}, testInfo) => {
    const {enablePassword, readOnlyPassword} = testInfo.project.use.rspamdPasswords;
    const baseStat = await (await request.get("/stat", {headers: {Password: readOnlyPassword}})).json();

    let n2Up = false;
    await page.route("**/neighbours", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
            srv1: {host: "127.0.0.1", url: "http://localhost:11334/n1/"},
            srv2: {host: "127.0.0.1", url: "http://localhost:11334/n2/"},
        }),
    }));
    await page.route("**/n1/stat", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({...baseStat, fuzzy_hashes: {"rspamd.com": 1234567}}),
    }));
    await page.route("**/n2/stat", (route) => {
        if (!n2Up) return route.fulfill({status: 503, contentType: "application/json", body: "{}"});
        return route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({...baseStat, fuzzy_hashes: {"rspamd.com": 42}}),
        });
    });
    for (const n of ["n1", "n2"]) {
        for (const ep of ["auth", "healthy", "ready"]) {
            await page.route(`**/${n}/${ep}`, (route) => route.fulfill({
                status: 200,
                contentType: "application/json",
                body: JSON.stringify(ep === "auth"
                    ? {auth: "ok", version: baseStat.version}
                    : {}),
            }));
        }
    }
    await page.route("**/n1/plugins/fuzzy/storages", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
            storages: {
                "rspamd.com": {
                    flags: {FUZZY_DENIED: 1},
                    read_only: true,
                    servers: ["fuzzy1.rspamd.com:11335"]
                }
            },
            success: true
        }),
    }));
    await page.route("**/n2/plugins/fuzzy/storages", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
            storages: {
                "rspamd.com": {
                    flags: {FUZZY_DENIED: 5},
                    read_only: true,
                    read_servers: ["127.0.0.1:11335"],
                    write_servers: ["10.0.0.1:11335"]
                }
            },
            success: true
        }),
    }));

    const n1Storages = page.waitForResponse((r) => r.url().includes("/n1/plugins/fuzzy/storages"));
    await login(page, enablePassword);
    await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});
    await Promise.all([
        n1Storages,
        page.locator("#status_nav").click(),
    ]);

    // While n2 is down only n1 renders, with its storages metadata
    const rows = page.locator("#fuzzyTable tbody tr");
    await expect(rows).toHaveCount(1);
    await expect(rows.nth(0).locator("td").nth(1))
        .toHaveAttribute("title", "Servers: fuzzy1.rspamd.com:11335\nSymbols:\nFUZZY_DENIED (1)");
    await expect(page.locator("#fuzzyTable .badge")).toHaveCount(1);

    // n2 recovers with the same config_id; the manual refresh runs a new
    // cycle whose changed up-set must refetch the storages config. Arm the
    // listener before flipping the state so no fetch can slip past it
    const n2Storages = page.waitForResponse((r) => r.url().includes("/n2/plugins/fuzzy/storages"));
    n2Up = true;
    await Promise.all([
        n2Storages,
        page.locator("#refresh").click(),
    ]);
    await expect(rows).toHaveCount(2);
    await expect(rows.nth(1).locator("td").nth(1)).toHaveAttribute("title",
        "Read: 127.0.0.1:11335\nWrite: 10.0.0.1:11335\nSymbols:\nFUZZY_DENIED (5)");
    await expect(page.locator("#fuzzyTable .badge")).toHaveCount(2);
});
