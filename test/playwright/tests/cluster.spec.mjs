import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

// The Git ID column lights up only when some server reports git_id in /stat.
// CI builds pass no -DGIT_ID (that hidden path is asserted in charts.spec),
// so the positive path is exercised against a mocked 3-server cluster: the
// /neighbours map points at path prefixes on the same origin (keeps the
// Password-header XHRs free of CORS), and every /n<N>/stat reply is the real
// /stat body with git_id injected, so the schema stays in sync with the
// backend.
test("Git ID column: values, drift badge, details colspan", async ({page, request}, testInfo) => {
    const {enablePassword, readOnlyPassword} = testInfo.project.use.rspamdPasswords;
    const baseStat = await (await request.get("/stat", {headers: {Password: readOnlyPassword}})).json();

    const git = {n1: "a1b2c3d", n2: "a1b2c3d", n3: "e5f6a7b<b>x</b>"}; // n3: deviant + escaping canary
    await page.route("**/neighbours", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
            srv1: {host: "127.0.0.1", url: "http://localhost:11334/n1/"},
            srv2: {host: "127.0.0.1", url: "http://localhost:11334/n2/"},
            srv3: {host: "127.0.0.1", url: "http://localhost:11334/n3/"},
        }),
    }));
    for (const n of Object.keys(git)) {
        await page.route(`**/${n}/stat`, (route) => route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({...baseStat, git_id: git[n]}),
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
    }

    await login(page, enablePassword);
    await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});
    await Promise.all([
        page.waitForResponse((r) => r.url().includes("/n3/stat")),
        page.locator("#status_nav").click(),
    ]);

    // Column visible; n3's value rendered as text (proves escaping: broken
    // escapeHTML would parse <b> as an element and drop it from innerText)
    await expect(page.locator("#clusterTable thead th.cluster-git")).toBeVisible();
    await expect(page.locator('tr[data-server="srv1"] td.cluster-git')).toHaveText("a1b2c3d");
    await expect(page.locator('tr[data-server="srv3"] td.cluster-git')).toContainText("e5f6a7b<b>x</b>");

    // Identical versions and config ids: the git drift badge marks the
    // deviant and the aggregate row alike (its majority value is not
    // cluster-wide)
    await expect(page.locator("#clusterTable .cluster-drift")).toHaveCount(2);
    await expect(page.locator('tr[data-server="srv3"] td.cluster-git .cluster-drift'))
        .toHaveAttribute("title", "Git ID differs: 2 of 3 servers run a1b2c3d");
    await expect(page.locator('tr[data-server="All SERVERS"] td.cluster-git .cluster-drift'))
        .toHaveAttribute("title", "Git ID differs: 2 of 3 servers run a1b2c3d");

    // All up: green aggregate row carrying the up-counter and the majority
    // git value
    await expect(page.locator('tr[data-server="All SERVERS"]')).toHaveClass(/\bsuccess\b/);
    await expect(page.locator('tr[data-server="All SERVERS"] td.cluster-status'))
        .toContainText("3/3");
    await expect(page.locator('tr[data-server="All SERVERS"] td.cluster-git'))
        .toContainText("a1b2c3d");

    // The details row spans all 12 visible columns
    await page.locator('tr[data-server="srv1"] td').nth(2).click();
    await expect(page.locator("#clusterTable tr.cluster-details td").first())
        .toHaveAttribute("colspan", "12");
});

// The "All SERVERS" row shows majority identity values (not the first
// neighbour's), the youngest uptime, the cluster-wide scan-time envelope and
// the slowest server latency, and expands into summed traffic/memory totals.
// Same mocking scheme as the Git ID test above.
test("All SERVERS row aggregates identity, uptime, scan time and latency", async ({page, request}, testInfo) => {
    const {enablePassword, readOnlyPassword} = testInfo.project.use.rspamdPasswords;
    const baseStat = await (await request.get("/stat", {headers: {Password: readOnlyPassword}})).json();

    // n3 deviates on version and config id; its uptime is the youngest
    const variations = {
        n1: {config_id: "cafebabedeadbeef", scan_times: Array(31).fill(1.0), uptime: 7200, version: "9.9.9"},
        n2: {config_id: "cafebabedeadbeef", scan_times: Array(31).fill(2.0), uptime: 90000, version: "9.9.9"},
        n3: {config_id: "0123456789abcdef", scan_times: Array(31).fill(3.0), uptime: 60, version: "8.8.8"},
    };
    await page.route("**/neighbours", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
            srv1: {host: "127.0.0.1", url: "http://localhost:11334/n1/"},
            srv2: {host: "127.0.0.1", url: "http://localhost:11334/n2/"},
            srv3: {host: "127.0.0.1", url: "http://localhost:11334/n3/"},
        }),
    }));
    for (const [n, stat] of Object.entries(variations)) {
        const statBody = {...baseStat, ...stat};
        // No git_id: the Git ID column stays hidden regardless of the
        // underlying build, so the details row spans a fixed 11 columns
        delete statBody.git_id;
        await page.route(`**/${n}/stat`, (route) => route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify(statBody),
        }));
        // The login-time auth fan-out and the health probes must not 404
        for (const ep of ["auth", "healthy", "ready"]) {
            await page.route(`**/${n}/${ep}`, (route) => route.fulfill({
                status: 200,
                contentType: "application/json",
                body: JSON.stringify(ep === "auth"
                    ? {auth: "ok", version: stat.version}
                    : {}),
            }));
        }
    }

    await login(page, enablePassword);
    await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});
    await Promise.all([
        page.waitForResponse((r) => r.url().includes("/n3/stat")),
        page.locator("#status_nav").click(),
    ]);

    const allRow = page.locator('tr[data-server="All SERVERS"]');

    // Majority version and configuration id, each with the drift badge
    await expect(allRow.locator("td").nth(9)).toHaveText("9.9.9");
    await expect(allRow.locator("td").nth(9).locator(".cluster-drift"))
        .toHaveAttribute("title", "Version differs: 2 of 3 servers run 9.9.9");
    await expect(allRow.locator("td").nth(11)).toHaveText("cafebabe");
    await expect(allRow.locator("td").nth(11).locator(".cluster-drift"))
        .toHaveAttribute("title", "Configuration ID differs: 2 of 3 servers share cafebabe");

    // Youngest uptime (n3: 60 s), flagged as a recent restart
    await expect(allRow.locator("td").nth(8)).toHaveText("1min");
    await expect(allRow.locator("td").nth(8)).toHaveClass(/\bwarning\b/);
    await expect(allRow.locator("td").nth(8))
        .toHaveAttribute("title", "Youngest server has been restarted within the last hour");

    // Cluster scan-time envelope: min of mins / mean of means / max of maxes
    await expect(allRow.locator("td").nth(5)).toHaveText("1.000/2.000/3.000");
    await expect(allRow.locator("td").nth(5)).toHaveAttribute("title", "min/avg/max across servers");

    // Slowest server latency and the summed load tooltip
    await expect(allRow.locator("td").nth(7)).toHaveText(/^[\d.]+ (ms|s)$/);
    await expect(allRow.locator("td").nth(7)).toHaveAttribute("title", "Slowest server response");
    await expect(allRow.locator("td").nth(6))
        .toHaveAttribute("title", "Sum of messages scanned per minute across servers");

    // The uptime/version widgets mirror the aggregate semantics
    await expect(page.locator('#statWidgets [title="Minimum uptime across servers"]'))
        .toContainText("1min");
    await expect(page.locator('#statWidgets [title="Most common version across servers"]'))
        .toContainText("9.9.9");

    // The aggregate row expands into summed traffic and memory totals
    await allRow.locator("td").nth(2).click();
    const details = page.locator("#clusterTable tr.cluster-details").first();
    await expect(details).toBeVisible();
    await expect(details.locator("td")).toHaveAttribute("colspan", "11");
    await expect(details).toContainText("Traffic");
    await expect(details).toContainText("Memory");
    await expect(details).toContainText(
        (baseStat.scanned * 3).toLocaleString("en-US"));
});

// A down neighbour turns the "All SERVERS" row amber with an up/total counter,
// while the aggregates stay over the servers that still answer.
test("All SERVERS row reflects a down neighbour", async ({page, request}, testInfo) => {
    const {enablePassword, readOnlyPassword} = testInfo.project.use.rspamdPasswords;
    const baseStat = await (await request.get("/stat", {headers: {Password: readOnlyPassword}})).json();

    const variations = {
        n1: {config_id: "cafebabedeadbeef", uptime: 7200, version: "9.9.9"},
        n2: {config_id: "cafebabedeadbeef", uptime: 90000, version: "9.9.9"},
    };
    await page.route("**/neighbours", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
            srv1: {host: "127.0.0.1", url: "http://localhost:11334/n1/"},
            srv2: {host: "127.0.0.1", url: "http://localhost:11334/n2/"},
            srv3: {host: "127.0.0.1", url: "http://localhost:11334/n3/"},
        }),
    }));
    for (const [n, stat] of Object.entries(variations)) {
        await page.route(`**/${n}/stat`, (route) => route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({...baseStat, ...stat}),
        }));
        for (const ep of ["auth", "healthy", "ready"]) {
            await page.route(`**/${n}/${ep}`, (route) => route.fulfill({
                status: 200,
                contentType: "application/json",
                body: JSON.stringify(ep === "auth"
                    ? {auth: "ok", version: stat.version}
                    : {}),
            }));
        }
    }
    await page.route("**/n3/stat", (route) => route.fulfill({status: 503}));
    await page.route("**/n3/auth", (route) => route.fulfill({status: 503}));

    await login(page, enablePassword);
    await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});
    await Promise.all([
        page.waitForResponse((r) => r.url().includes("/n2/stat")),
        page.locator("#status_nav").click(),
    ]);

    // srv3 renders as down
    await expect(page.locator('tr[data-server="srv3"]')).toHaveClass(/\bdanger\b/);

    // The aggregate row: amber, counter, reason in the tooltip
    const allRow = page.locator('tr[data-server="All SERVERS"]');
    await expect(allRow).toHaveClass(/\bwarning\b/);
    await expect(allRow.locator("td.cluster-status")).toContainText("2/3");
    await expect(allRow.locator("td.cluster-status"))
        .toHaveAttribute("title", "1 of 3 servers down");

    // Aggregates span the up servers only: unanimous version, youngest of
    // the two uptimes (2 h), no drift badges
    await expect(allRow.locator("td").nth(9)).toHaveText("9.9.9");
    await expect(allRow.locator("td").nth(8)).toHaveText("2hr 0min");
    await expect(allRow.locator("td").nth(8)).toHaveAttribute("title", "Minimum uptime across servers");
    await expect(page.locator("#clusterTable .cluster-drift")).toHaveCount(0);
});

// A fully down cluster never renders the aggregate row: the fan-out fires
// success only when at least one neighbour answers, so the table keeps its
// initial empty state instead of a fake-green "All SERVERS" row. The waits
// run before the assertion so the completed failure path, not a slow fan-out,
// is what gets checked.
test("All SERVERS row not rendered when all neighbours are down", async ({page}, testInfo) => {
    const {enablePassword} = testInfo.project.use.rspamdPasswords;

    await page.route("**/neighbours", (route) => route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
            srv1: {host: "127.0.0.1", url: "http://localhost:11334/n1/"},
            srv2: {host: "127.0.0.1", url: "http://localhost:11334/n2/"},
            srv3: {host: "127.0.0.1", url: "http://localhost:11334/n3/"},
        }),
    }));
    for (const n of ["n1", "n2", "n3"]) {
        await page.route(`**/${n}/stat`, (route) => route.fulfill({status: 503}));
        for (const ep of ["auth", "healthy", "ready"]) {
            await page.route(`**/${n}/${ep}`, (route) => route.fulfill({
                status: 200,
                contentType: "application/json",
                body: "{}",
            }));
        }
    }

    await login(page, enablePassword);
    await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});
    await Promise.all([
        page.waitForResponse((r) => r.url().includes("/n1/stat")),
        page.waitForResponse((r) => r.url().includes("/n2/stat")),
        page.waitForResponse((r) => r.url().includes("/n3/stat")),
        page.locator("#status_nav").click(),
    ]);

    // Every neighbour failed: nothing renders, the synthetic row included
    await expect(page.locator("#clusterTable tbody tr")).toHaveCount(0);
});
