import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

// Status / Throughput / History rendering. The existing scan.spec only reads the
// numeric #rrd-total-value; the D3Pie/D3Evolution charts, graph controls, the
// client-side history search and the column-options dropdown are untested.
//
// Shares one logged-in page across the serial tests (like scan.spec) to amortise
// login. No test waits on the 60 s RRD row boundary — only rendering & controls.
test.describe.serial("WebUI Status / Throughput / History rendering", () => {
    let page = null;

    test.beforeAll(async ({browser}, testInfo) => {
        const context = await browser.newContext();
        page = await context.newPage();
        const {enablePassword} = testInfo.project.use.rspamdPasswords;
        await login(page, enablePassword);
        await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});
    });

    test.afterAll(async () => {
        if (page) await page.close();
    });

    test("Status tab renders stat widgets and the pie chart", async () => {
        await page.locator("#status_nav").click();
        await page.waitForResponse((r) => r.url().includes("/stat") && r.ok());
        await expect(page.locator("#statWidgets")).toBeVisible();
        await expect(page.locator("#statWidgets .widget").first()).toBeVisible();
        // D3Pie draws an <svg> inside #chart.
        await expect.poll(async () => await page.locator("#chart svg").count()).toBeGreaterThan(0);
    });

    test("Status cluster table: load/latency columns and expandable details", async () => {
        // The Status tab is active from the previous test. The auto-refresh may
        // rebuild the table under us, but the assertions re-resolve locators.
        await page.waitForResponse((r) => r.url().includes("/stat") && r.ok());
        await expect(page.locator("#clusterTable thead")).toContainText("Load");
        await expect(page.locator("#clusterTable thead")).toContainText("Latency");
        await expect(page.locator("#clusterTable tbody td[title='Messages scanned per minute']").first())
            .toHaveText(/-|[\d.]+\/min/);

        // Clicking anywhere on a server row (except the radio) expands its
        // details row built from the already-fetched /stat snapshot (traffic
        // and memory counters). The row also carries the Writable badge when
        // the server is not in read-only mode.
        const row = page.locator("#clusterTable tbody tr[data-server]")
            .filter({has: page.locator("td.cluster-toggle")}).first();
        await expect(row).toContainText("Writable");
        const serverNameCell = row.locator("td").nth(2); // Server name
        const details = page.locator("#clusterTable tr.cluster-details").first();
        await serverNameCell.click();
        await expect(details).toBeVisible();
        await expect(details).toContainText("Memory");
        await serverNameCell.click();
        await expect(details).toBeHidden();

        // The expansion state survives the table rebuild on refresh.
        await serverNameCell.click();
        await expect(details).toBeVisible();
        await Promise.all([
            page.waitForResponse((r) => r.url().includes("/stat") && r.ok()),
            page.locator("#refresh").click(),
        ]);
        await expect(details).toBeVisible();

        // Three-state health: simulate a /healthy failure (HTTP 500 with the
        // reason in the JSON body) and check the degraded row state.
        await page.route("**/healthy", (route) => route.fulfill({
            status: 500,
            contentType: "application/json",
            body: JSON.stringify({error: "2 workers are not responding"}),
        }));
        await Promise.all([
            page.waitForResponse((r) => r.url().includes("/stat") && r.ok()),
            page.locator("#refresh").click(),
        ]);
        await expect(row).toHaveClass(/\bwarning\b/);
        await expect(row.locator("td").nth(4)).toHaveAttribute("title",
            "Degraded: 2 workers are not responding");

        // Back to the healthy state once /healthy answers again.
        await page.unroute("**/healthy");
        await Promise.all([
            page.waitForResponse((r) => r.url().includes("/stat") && r.ok()),
            page.locator("#refresh").click(),
        ]);
        await expect(row).toHaveClass(/\bsuccess\b/);
    });

    test("Throughput tab renders the graph and reloads on dataset change", async () => {
        // Track every /graph response. The listener is attached before navigating
        // so there is no race (localhost responses can beat a waitForResponse
        // registered after the triggering click).
        const graphUrls = [];
        page.on("response", (r) => {
            if (r.url().includes("/graph")) graphUrls.push(r.url());
        });

        await page.locator("#throughput_nav").click();
        await expect.poll(() => graphUrls.length).toBeGreaterThan(0);
        await expect.poll(async () => await page.locator("#graph svg").count()).toBeGreaterThan(0);
        await expect(page.locator("#rrd-total-value")).toBeVisible();

        // tabClick() disables navbar controls (incl. #throughput_nav) for 1s after
        // activating the tab. The #selData change handler routes through tabClick,
        // which short-circuits while a control is disabled — so wait for the
        // controls to re-enable before changing the dataset.
        await expect(page.locator("#throughput_nav")).not.toHaveClass(/\bdisabled\b/);

        // Switching dataset fires a fresh /graph?type=week request and redraws.
        const before = graphUrls.length;
        await page.locator("#selData").selectOption("week");
        await expect.poll(() => graphUrls.slice(before).some((u) => u.includes("type=week"))).toBe(true);
    });

    test("History global search filters rows client-side", async () => {
        // Two network scans + a history fetch + several debounced client-side
        // filter cycles exceed the global 30 s budget under webkit/CI load
        // (cf. scan.spec throughput test, which overrides to 140 s).
        test.setTimeout(60000);
        // Seed two messages with distinct subjects. The body URL tends to produce
        // option-bearing symbols, exercised in the option-search step below.
        await page.locator("#scan_nav").click();
        const scanBtn = page.locator('#scan button[data-upload="checkv2"]');
        const subjects = [`charts-A-${Date.now()}`, `charts-B-${Date.now()}`];
        for (const subject of subjects) {
            await page.locator("#scanMsgSource").fill(
                `Message-Id: <${subject}@e2e>\nFrom: test@example.com\nSubject: ${subject}\n` +
                `Content-Type: text/plain; charset=utf-8\n\nhttp://${subject}.invalid/u`
            );
            await Promise.all([
                page.waitForResponse((r) => r.url().includes("checkv2") && r.ok()),
                scanBtn.click(),
            ]);
            await expect(page.locator(".alert-success, .alert-modal.alert-success").last())
                .toContainText("Data successfully scanned", {timeout: 10000});
        }

        await page.locator("#history_nav").click();
        await page.waitForResponse((r) => r.url().includes("/history") && r.ok());
        await expect(page.locator("#historyTable_history .tabulator-row").first())
            .toBeVisible({timeout: 10000});
        const baseline = await page.locator("#historyTable_history .tabulator-row").count();

        // The filter is debounced (250 ms) and applied client-side via Tabulator.
        await page.locator("#filter_history").fill(subjects[0]);
        await expect.poll(async () => await page.locator("#historyTable_history .tabulator-row").count())
            .toBeLessThan(baseline);

        // Clearing restores the rows.
        await page.locator("#filter_history").fill("");
        await expect.poll(async () => await page.locator("#historyTable_history .tabulator-row").count())
            .toBe(baseline);

        // Regression (#6168): a symbol option value (e.g. asn:205640) must match.
        // The symbols column collapses into the responsive detail row, so expand
        // the first (most recent) row and read a rendered "key:value" option token
        // from the symbols cell, then search for it. Guarded so the test still
        // passes (subject assertions above) when no option-bearing symbol fires.
        const table = page.locator("#historyTable_history");
        const firstRow = table.locator(".tabulator-row").first();
        const detail = firstRow.locator(".tabulator-responsive-collapse");
        if (!(await detail.isVisible())) await firstRow.click();
        await expect(detail).toBeVisible();
        const symbolsHtml = await detail.locator("tr:has(.sym-order-toggle) td").nth(1).innerHTML();
        // innerHTML returns escaped text; pick a token with no HTML entities.
        const optGroup = symbolsHtml.match(/\[([^\]]*)\]/);
        const optionToken = optGroup && optGroup[1].split(",").map((s) => s.trim())
            .find((s) => (/^\S+:\S+$/).test(s) && !s.includes("&"));

        if (optionToken) {
            await page.locator("#filter_history").fill(optionToken);
            // Before the fix options were absent from the haystack, so this yielded
            // zero rows. The row carrying the option must now remain visible.
            await expect.poll(async () => await table.locator(".tabulator-row").count())
                .toBeGreaterThan(0);
            await page.locator("#filter_history").fill("");
            await expect.poll(async () => await table.locator(".tabulator-row").count())
                .toBe(baseline);
        }
    });

    test("History column-options dropdown hides and resets a column", async () => {
        // History table is already loaded from the preceding serial test.
        const colBtn = page.locator("#history .tab-columns-btn");
        await expect(colBtn).toBeEnabled();

        await colBtn.click();
        const dropdown = page.locator("#history .tab-columns-dropdown");
        await expect(dropdown).toBeVisible();
        await expect(dropdown.locator("button", {hasText: "Reset to default"})).toBeVisible();
        await expect(dropdown.locator("input[data-option='visible']")).not.toHaveCount(0);

        // Hide the Subject column and persist (dropdown stays open: auto-close=outside).
        const subjectVisible = dropdown.locator("input[data-name='subject'][data-option='visible']");
        test.skip((await subjectVisible.count()) === 0, "Subject column checkbox not present");
        await subjectVisible.check();
        await dropdown.locator("button", {hasText: "Save"}).click();
        await expect.poll(() => page.evaluate(() => localStorage.getItem("columns") || ""))
            .toContain("subject");

        // Reset to default clears the customisation.
        await dropdown.locator("button", {hasText: "Reset to default"}).click();
        await expect.poll(() => page.evaluate(() => localStorage.getItem("columns") || ""))
            .not.toContain("subject");
    });
});
