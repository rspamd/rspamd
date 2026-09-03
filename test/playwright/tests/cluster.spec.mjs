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

    // Identical versions and config ids: the git deviant carries the only badge
    await expect(page.locator("#clusterTable .cluster-drift")).toHaveCount(1);
    await expect(page.locator('tr[data-server="srv3"] td.cluster-git .cluster-drift'))
        .toHaveAttribute("title", "Git ID differs: 2 of 3 servers run a1b2c3d");

    // The details row spans all 12 visible columns
    await page.locator('tr[data-server="srv1"] td').nth(2).click();
    await expect(page.locator("#clusterTable tr.cluster-details td").first())
        .toHaveAttribute("colspan", "12");
});
