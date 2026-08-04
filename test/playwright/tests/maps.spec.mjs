import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

// Configuration → Maps editor. The existing config.spec only covers the Actions
// thresholds; the Maps card, modal editor and read-only handling are untested.
// Map rows: the clickable cell is span.map-link; a "Writable" badge
// (span.badge.text-bg-success) marks editable maps.
test.describe("WebUI Configuration → Maps editor", () => {
    test.beforeEach(async ({page}, testInfo) => {
        const {enablePassword} = testInfo.project.use.rspamdPasswords;
        await login(page, enablePassword);
        await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});

        await page.locator("#configuration_nav").click();
        await page.waitForResponse((r) => r.url().endsWith("/maps") && r.ok());
        await expect(page.locator("#listMaps tbody tr").first()).toBeVisible();
    });

    test("maps list renders rows with flag badges and a map link", async ({page}) => {
        const firstRow = page.locator("#listMaps tbody tr").first();
        await expect(firstRow).toBeVisible();
        // Flags cell carries at least one badge; URL cell has the clickable .map-link.
        await expect(firstRow.locator("span.badge")).not.toHaveCount(0);
        await expect(firstRow.locator("span.map-link")).not.toHaveCount(0);
    });

    test("opening a writable map shows the editor with Save enabled", async ({page}) => {
        const writableLink = page.locator(
            "#listMaps tbody tr:has(span.badge.text-bg-success) span.map-link"
        );
        test.skip((await writableLink.count()) === 0, "no writable map present in this configuration");

        // Register the response listener before the click: getmap on localhost is
        // faster than a sequentially-registered waitForResponse, which would miss it.
        await Promise.all([
            page.waitForResponse((r) => r.url().includes("getmap")),
            writableLink.first().click(),
        ]);

        await expect(page.locator("#modalDialog")).toBeVisible();
        await expect(page.locator("#modalTitle")).not.toBeEmpty();
        await expect(page.locator("#editor")).toBeVisible();
        // Writable branch: Save group is shown (no d-none).
        await expect(page.locator("#modalSaveGroup")).not.toHaveClass(/\bd-none\b/);
        await expect(page.locator("#modalSave")).toBeVisible();
    });

    test("opening a read-only map hides Save", async ({page}) => {
        // A loaded, non-writable row lacks the Writable badge (and isn't unloaded).
        const readOnlyRow = page.locator(
            "#listMaps tbody tr:not(:has(span.badge.text-bg-success)):not(.table-active)"
        );
        const count = await readOnlyRow.count();
        test.skip(count === 0, "no read-only map present in this configuration");

        // Listener before click (see writable test): localhost getmap beats a
        // sequentially-registered waitForResponse.
        await Promise.all([
            page.waitForResponse((r) => r.url().includes("getmap")),
            readOnlyRow.locator("span.map-link").first().click(),
        ]);

        await expect(page.locator("#modalDialog")).toBeVisible();
        // Read-only branch: the whole Save group is hidden.
        await expect(page.locator("#modalSaveGroup")).toHaveClass(/\bd-none\b/);
    });
});
