import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

test.describe("WebUI basic", () => {
    test.beforeEach(async ({page}, testInfo) => {
        const {readOnlyPassword} = testInfo.project.use.rspamdPasswords;
        await login(page, readOnlyPassword);
    });

    test("Smoke: loads WebUI and shows main elements", async ({page}) => {
        await expect(page).toHaveTitle(/Rspamd Web Interface/i);
        // Wait for preloader to be hidden by JS when loading is complete
        await expect(page.locator("#preloader")).toBeHidden({timeout: 30000});
        // Wait for main UI class to be removed by JS
        await expect(page.locator("#mainUI")).not.toHaveClass("d-none", {timeout: 30000});
        await expect(page.locator("#mainUI")).toBeVisible();

        await expect(page.locator("#navBar")).toBeVisible();
        await expect(page.locator("#tablist")).toBeVisible();
        await expect(page.locator(".tab-pane")).toHaveCount(7);
    });

    test("Shows no alert when backend returns non-AJAX error", async ({page}) => {
        // Try to call a non-existent endpoint using browser fetch
        await Promise.all([
            page.waitForResponse((resp) => resp.url().includes("/notfound") && !resp.ok()),
            page.evaluate(() => fetch("/notfound"))
        ]);
        // WebUI shows alert-error only for errors handled via AJAX (common.query)
        // If alert is not shown, the test should not fail
        await expect(page.locator(".alert-error, .alert-modal.alert-error")).not.toBeVisible({timeout: 2000});
    });
});
