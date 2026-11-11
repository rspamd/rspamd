import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

// Global widgets not tied to a single tab: theme toggle, settings popover, the
// backend-API-errors badge/modal, and sticky-tab (URL hash) navigation.
test.describe("WebUI global widgets", () => {
    test.beforeEach(async ({page}, testInfo) => {
        const {enablePassword} = testInfo.project.use.rspamdPasswords;
        await login(page, enablePassword);
        await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});
    });

    // #theme-toggle cycles the stored preference light → dark → auto → light
    // (rspamd.js themeMap) and applies it via data-bs-theme on <html>.
    test("theme toggle cycles light → dark → auto and persists to localStorage", async ({page}) => {
        const html = page.locator("html");
        // A fresh context has no stored theme => treated as "auto".
        await page.locator("#theme-toggle").click();
        await expect(html).toHaveAttribute("data-bs-theme", "light");
        expect(await page.evaluate(() => localStorage.getItem("theme"))).toBe("light");

        await page.locator("#theme-toggle").click();
        await expect(html).toHaveAttribute("data-bs-theme", "dark");
        expect(await page.evaluate(() => localStorage.getItem("theme"))).toBe("dark");

        await page.locator("#theme-toggle").click();
        expect(await page.evaluate(() => localStorage.getItem("theme"))).toBe("auto");
    });

    test("settings popover validates locale and restores the ajax timeout", async ({page}) => {
        await page.locator("#settings").click();
        // The popover clones #settings-popover into a .popover container.
        const popover = page.locator(".popover #settings-popover");
        await expect(popover).toBeVisible();

        // Custom locale: valid value → is-valid and a rendered date example.
        await popover.locator('input[name="locale"][value="custom"]').check();
        const localeInput = popover.locator("#locale");
        await localeInput.fill("de-DE");
        await expect(localeInput).toHaveClass(/\bis-valid\b/, {timeout: 10000});
        await expect(popover.locator("#date-example")).not.toBeEmpty();

        // Invalid value → is-invalid. Use a value toLocaleString() actually
        // rejects: ICU accepts "not-a-locale"-shaped tags, but "1" is never a
        // valid language subtag → RangeError → is-invalid.
        await localeInput.fill("1");
        await expect(localeInput).toHaveClass(/\bis-invalid\b/, {timeout: 10000});

        // HTTP timeout: set then restore to the default (20000 ms).
        await popover.locator("#ajax-timeout").fill("30000");
        await expect.poll(async () => await page.evaluate(() => localStorage.getItem("ajax_timeout"))).toBe("30000");
        await popover.locator("#ajax-timeout-restore").click();
        await expect.poll(async () => await page.evaluate(() => localStorage.getItem("ajax_timeout"))).toBe("20000");
    });

    test("backend API error surfaces the error badge and errors modal", async ({page}) => {
        // Force /symbols to fail so opening the Symbols tab logs an API error.
        await page.route("**/symbols", (route) => route.fulfill({status: 500, body: "server error"}));

        const badge = page.locator("#error-log-badge");
        await expect(badge).toHaveClass(/\bd-none\b/);

        await page.locator("#symbols_nav").click();
        await page.waitForResponse((r) => r.url().includes("/symbols") && r.status() === 500);

        // A failed request is logged → badge + unseen counter appear.
        await expect(badge).not.toHaveClass(/\bd-none\b/);
        await expect(page.locator("#error-count")).not.toHaveClass(/\bd-none\b/);

        // Open the modal → table populated, action buttons enabled.
        await page.locator("#error-log-badge button").click();
        await expect(page.locator("#errorLogModal")).toBeVisible();
        await expect(page.locator("#errorLogTable tbody tr")).not.toHaveCount(0);
        await expect(page.locator("#clearErrorLog")).toBeEnabled();
        await expect(page.locator("#copyErrorLog")).toBeEnabled();

        // Clear → badge hides again.
        await page.locator("#clearErrorLog").click();
        await expect(badge).toHaveClass(/\bd-none\b/);
    });

    test("sticky tabs switch the active pane on URL hash change", async ({page}) => {
        // Status is the initial tab after login.
        await expect(page.locator("#status")).toHaveClass(/\bactive\b/);

        // initStickyTabs binds hashchange → activates the matching tab.
        await page.evaluate(() => {
            history.pushState(null, "", "#selectors");
            window.dispatchEvent(new Event("hashchange"));
        });

        await expect(page.locator("#selectors")).toHaveClass(/\bactive\b/);
    });
});
