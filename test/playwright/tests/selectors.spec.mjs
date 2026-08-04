import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

// The "Test selectors" tab — previously the only tab with zero E2E coverage.
// displayUI() (selectors.js) fires list_extractors/list_transforms on first
// open and disables #selectorsChkMsgBtn while the selector textarea is empty.
test.describe("WebUI Selectors tab", () => {
    test.beforeEach(async ({page}, testInfo) => {
        const {enablePassword} = testInfo.project.use.rspamdPasswords;
        await login(page, enablePassword);
        await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});

        // displayUI() fires list_extractors and list_transforms together, right
        // from the click handler. Register both listeners before the click — on
        // localhost they can beat a sequentially-registered waitForResponse,
        // especially on older Playwright.
        await Promise.all([
            page.waitForResponse((r) => r.url().includes("list_extractors") && r.ok()),
            page.waitForResponse((r) => r.url().includes("list_transforms") && r.ok()),
            page.locator("#selectors_nav").click(),
        ]);
        await expect(page.locator("#selectorsTable-extractors tbody tr").first()).toBeVisible();
    });

    // check_selector toggles is-valid/is-invalid on #selectorsSelArea; the Check
    // button is enabled only when the selector is valid AND a message is present.
    test("selector textarea live-validates and gates the Check button", async ({page}) => {
        const selArea = page.locator("#selectorsSelArea");
        const checkBtn = page.locator("#selectorsChkMsgBtn");

        // Empty selector on a fresh tab → button disabled.
        await expect(checkBtn).toBeDisabled();

        // Invalid selector → is-invalid, button still disabled.
        await selArea.fill("from(unclosed");
        await expect(selArea).toHaveClass(/\bis-invalid\b/, {timeout: 10000});
        await expect(checkBtn).toBeDisabled();

        // A valid selector (plus a non-empty message) enables the button.
        await page.locator("#selectorsMsgArea").fill("From: test@example.com\n\nBody");
        await selArea.fill("from");
        await expect(selArea).toHaveClass(/\bis-valid\b/, {timeout: 10000});
        await expect(checkBtn).toBeEnabled();
    });

    test("Check message evaluates the selector and fills the result", async ({page}) => {
        await page.locator("#selectorsMsgArea").fill("From: test@example.com\nSubject: hi\n\nBody text");
        await page.locator("#selectorsSelArea").fill("from");
        await expect(page.locator("#selectorsSelArea")).toHaveClass(/\bis-valid\b/);

        // Listener before click: check_message fires synchronously from the click
        // handler and can beat a post-click waitForResponse on localhost.
        await Promise.all([
            page.waitForResponse((r) => r.url().includes("check_message") && r.ok()),
            page.locator("#selectorsChkMsgBtn").click(),
        ]);

        // The result textarea (disabled/readonly) is populated with the extraction.
        await expect(page.locator("#selectorsResArea")).not.toHaveValue("");
    });

    test("extractors/transforms tables populate and sidebars collapse", async ({page}) => {
        await expect(page.locator("#selectorsTable-extractors tbody tr")).not.toHaveCount(0);
        await expect(page.locator("#selectorsTable-transforms tbody tr")).not.toHaveCount(0);

        // Collapsing the left sidebar toggles a `collapsed` class and regrids #content.
        await expect(page.locator("#sidebar-left")).not.toHaveClass(/\bcollapsed\b/);
        await page.locator("#sidebar-tab-left > a").click();
        await expect(page.locator("#sidebar-left")).toHaveClass(/\bcollapsed\b/);
        await expect(page.locator("#content")).toHaveClass(/\bcol-lg-9\b/);

        // Expand back.
        await page.locator("#sidebar-tab-left > a").click();
        await expect(page.locator("#sidebar-left")).not.toHaveClass(/\bcollapsed\b/);
    });
});
