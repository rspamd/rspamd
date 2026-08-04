import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

// Read-only permission gating. NOTE: this works without any CI change — the
// controller already authenticates (secure_ip="0" matches only 0.0.0.0, never
// localhost), so a read-only password yields a real read-only session and
// displayUI() applies .ro-hide / .ro-disable / .ro-show accordingly.
//
// The assertions use elements that exist in the DOM regardless of the active
// tab: the Scan nav "/Learn" label (span.ro-hide, always rendered) and the
// Actions fieldset (.ro-disable), so they reflect the global RO state set on
// login rather than the visibility of the active pane.
test.describe("WebUI read-only permission gating", () => {
    test("read-only login hides write controls and disables inputs", async ({page}, testInfo) => {
        const {readOnlyPassword} = testInfo.project.use.rspamdPasswords;
        await login(page, readOnlyPassword);
        await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});

        // .ro-hide hidden: the "/Learn" label on the Scan tab is hidden.
        await expect(page.locator("#scan_nav span.ro-hide")).toHaveClass(/\bd-none\b/);
        // .ro-disable disabled: the Actions fieldset is locked. Assert the property
        // directly — Playwright's toBeDisabled() does not treat a disabled
        // <fieldset> (which locks its descendants) as a disabled element itself.
        await expect(page.locator("#actionsFormField")).toHaveJSProperty("disabled", true);
    });

    test("enable login exposes write controls", async ({page}, testInfo) => {
        const {enablePassword} = testInfo.project.use.rspamdPasswords;
        await login(page, enablePassword);
        await expect(page.locator("#navBar")).not.toHaveClass(/d-none/, {timeout: 30000});

        await expect(page.locator("#scan_nav span.ro-hide")).not.toHaveClass(/\bd-none\b/);
        await expect(page.locator("#actionsFormField")).toHaveJSProperty("disabled", false);
    });
});
