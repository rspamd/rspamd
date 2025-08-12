import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

test("Logs page displays recent errors and allows refresh", async ({page}, testInfo) => {
    const {enablePassword} = testInfo.project.use.rspamdPasswords;
    await login(page, enablePassword);

    await page.locator("#history_nav").click();
    await expect(page.locator("#errorsLog")).toBeVisible();
    const rowCount = await page.locator("#errorsLog tbody tr").count();
    expect(rowCount).toBeGreaterThan(0);
    await page.locator("#updateErrors").click();
    await expect(page.locator("#errorsLog")).toBeVisible();
});
