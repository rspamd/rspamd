import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

test.describe("Symbols", () => {
    test.beforeEach(async ({page}, testInfo) => {
        const {enablePassword} = testInfo.project.use.rspamdPasswords;
        await login(page, enablePassword);
        await page.locator("#symbols_nav").click();
        await expect(page.locator("#symbolsTable")).toBeVisible();
        // Ensure table data has been loaded before running tests
        await expect(page.locator("#symbolsTable tbody tr").first()).toBeVisible();
    });

    test("shows list and allows filtering by group", async ({page}) => {
        // Check filtering by group (if selector exists)
        const groupSelect = page.locator(".footable-filtering select.form-select").first();
        if (await groupSelect.count()) {
            // Ensure there is at least one real group besides "Any group"
            const optionCount = await groupSelect.evaluate((el) => el.options.length);
            expect(optionCount).toBeGreaterThan(1);

            // Read target group's value and text BEFORE selection to avoid FooTable redraw races
            const target = await groupSelect.evaluate((el) => {
                const [, op] = Array.from(el.options); // first non-default option
                return {text: op.text, value: op.value};
            });

            const groupCells = page.locator("#symbolsTable tbody tr td.footable-first-visible");
            const beforeTexts = await groupCells.allTextContents();

            await groupSelect.selectOption({value: target.value});
            const selectedGroup = target.text.toLowerCase();

            // Wait until table content updates (using expect.poll with matcher)
            await expect.poll(async () => {
                const texts = await groupCells.allTextContents();
                return texts.join("|");
            }, {timeout: 5000}).not.toBe(beforeTexts.join("|"));

            const afterTexts = await groupCells.allTextContents();

            // Validate that all visible rows belong to the selected group
            for (const text of afterTexts) {
                expect(text.toLowerCase()).toContain(selectedGroup);
            }
        }
    });

    test.describe.configure({mode: "serial"});
    test("edits score for the first symbol and saves", async ({page}) => {
        const scoreInput = page.locator("#symbolsTable .scorebar").first();
        const scoreInputId = await scoreInput.evaluate((element) => element.id);
        const oldValue = await scoreInput.inputValue();

        // Try to change the score value for the first symbol
        await scoreInput.fill((parseFloat(oldValue) + 0.01).toFixed(2));
        await scoreInput.blur();

        // A save notification should appear
        const saveAlert = page.locator("#save-alert");
        await expect(saveAlert).toBeVisible();

        // Save changes
        await saveAlert.getByRole("button", {exact: true, name: "Save"}).click();

        // A success alert should appear (wait for any alert-success)
        const alertSuccess = page.locator(".alert-success, .alert-modal.alert-success");
        await expect(alertSuccess).toBeVisible();

        // Revert to the old value (clean up after the test)
        await expect(alertSuccess).not.toBeVisible({timeout: 10000});
        const revertedScoreInput = page.locator("#" + scoreInputId);
        await revertedScoreInput.fill(oldValue);
        await revertedScoreInput.blur();
        await saveAlert.getByRole("button", {exact: true, name: "Save"}).click();
    });
});
