import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

async function logAlertOnError(page, locator, fn) {
    try {
        await fn();
    } catch (e) {
        const alertText = await locator.textContent();
        // eslint-disable-next-line no-console
        console.log("[E2E] Alert error text:", alertText);
        throw e;
    }
}

// Helper function for sequentially filling in fields
function fillSequentially(elements, values) {
    return elements.reduce((promise, el, i) => promise.then(() => el.fill(values[i])), Promise.resolve());
}

test("Config page: always checks order error and valid save for actions", async ({page}, testInfo) => {
    const {enablePassword} = testInfo.project.use.rspamdPasswords;
    await login(page, enablePassword);

    await page.locator("#configuration_nav").click();
    await expect(page.locator("#actionsFormField")).toBeVisible({timeout: 10000});

    function getInputs() { return page.locator("#actionsFormField input[data-id='action']"); }
    const alert = page.locator(".alert-danger, .alert-modal.alert-danger");

    const inputs = getInputs();
    const count = await inputs.count();
    expect(count).toBeGreaterThan(0);
    await Promise.all(
        Array.from({length: count}, (_, i) => expect(inputs.nth(i)).toBeVisible())
    );

    // Save the original values
    const values = await Promise.all(Array.from({length: count}, (_, i) => inputs.nth(i).inputValue()));

    // Determine only the fields actually available for input (not disabled, not readonly)
    const fillableChecks = Array.from({length: count}, (_, i) => (async () => {
        const input = inputs.nth(i);
        const isDisabled = await input.isDisabled();
        const isReadOnly = await input.evaluate((el) => el.hasAttribute("readonly"));
        return !isDisabled && !isReadOnly ? i : null;
    })());
    const fillableIndices = (await Promise.all(fillableChecks)).filter((i) => i !== null);

    const fillableInputs = fillableIndices.map((i) => inputs.nth(i));

    // 1. Correct order: strictly decreasing sequence
    const correctOrder = fillableIndices.map((_, idx) => (idx * 10).toString());

    await fillSequentially(fillableInputs, correctOrder);

    await page.locator("#saveActionsBtn").click();

    await logAlertOnError(page, alert, async () => {
        await expect(alert).not.toBeVisible({timeout: 2000});
    });

    // Reload the configuration and make sure the new value has been saved
    await page.locator("#refresh").click();
    await page.locator("#configuration_nav").click();

    const reloadedInputs = getInputs();
    const reloadedCount = await reloadedInputs.count();

    // Recalculate the fillable fields after reload
    const reloadedFillableChecks = Array.from({length: reloadedCount}, (_, i) => (async () => {
        const input = reloadedInputs.nth(i);
        const isDisabled = await input.isDisabled();
        const isReadOnly = await input.evaluate((el) => el.hasAttribute("readonly"));
        return !isDisabled && !isReadOnly ? i : null;
    })());
    const reloadedFillableIndices = (await Promise.all(reloadedFillableChecks)).filter((i) => i !== null);
    const reloadedFillableInputs = reloadedFillableIndices.map((i) => reloadedInputs.nth(i));

    await Promise.all(reloadedFillableInputs.map((input) => expect(input).toBeVisible()));

    const saved = await Promise.all(reloadedFillableInputs.map((input) => input.inputValue()));
    expect(saved).toEqual(correctOrder);

    // 2. Break the order: increasing sequence
    const wrongOrder = reloadedFillableIndices.map((_, idx) => ((reloadedFillableIndices.length - idx) * 10).toString());

    await fillSequentially(reloadedFillableInputs, wrongOrder);

    await page.locator("#saveActionsBtn").click();

    await expect(alert).toBeVisible({timeout: 10000});
    const alertText = await alert.textContent();
    expect(alertText).toContain("Incorrect order of actions thresholds");

    // Restore the original values
    await fillSequentially(reloadedFillableInputs, values);

    await page.locator("#saveActionsBtn").click();
});
