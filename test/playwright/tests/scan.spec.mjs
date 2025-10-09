import {expect, test} from "@playwright/test";
import {login} from "../helpers/auth.mjs";

test.describe.serial("Scan flow across WebUI tabs", () => {
    let page = null;
    let scannedSubjects = [];
    const scannedBefore = {scanTab: 0, throughput: 0};

    async function gotoTab(name) {
        await page.locator(`#${name}_nav`).click();
    }

    function extractNumber(text) {
        return parseInt(text.replace(/\D/g, ""), 10);
    }

    async function readScanTab() {
        // Status tab → scanned widget
        await gotoTab("status");
        await page.waitForResponse((resp) => resp.url().includes("/stat") && resp.status() === 200);
        const scannedWidget = page.locator("#statWidgets .widget[title*='scanned']");
        await expect(scannedWidget).toBeVisible();
        const scannedTitle = await scannedWidget.getAttribute("title");
        return extractNumber(scannedTitle);
    }

    async function readThroughput() {
        // Throughput tab → id="rrd-total-value"
        await gotoTab("throughput");
        await page.waitForResponse((resp) => resp.url().includes("/graph") && resp.status() === 200);
        const throughputValue = page.locator("#rrd-total-value");
        await expect(throughputValue).toBeVisible();
        return extractNumber(await throughputValue.textContent());
    }

    async function expectAlertSuccess(expectedText) {
        // Wait for a new alert to appear by counting existing alerts first
        const initialAlertCount = await page.locator(".alert-success, .alert-modal.alert-success").count();

        // Wait for a new alert to appear
        await expect(async () => {
            const currentCount = await page.locator(".alert-success, .alert-modal.alert-success").count();
            return currentCount > initialAlertCount;
        }).toPass({timeout: 5000});

        // Get the most recently appeared alert (last one)
        const alert = page.locator(".alert-success, .alert-modal.alert-success").last();
        await expect(alert).toBeVisible();
        const text = await alert.textContent();
        expect(text).toContain(expectedText);
        await expect(alert).not.toBeVisible({timeout: 10000});
    }

    test.beforeAll(async ({browser}, testInfo) => {
        const context = await browser.newContext();
        page = await context.newPage();
        const {enablePassword} = testInfo.project.use.rspamdPasswords;
        await login(page, enablePassword);
    });

    test.afterAll(async () => {
        await page.close();
    });

    test.describe("Phase 1: before scanning", () => {
        test("Read current Scanned counters", async () => {
            scannedBefore.scanTab = await readScanTab();
            scannedBefore.throughput = await readThroughput();
        });
    });

    test.describe("Phase 2: scanning", () => {
        test("Scan two test messages", async ({}, testInfo) => {
            const {testId} = testInfo;
            await gotoTab("scan");
            const scanMessageBtn = page.locator('#scan button[data-upload="checkv2"]');
            await expect(scanMessageBtn).toBeDisabled();

            scannedSubjects = [];

            for (let i = 1; i <= 2; i++) {
                const timestamp = Date.now();
                const msgId = `E2E-${i}-${timestamp}@example.com`;
                const subject = `E2E Test ${i} ${testId}-${timestamp}`;
                scannedSubjects.push(subject);

                await page.locator("#scanMsgSource").fill(
                    `Message-Id: ${msgId}\nFrom: test@example.com\nSubject: ${subject}\n\nTest body`
                );
                await scanMessageBtn.click();

                await expectAlertSuccess("Data successfully scanned");
                await expect(
                    page.locator(`#historyTable_scan tbody tr:first-child td.footable-first-visible:has-text("${msgId}")`)
                ).toBeVisible();
            }
        });
    });

    test.describe("Phase 3: after scanning", () => {
        test("History shows scanned messages and can be reset", async () => {
            await gotoTab("history");

            // Check both scanned messages are present in reverse order
            for (let i = 0; i < scannedSubjects.length; i++) {
                const subject = scannedSubjects[scannedSubjects.length - 1 - i]; // reverse order
                await expect(
                    page.locator("#historyTable_history tbody tr").nth(i)
                        .locator(`td:has-text("${subject}")`)
                ).toBeVisible();
            }

            // Reset history
            const resetBtn = page.locator("#resetHistory");
            await expect(resetBtn).toBeVisible();
            page.once("dialog", (dialog) => dialog.accept());
            await resetBtn.click();

            const updateHistoryBtn = page.locator("#updateHistory");
            await expect(updateHistoryBtn).toBeDisabled();
            await expect(updateHistoryBtn).not.toBeDisabled();

            const rows = await page.locator("#historyTable_history tbody tr").count();
            // Known bug: Rspamd leaves one row after history reset
            expect([0, 1]).toContain(rows);
        });
    });

    test.describe("Phase 4: counters after scanning", () => {
        test("Status tab `Scanned` counter increased by 2", async () => {
            const scanTab = await readScanTab();
            expect(scanTab).toBe(scannedBefore.scanTab + 2);
        });

        test("Throughput `Total messages` counter increased", async ({}, testInfo) => {
            testInfo.setTimeout(140000);
            // With empty RRD the first PDP is lost, so only +1 is visible
            // Depending on row boundaries, throughput may show +2 or even +3
            const targetValues = [
                scannedBefore.throughput + 1,
                scannedBefore.throughput + 2,
                scannedBefore.throughput + 3,
            ];

            let lastValue = null;
            try {
                await expect.poll(async () => {
                    lastValue = await readThroughput();
                    return targetValues.includes(lastValue);
                }, {
                    interval: 5000,
                    // step = 1s, pdp_per_row = 60 → next row every 60s
                    timeout: 125000,
                }).toBeTruthy();
            } catch (e) {
                const msg = `Throughput counter should be one of [${targetValues.join(", ")}], got ${lastValue}`;
                throw new Error(msg, {cause: e});
            }
        });
    });

    test.describe("Regression: classifier list after RO → disconnect → enable", () => {
        test("Classifier dropdown is populated after reconnect", async ({browser}, testInfo) => {
            const {readOnlyPassword, enablePassword} = testInfo.project.use.rspamdPasswords;

            // Use isolated context to avoid pre-populated state from other tests
            const context = await browser.newContext();
            const page2 = await context.newPage();

            async function gotoTabLocal(name) {
                await page2.locator(`#${name}_nav`).click();
            }

            // Login as read-only
            await login(page2, readOnlyPassword);
            await page2.waitForSelector("#navBar:not(.d-none)");

            // Go to Scan in RO
            await gotoTabLocal("scan");
            await expect(page2.locator("#scan")).toBeVisible();

            // Disconnect and login as enable (writable)
            await page2.locator("#disconnect").click();
            // Avoid shared login() helper which calls page.goto('/') to stay on the same tab.
            await page2.locator("#connectPassword").fill(enablePassword);
            // Expect classifiers request after successful enable login
            const p = page2.waitForResponse(
                (r) => r.url().includes("/bayes/classifiers") && r.status() === 200,
                {timeout: 5000}
            );
            await page2.locator("#connectButton").click();
            await page2.waitForSelector("#navBar:not(.d-none)");
            await p;

            // Expect classifiers to be populated
            const classifier = page2.locator("#classifier");
            await expect(classifier).toBeVisible();
            const optionCount = await classifier.locator("option").count();
            expect(optionCount).toBeGreaterThan(1);

            // Verify that a subsequent getClassifiers call under the same config is skipped
            let reqCount = 0;
            function reqListener(r) {
                if (r.url().includes("/bayes/classifiers")) {
                    reqCount += 1;
                }
            }
            page2.on("request", reqListener);

            await page2.evaluate(() => new Promise((resolve) => {
                // AMD require is available in the UI
                // eslint-disable-next-line no-undef
                require(["app/upload"], (u) => {
                    u.getClassifiers();
                    resolve();
                });
            }));

            await page2.waitForTimeout(250);
            page2.off("request", reqListener);
            expect(reqCount).toBe(0);

            // Options must remain populated (not reset to just default)
            const finalCount = await classifier.locator("option").count();
            expect(finalCount).toBeGreaterThan(1);

            await page2.close();
            await context.close();
        });
    });
});
