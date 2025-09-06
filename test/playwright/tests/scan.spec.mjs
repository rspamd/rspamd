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
        const alert = page.locator(".alert-success, .alert-modal.alert-success");
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
            // Depending on row boundaries, throughput may show +2 or even +3
            const targetValues = [
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
                throw new Error(`Throughput counter should be one of [${targetValues.join(", ")}], got ${lastValue}`);
            }
        });
    });
});
