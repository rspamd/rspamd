export async function login(page, password) {
    await page.goto("/");
    const input = page.locator("#connectPassword");
    await input.fill(password);
    await page.locator("#connectButton").click();
}
