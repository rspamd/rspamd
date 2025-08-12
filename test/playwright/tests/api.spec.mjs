import {expect, test} from "@playwright/test";

test("API /stat endpoint is available and returns version", async ({request}, testInfo) => {
    const {readOnlyPassword} = testInfo.project.use.rspamdPasswords;

    const response = await request.get("/stat", {headers: {Password: readOnlyPassword}});
    expect(response.ok()).toBeTruthy();
    const data = await response.json();
    expect(data).toHaveProperty("version");
});
