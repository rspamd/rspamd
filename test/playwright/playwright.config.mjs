/** @type {import("@playwright/test").PlaywrightTestConfig} */
const config = {
    projects: [
        {
            name: "firefox",
            use: {browserName: "firefox"}
        },
        {
            name: "chromium",
            use: {browserName: "chromium"}
        },
        {
            name: "webkit",
            use: {browserName: "webkit"}
        }
    ],
    reporter: [["html", {open: "never", outputFolder: "playwright-report"}]],
    retries: 0,
    testDir: "./tests",
    timeout: 30000,
    use: {
        baseURL: "http://localhost:11334",
        rspamdPasswords: {
            enablePassword: "enable",
            readOnlyPassword: "read-only",
        },
        screenshot: "on-first-failure",
    },
};

export default config;
