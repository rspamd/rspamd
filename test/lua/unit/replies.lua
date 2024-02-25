context("Check replies set", function()
    local fun = require("fun")
    local rspamd_task = require("rspamd_task")
    local replies = require("replies")

    test("Check replies set of 1 sender 1 recipient", function()

        local msg = [[
        From: <sender@example.com>
        To: <recipient0@example.com>
        Subject: in-reply-to
        Content-Type: text/plain
        ]]
        local res, task = rspamd_task.load_from_string(msg)
        assert_true(res, "failed to load message")
        replies:replies_check(task)

    end )

    test("Check replies set of 1 sender many recipients", function()

        local msg = [[
        From: <sender@example.com>
        To: <recipient1@example.com>, <recipient2@example.com>, <recipient3@example.com>
        Subject: in-reply-to
        Content-Type: text/plain
        ]]
        local res, task = rspamd_task.load_from_string(msg)
        assert_true(res, "failed to load message")
        replies:replies_check(task)

    end )
end )