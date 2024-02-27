context("Sqlite3 API", function()
  local sqlite3 = require "rspamd_sqlite3"
  local tmpdir = os.getenv("TMPDIR") or "/tmp"
  
  test("Sqlite3 open", function()
    os.remove(tmpdir .. '/rspamd_unit_test_sqlite3.sqlite')
    local db = sqlite3.open(tmpdir .. '/rspamd_unit_test_sqlite3.sqlite')
    assert_not_nil(db, "should be able to create sqlite3 db")
    db = sqlite3.open('/non/existent/path/rspamd_unit_test_sqlite3.sqlite')
    assert_nil(db, "should not be able to create sqlite3 db")
    os.remove(tmpdir .. '/rspamd_unit_test_sqlite3.sqlite')
  end)

  test("Sqlite3 query", function()
    os.remove(tmpdir .. '/rspamd_unit_test_sqlite3-1.sqlite')
    local db = sqlite3.open(tmpdir .. '/rspamd_unit_test_sqlite3-1.sqlite')
    assert_not_nil(db, "should be able to create sqlite3 db")
    
    local ret = db:sql([[
      CREATE TABLE x (id INT, value TEXT);
    ]])
    assert_true(ret, "should be able to create table")
    local ret = db:sql([[
      INSERT INTO x VALUES (?1, ?2);
    ]], 1, 'test')
    assert_true(ret, "should be able to insert row")
    os.remove(tmpdir .. '/rspamd_unit_test_sqlite3-1.sqlite')
  end)

  test("Sqlite3 rows", function()
    os.remove(tmpdir .. '/rspamd_unit_test_sqlite3-2.sqlite')
    local db = sqlite3.open(tmpdir .. '/rspamd_unit_test_sqlite3-2.sqlite')
    assert_not_nil(db, "should be able to create sqlite3 db")
    
    local ret = db:sql([[
      CREATE TABLE x (id INT, value TEXT);
    ]])
    assert_true(ret, "should be able to create table")
    local ret = db:sql([[
      INSERT INTO x VALUES (?1, ?2);
    ]], 1, 'test')
    assert_true(ret, "should be able to insert row")

    for row in db:rows([[SELECT * FROM x;]]) do
      assert_equal(row.id, '1')
      assert_equal(row.value, 'test')
    end
    os.remove(tmpdir .. '/rspamd_unit_test_sqlite3-2.sqlite')
  end)
end)