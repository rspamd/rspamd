import requests
import json
from robot.libraries.BuiltIn import BuiltIn
from robot.api import logger

__client = None


class Client:
    def __init__(self):
        self.port = BuiltIn().get_variable_value('${CLICKHOUSE_PORT}', default=18123)

    def get_query_string(self):
        return "http://localhost:%d/?default_format=JSONEachRow" % (self.port)

    def execute(self, sql):
        r = requests.post(self.get_query_string(), sql)
        logger.info("Client.execute: response: %s" % str(r))
        if r.status_code != 200:
            raise Exception("Clickhouse request failed: " + r.content)
        return r

    def query(self, sql):
        r = self.execute(sql)

        # logger.console("decoding " + r.content)
        # [logger.console("decoding " + _) for _ in r.content.strip().split("\n")]
        response = [json.loads(_) for _ in r.content.strip().split("\n")]
        return response


def client():
    global __client
    if __client is None:
        __client = Client()
    return __client


def upload_new_schema(schema_file):
    with open(schema_file, 'r') as content_file:
        content = content_file.read()

    queries = content.split(";")
    for q in queries:
        if q.strip() == "":
            continue
        client().execute(q)  # throws exception on error


def insert_data(table_name, filename):
    with open(filename, 'r') as content_file:
        content = content_file.read()

    client().execute("insert into %s format Values %s;" % (table_name, content))  # throws exception on error


def column_should_exist(table_name, column_name):
    sql = "select hasColumnInTable('default', '%s', '%s') as is_exist" % (table_name, column_name)
    r = client().query(sql)
    logger.info("response: %s" % str(r))
    if r[0]['is_exist'] != 1:
        raise Exception("Failed asseting that column '%s' exists in table 'default'.'%s'" % (column_name, table_name))


def schema_version_should_be(version):
    sql = "select max(Version) as version from rspamd_version"
    r = client().query(sql)
    logger.info("response: %s" % str(r))
    if r[0]['version'] != int(version):
        raise Exception("Failed asseting that schema version is %d, %d schema version in ClickHouse" % (int(version), int(r[0]['version'])))


def assert_rows_count(table_name, number):
    sql = "select count(*) as cnt from %s" % table_name
    r = client().query(sql)
    logger.info("response: %s" % str(r))
    if int(r[0]['cnt']) != int(number):
        raise Exception("Failed asserting that table '%s' has %d rows (actual number: %d)" % (table_name, int(number), int(r[0]['cnt'])))
