from db.sink import Neo4jSink


class _Transaction:
    def run(self, query: str, **params: object):
        return [{"query": query, "params": params}]


class _Session:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute_read(self, callback, *args):
        self.calls.append("read")
        return callback(_Transaction(), *args)

    def execute_write(self, callback, *args):
        self.calls.append("write")
        return callback(_Transaction(), *args)


class _Driver:
    def __init__(self) -> None:
        self.session_instance = _Session()

    def session(self):
        return self.session_instance


def test_neo4j_sink_uses_managed_read_and_write_transactions() -> None:
    sink = Neo4jSink.__new__(Neo4jSink)
    driver = _Driver()
    sink.driver = driver

    assert sink.run_read("RETURN $value", value=1)[0]["params"] == {"value": 1}
    assert sink.run_write("CREATE (n)", value=2)[0]["params"] == {"value": 2}
    assert driver.session_instance.calls == ["read", "write"]
