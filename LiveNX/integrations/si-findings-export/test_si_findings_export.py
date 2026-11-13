import json

import pytest

import si_findings_export as mod


class FakeSource:
    def __init__(self, rows):
        self.rows = rows  # list of (epoch, dict)
        self.calls = []

    def fetch(self, start, end):
        self.calls.append((start, end))
        return [dict(r) for t, r in self.rows if start <= t < end]


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("SI_OUTPUT_FILE", str(tmp_path / "out.jsonl"))
    monkeypatch.setenv("SI_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("SI_LOOKBACK_SECONDS", "600")
    monkeypatch.setenv("SI_INITIAL_BACKFILL_HOURS", "1")
    monkeypatch.setenv("SI_MAX_WINDOW_SECONDS", "900")
    monkeypatch.setenv("SI_LIVENX_HOST", "livenx.example.com")

    def build(rows, now):
        cfg = mod.Config()
        source, clock = FakeSource(rows), Clock(now)
        exporter = mod.Exporter(
            cfg, source, mod.State(cfg.state_file).load(), mod.Output(cfg.output_file, 0, 0), clock
        )
        return exporter, source, clock

    def lines():
        path = tmp_path / "out.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    return build, lines


def test_no_duplicates_across_cycles_and_restart(setup):
    build, lines = setup
    rows = [(1000, {"time": 1000, "m": "a"}), (2000, {"time": 2000, "m": "b"})]
    exporter, source, clock = build(rows, now=3000)
    assert exporter.run_cycle() == 2
    assert exporter.run_cycle() == 0
    # A new process picks up from the saved state.
    exporter, _, _ = build(rows, now=3010)
    assert exporter.run_cycle() == 0
    assert [r["m"] for r in lines()] == ["a", "b"]


def test_late_row_inside_lookback_is_exported(setup):
    build, lines = setup
    rows = [(2900, {"time": 2900, "m": "on-time"})]
    exporter, source, clock = build(rows, now=3000)
    assert exporter.run_cycle() == 1
    # Inserted after the checkpoint passed it, but with an older `time`.
    rows.append((2700, {"time": 2700, "m": "late"}))
    clock.now = 3030
    assert exporter.run_cycle() == 1
    assert [r["m"] for r in lines()] == ["on-time", "late"]


def test_identical_rows_are_each_exported_once(setup):
    build, lines = setup
    row = {"time": 2900, "m": "same"}
    rows = [(2900, row), (2900, row)]
    exporter, source, clock = build(rows, now=3000)
    assert exporter.run_cycle() == 2
    rows.append((2900, row))
    assert exporter.run_cycle() == 1
    assert len(lines()) == 3


def test_seen_keys_are_pruned_to_the_lookback_window(setup):
    build, _ = setup
    rows = [(t, {"time": t}) for t in range(0, 3000, 100)]
    exporter, source, clock = build(rows, now=3000)
    exporter.run_cycle()  # backfill covers the last hour: every row
    assert len(exporter.state.seen) == 30
    clock.now = 3010
    exporter.run_cycle()  # steady state re-reads only the last 600s
    assert len(exporter.state.seen) == 6


def test_api_source_splits_window_instead_of_using_cursor(monkeypatch):
    monkeypatch.setenv("SI_API_PAGE_SIZE", "2")
    monkeypatch.setenv("SI_LIVENX_HOST", "livenx.example.com")
    monkeypatch.setenv("SI_API_TOKEN", "secret")
    data = [{"time": t} for t in (10, 10, 11, 12, 12, 12)]
    requests = []

    class Resp:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, *_):
            return json.dumps(self.payload).encode()

    def fake_urlopen(req, timeout=None, context=None):
        url = mod.urllib.parse.urlsplit(req.full_url)
        assert (url.netloc, url.path) == ("livenx.example.com", "/api/security-proxy/api/v1/findings")
        assert req.get_header("Authorization") == "Bearer secret"
        query = mod.urllib.parse.parse_qs(url.query)
        requests.append(query)
        assert "cursor" not in query
        lo, hi = [int(part.split("=")[-1]) for part in query["filter"][0].split(";")[:2]]
        size = int(query["pageSize"][0])
        match = [r for r in data if lo <= r["time"] < hi]
        return Resp({"data": match[:size], "hasMore": len(match) > size, "totalCount": len(match)})

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)
    rows = mod.ApiSource(mod.Config()).fetch(10, 14)
    assert sorted(r["time"] for r in rows) == [10, 10, 11, 12, 12, 12]


def test_rotation_keeps_configured_number_of_files(tmp_path):
    path = tmp_path / "out.jsonl"
    output = mod.Output(str(path), max_bytes=10, keep=2)
    for index in range(4):
        output.write([{"n": index, "pad": "x" * 20}])
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out.jsonl", "out.jsonl.1", "out.jsonl.2"]
    assert json.loads(path.read_text())["n"] == 3


def test_unconfigured_api_source_exits_with_config_error(monkeypatch):
    for name in ("SI_LIVENX_HOST", "SI_API_URL", "SI_SOURCE"):
        monkeypatch.delenv(name, raising=False)
    assert mod.main(["--once"]) == mod.EX_CONFIG


def test_api_empty_window_404_is_not_an_error(monkeypatch):
    monkeypatch.setenv("SI_LIVENX_HOST", "livenx.example.com")
    import io

    def fake_urlopen(req, timeout=None, context=None):
        body = b'{"httpCode":404,"code":"findings:not_found","message":"Findings not found."}'
        raise mod.urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(body))

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)
    assert mod.ApiSource(mod.Config()).fetch(10, 20) == []


def test_api_wrong_path_404_is_an_error(monkeypatch):
    monkeypatch.setenv("SI_LIVENX_HOST", "livenx.example.com")
    import io

    def fake_urlopen(req, timeout=None, context=None):
        raise mod.urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b"<html>nope</html>"))

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(RuntimeError):
        mod.ApiSource(mod.Config()).fetch(10, 20)
