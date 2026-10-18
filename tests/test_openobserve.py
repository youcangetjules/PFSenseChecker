"""OpenObserve client: auth, search guard, and settings without secrets."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from pfsense_checker import openobserve
from pfsense_checker.openobserve import OpenObserveError, OpenObserveSettings


@pytest.fixture(autouse=True)
def _reset_openobserve_state():
    openobserve._cached = None
    openobserve._queue.clear()
    openobserve._last_error = ""
    yield
    openobserve._cached = None
    openobserve._queue.clear()


def _settings(**overrides) -> OpenObserveSettings:
    base = dict(
        enabled=True,
        base_url="http://127.0.0.1:5080",
        organization="default",
        stream="netcheck",
        username="root@example.com",
    )
    base.update(overrides)
    return OpenObserveSettings(**base)


def test_settings_file_never_stores_a_password(tmp_path) -> None:
    path = tmp_path / "openobserve.json"
    openobserve.save_settings(_settings(), path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert "password" not in raw
    assert "token" not in raw
    assert raw["base_url"] == "http://127.0.0.1:5080"
    assert raw["organization"] == "default"


def test_url_rejects_embedded_credentials_and_paths() -> None:
    with pytest.raises(OpenObserveError):
        openobserve.normalise_base_url("http://user:secret@127.0.0.1:5080")
    with pytest.raises(OpenObserveError):
        openobserve.normalise_base_url("http://127.0.0.1:5080/api")
    with pytest.raises(OpenObserveError):
        openobserve.normalise_base_url("ftp://127.0.0.1:5080")


def test_remote_http_warns_loopback_and_https_do_not() -> None:
    assert openobserve.credential_transport_warning("http://10.1.1.8:5080")
    assert openobserve.credential_transport_warning("http://logs.lab:5080") == (
        openobserve.credential_transport_warning("http://10.1.1.8:5080")
    )
    assert not openobserve.credential_transport_warning("http://127.0.0.1:5080")
    assert not openobserve.credential_transport_warning("https://logs.example:5080")


def test_search_sql_is_a_single_select() -> None:
    assert openobserve.validate_search_sql("SELECT * FROM netcheck") == (
        "SELECT * FROM netcheck"
    )
    for bad in (
        "DROP TABLE netcheck",
        "SELECT * FROM netcheck; DELETE FROM netcheck",
        "SELECT password INTO OUTFILE '/tmp/x' FROM netcheck",
        "INSERT INTO netcheck VALUES (1)",
    ):
        with pytest.raises(OpenObserveError):
            openobserve.validate_search_sql(bad)


def test_ingest_uses_basic_auth_and_drops_secret_fields() -> None:
    seen: dict = {}

    def send(request, timeout):  # noqa: ANN001
        seen["url"] = request.full_url
        seen["auth"] = request.get_header("Authorization")
        seen["body"] = request.data
        seen["timeout"] = timeout
        return 200, b'{"code":200,"status":[{"successful":1,"failed":0}]}'

    openobserve.ingest(
        [{"message": "link up", "password": "nope", "level": "info"}],
        _settings(timeout_sec=7),
        password="s3cret-value",
        send=send,
    )
    assert seen["url"] == "http://127.0.0.1:5080/api/default/netcheck/_json"
    assert seen["auth"].startswith("Basic ")
    assert b"s3cret-value" not in seen["body"]
    assert b"nope" not in seen["body"]
    body = json.loads(seen["body"])
    assert body[0]["message"] == "link up"
    assert body[0]["level"] == "info"
    assert "_timestamp" in body[0]
    assert seen["timeout"] == 7


def test_empty_user_uses_bearer_token() -> None:
    seen: dict = {}

    def send(request, timeout):  # noqa: ANN001
        seen["auth"] = request.get_header("Authorization")
        return 200, b'{"code":200,"status":[]}'

    openobserve.ingest(
        [{"message": "x"}],
        _settings(username=""),
        password="tok-1",
        send=send,
    )
    assert seen["auth"] == "Bearer tok-1"


def test_org_traversal_is_rejected_before_send() -> None:
    def send(request, timeout):  # noqa: ANN001
        raise AssertionError("request must not be sent")

    with pytest.raises(OpenObserveError):
        openobserve.ingest(
            [{"message": "x"}],
            _settings(organization="../default"),
            password="x",
            send=send,
        )


def test_search_window_is_microseconds() -> None:
    seen: dict = {}

    def send(request, timeout):  # noqa: ANN001
        seen["url"] = request.full_url
        seen["body"] = json.loads(request.data)
        return 200, b'{"hits":[{"message":"up","severity":"info"}],"total":1}'

    text = openobserve.format_search_result(
        openobserve.search(
            "SELECT * FROM netcheck",
            _settings(),
            minutes=15,
            password="x",
            send=send,
            now=1_700_000_000,
        )
    )
    query = seen["body"]["query"]
    assert seen["url"].endswith("/api/default/_search?type=logs")
    assert query["sql"] == "SELECT * FROM netcheck"
    assert query["end_time"] == 1_700_000_000 * 1_000_000
    assert query["start_time"] == (1_700_000_000 - 15 * 60) * 1_000_000
    assert "up" in text


def test_redirects_are_not_followed() -> None:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/stolen")
            self.end_headers()

        def log_message(self, fmt, *args):  # noqa: ANN001
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(OpenObserveError, match="redirect"):
            openobserve.health(
                _settings(base_url=f"http://127.0.0.1:{port}")
            )
    finally:
        server.shutdown()
        server.server_close()


def test_offer_syslog_keeps_accepted_lines_only() -> None:
    openobserve._cached = _settings()
    openobserve.offer_syslog(SimpleNamespace(accepted=False, message="dropped"))
    assert len(openobserve._queue) == 0
    openobserve.offer_syslog(
        SimpleNamespace(
            accepted=True,
            message="filter block",
            raw="raw",
            source_ip="10.0.0.1",
            source_port=514,
            device_name="edge",
            facility_name="local0",
            severity_name="warning",
            hostname="fw",
            app_name="filterlog",
            password="nope",
        )
    )
    assert len(openobserve._queue) == 1
    row = openobserve._queue[0]
    assert row["log_type"] == "syslog"
    assert row["message"] == "filter block"
    assert row["device"] == "edge"
    assert "password" not in row
