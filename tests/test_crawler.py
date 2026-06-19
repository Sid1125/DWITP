from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.common.models import CrawlTarget


@pytest.fixture
def mock_onion_target():
    return CrawlTarget(
        source_id="test_src",
        url="http://abc123.onion/",
        category="forum",
        status="approved",
        approved_by="analyst",
        approved_date="2026-01-01",
    )


@pytest.fixture
def mock_session():
    return MagicMock(spec=requests.Session)


class TestCrawlUrlRedirects:
    def test_no_redirect_returns_record(self, mock_session, mock_onion_target, tmp_path):
        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.iter_content.return_value = [b"Hello World"]

        mock_session.get.return_value = mock_response

        from src.crawler.main import crawl_url

        record = crawl_url(mock_session, mock_onion_target)
        assert record is not None
        assert record["source"] == "test_src"
        assert record["raw_text"] == "Hello World"
        assert record["sha256"] is not None

    def test_single_redirect_followed(self, mock_session, mock_onion_target, tmp_path):
        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        redirect_resp = MagicMock()
        redirect_resp.status_code = 301
        redirect_resp.headers = {"Location": "http://abc123.onion/landing"}

        final_resp = MagicMock()
        final_resp.status_code = 200
        final_resp.headers = {"Content-Type": "text/html"}
        final_resp.iter_content.return_value = [b"Landed"]

        mock_session.get.side_effect = [redirect_resp, final_resp]

        from src.crawler.main import crawl_url

        record = crawl_url(mock_session, mock_onion_target)
        assert record is not None
        assert record["url"] == "http://abc123.onion/landing"
        assert record["raw_text"] == "Landed"

    def test_redirect_chain_enforces_limit(self, mock_session, mock_onion_target, tmp_path):
        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        def redirect_response(url, **kw):
            resp = MagicMock()
            resp.status_code = 302
            resp.headers = {"Location": url.replace("/a", "/b")}
            return resp

        mock_session.get.side_effect = redirect_response

        from src.crawler.main import MAX_REDIRECTS, crawl_url

        record = crawl_url(mock_session, mock_onion_target)
        assert record is None
        assert mock_session.get.call_count == MAX_REDIRECTS + 1

    def test_redirect_to_private_ip_blocked(self, mock_session, mock_onion_target, tmp_path):
        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        redirect_resp = MagicMock()
        redirect_resp.status_code = 302
        redirect_resp.headers = {"Location": "http://192.168.1.1/"}

        mock_session.get.return_value = redirect_resp

        from src.crawler.main import crawl_url

        def validate_side_effect(url, **kw):
            if "192.168" in url:
                raise ValueError("SSRF blocked: private IP")
            return True

        with patch("src.crawler.main.validate_url", side_effect=validate_side_effect):
            record = crawl_url(mock_session, mock_onion_target)
            assert record is None

    def test_redirect_no_location_returns_none(self, mock_session, mock_onion_target, tmp_path):
        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        redirect_resp = MagicMock()
        redirect_resp.status_code = 301
        redirect_resp.headers = {}

        mock_session.get.return_value = redirect_resp

        from src.crawler.main import crawl_url

        record = crawl_url(mock_session, mock_onion_target)
        assert record is None

    def test_non_200_returns_none(self, mock_session, mock_onion_target, tmp_path):
        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        error_resp = MagicMock()
        error_resp.status_code = 403

        mock_session.get.return_value = error_resp

        from src.crawler.main import crawl_url

        record = crawl_url(mock_session, mock_onion_target)
        assert record is None

    def test_binary_content_skipped(self, mock_session, mock_onion_target, tmp_path):
        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        binary_resp = MagicMock()
        binary_resp.status_code = 200
        binary_resp.headers = {"Content-Type": "application/octet-stream"}

        mock_session.get.return_value = binary_resp

        from src.crawler.main import crawl_url

        record = crawl_url(mock_session, mock_onion_target)
        assert record is None

    def test_request_exception_returns_none(self, mock_session, mock_onion_target, tmp_path):
        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        mock_session.get.side_effect = requests.exceptions.ConnectionError("Tor not available")

        from src.crawler.main import crawl_url

        record = crawl_url(mock_session, mock_onion_target)
        assert record is None

    def test_size_limit_exceeded(self, mock_session, mock_onion_target, tmp_path):
        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        big_content = b"x" * (6 * 1024 * 1024)
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html"}
        resp.iter_content.return_value = [big_content[:1024], big_content[1024:2048], big_content[2048:]]

        mock_session.get.return_value = resp

        from src.crawler.main import crawl_url

        record = crawl_url(mock_session, mock_onion_target)
        assert record is None


class TestCrawlUrlCircuitRotation:
    def test_rotation_counter_increments(self, mock_session, mock_onion_target, tmp_path):
        import src.crawler.main as crawler_mod

        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html"}
        resp.iter_content.return_value = [b"test"]

        mock_session.get.return_value = resp

        crawler_mod._requests_since_circuit_rotation = 0
        crawler_mod.crawl_url(mock_session, mock_onion_target)
        assert crawler_mod._requests_since_circuit_rotation == 1

    def test_rotation_triggered_at_interval(self, mock_session, mock_onion_target, tmp_path):
        import src.crawler.main as crawler_mod

        os.environ["DWITP_AUDIT_LOG"] = str(tmp_path / "audit.log")

        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html"}
        resp.iter_content.return_value = [b"test"]

        mock_session.get.return_value = resp

        crawler_mod._requests_since_circuit_rotation = 14
        crawler_mod.crawl_url(mock_session, mock_onion_target)
        assert crawler_mod._requests_since_circuit_rotation == 15


class TestCrawlerGuard:
    def test_tor_socket_check_pass(self):
        from src.crawler.main import CrawlerGuard

        with (
            patch("socket.socket") as mock_sock,
            patch("stem.control.Controller") as mock_ctrl,
        ):
            mock_instance = MagicMock()
            mock_instance.connect_ex.return_value = 0
            mock_sock.return_value = mock_instance
            mock_ctrl.from_port.side_effect = ImportError

            guard = CrawlerGuard()
            assert guard._verify_tor_active() is True

    def test_tor_socket_check_fail(self):
        from src.crawler.main import CrawlerGuard

        with (
            patch("socket.socket") as mock_sock,
            patch("stem.control.Controller"),
        ):
            mock_instance = MagicMock()
            mock_instance.connect_ex.return_value = 1
            mock_sock.return_value = mock_instance

            guard = CrawlerGuard()
            assert guard._verify_tor_active() is False

    def test_tor_stem_check_bootstrap_not_100(self):
        from src.crawler.main import CrawlerGuard

        with (
            patch("socket.socket") as mock_sock,
            patch("stem.control.Controller") as mock_ctrl,
        ):
            mock_sock.return_value.connect_ex.return_value = 0
            mock_ctrl.from_port.return_value.__enter__.return_value.get_info.return_value = "PROGRESS=50"

            guard = CrawlerGuard()
            assert guard._verify_tor_active() is False

    def test_queue_reachable(self):
        from src.crawler.main import CrawlerGuard

        with patch("src.crawler.main.QueueClient") as mock_qc:
            mock_instance = MagicMock()
            mock_qc.return_value = mock_instance

            guard = CrawlerGuard()
            assert guard._verify_queue_reachable() is True

    def test_queue_unreachable(self):
        from src.crawler.main import CrawlerGuard

        with patch("src.crawler.main.QueueClient") as mock_qc:
            mock_instance = MagicMock()
            mock_instance.connect.side_effect = Exception("Connection refused")
            mock_qc.return_value = mock_instance

            guard = CrawlerGuard()
            assert guard._verify_queue_reachable() is False

    def test_halt_exits(self):
        from src.crawler.main import CrawlerGuard

        with (
            patch("src.crawler.main.sys.exit") as mock_exit,
            patch("src.crawler.main.audit_log") as mock_audit,
        ):
            guard = CrawlerGuard()
            guard._halt("test halt")
            mock_exit.assert_called_once_with(1)
            mock_audit.assert_called_once()


class TestRotateCircuit:
    def test_rotate_calls_stem(self):
        from src.crawler.main import rotate_tor_circuit

        with patch("stem.control.Controller") as mock_ctrl:
            mock_ctrl.from_port.return_value.__enter__.return_value = MagicMock()

            rotate_tor_circuit()

            mock_ctrl.from_port.assert_called_once()

    def test_rotate_handles_import_error(self):
        from src.crawler.main import rotate_tor_circuit

        with patch("stem.control.Controller", side_effect=ImportError):
            rotate_tor_circuit()


class TestLoadSources:
    def test_load_sources_parses_yaml(self, tmp_path):
        import src.crawler.main
        sources_file = tmp_path / "sources.yaml"
        sources_file.write_text(
            """
sources:
  - source_id: "src1"
    url: "http://abc.onion"
    category: "forum"
    status: "approved"
    approved_by: "analyst"
    approved_date: "2026-01-01"
"""
        )
        src.crawler.main.SOURCES_CONFIG = str(sources_file)
        from src.crawler.main import load_sources

        sources = load_sources()
        assert len(sources) == 1
        assert sources[0].source_id == "src1"
        assert sources[0].status == "approved"

    def test_load_sources_empty(self, tmp_path):
        import src.crawler.main
        sources_file = tmp_path / "empty.yaml"
        sources_file.write_text("sources: []\n")
        src.crawler.main.SOURCES_CONFIG = str(sources_file)
        from src.crawler.main import load_sources

        assert load_sources() == []

    def test_load_sources_filters_approved(self, tmp_path):
        import src.crawler.main
        sources_file = tmp_path / "mixed.yaml"
        sources_file.write_text(
            """
sources:
  - source_id: "good"
    url: "http://good.onion"
    category: "forum"
    status: "approved"
    approved_by: "analyst"
    approved_date: "2026-01-01"
  - source_id: "pending"
    url: "http://pending.onion"
    category: "forum"
    status: "pending"
    approved_by: ""
    approved_date: ""
  - source_id: "retired"
    url: "http://retired.onion"
    category: "market"
    status: "retired"
    approved_by: "analyst"
    approved_date: "2026-02-01"
"""
        )
        src.crawler.main.SOURCES_CONFIG = str(sources_file)
        from src.crawler.main import load_sources

        sources = load_sources()
        approved = [s for s in sources if s.status == "approved"]
        assert len(approved) == 1
        assert approved[0].source_id == "good"


class TestFlushPublishBuffer:
    def test_empty_buffer_returns_immediately(self):
        import src.crawler.main as m
        m._publish_buffer.clear()
        client = MagicMock()
        m.flush_publish_buffer(client)
        client.publish.assert_not_called()

    def test_flush_publishes_buffered_records(self):
        import src.crawler.main as m
        m._publish_buffer.clear()
        m._publish_buffer.append({"id": "r1"})
        m._publish_buffer.append({"id": "r2"})
        client = MagicMock()
        m.flush_publish_buffer(client)
        assert client.publish.call_count == 2
        assert len(m._publish_buffer) == 0

    def test_flush_retains_failed_records(self):
        import src.crawler.main as m
        m._publish_buffer.clear()
        m._publish_buffer.append({"id": "r1"})
        m._publish_buffer.append({"id": "r2"})
        client = MagicMock()
        client.publish.side_effect = [None, Exception("queue down")]
        m.flush_publish_buffer(client)
        assert len(m._publish_buffer) == 1
        assert m._publish_buffer[0]["id"] == "r2"


class TestPublishOrBuffer:
    def test_publish_success(self):
        import src.crawler.main as m
        m._publish_buffer.clear()
        client = MagicMock()
        m.publish_or_buffer(client, "q", {"id": "r1"})
        client.publish.assert_called_once_with("q", {"id": "r1"})
        assert len(m._publish_buffer) == 0

    def test_publish_failure_buffers(self):
        import src.crawler.main as m
        m._publish_buffer.clear()
        client = MagicMock()
        client.publish.side_effect = RuntimeError("queue down")
        m.publish_or_buffer(client, "q", {"id": "r1"})
        assert len(m._publish_buffer) == 1
        assert m._publish_buffer[0]["id"] == "r1"


class TestCrawlerGuardAssertNominal:
    def test_all_checks_pass(self):
        from src.crawler.main import CrawlerGuard
        guard = CrawlerGuard()
        with (
            patch.object(guard, "_verify_tor_active", return_value=True),
            patch.object(guard, "_verify_queue_reachable", return_value=True),
            patch.object(guard, "_halt") as mock_halt,
        ):
            mock_session = MagicMock()
            guard.assert_nominal(mock_session)
            mock_halt.assert_not_called()

    def test_tor_check_fails(self):
        from src.crawler.main import CrawlerGuard
        guard = CrawlerGuard()
        with (
            patch.object(guard, "_verify_tor_active", return_value=False),
            patch.object(guard, "_verify_queue_reachable", return_value=True),
            patch.object(guard, "_halt") as mock_halt,
        ):
            mock_session = MagicMock()
            guard.assert_nominal(mock_session)
            mock_halt.assert_called_once()

    def test_queue_check_fails(self):
        from src.crawler.main import CrawlerGuard
        guard = CrawlerGuard()
        with (
            patch.object(guard, "_verify_tor_active", return_value=True),
            patch.object(guard, "_verify_queue_reachable", return_value=False),
            patch.object(guard, "_halt") as mock_halt,
        ):
            mock_session = MagicMock()
            guard.assert_nominal(mock_session)
            mock_halt.assert_called_once()


class TestRotateCircuitExtended:
    def test_rotate_with_password(self):
        import src.crawler.main as m
        with (
            patch("stem.control.Controller") as mock_ctrl,
            patch.dict(os.environ, {"TOR_CONTROL_PASSWORD": "secret123"}),
        ):
            import importlib
            importlib.reload(m)
            m.rotate_tor_circuit()
            mock_ctrl.from_port.assert_called_once()
            _, kwargs = mock_ctrl.from_port.call_args
            assert kwargs.get("password") == "secret123"

    def test_rotate_handles_other_error(self):
        from src.crawler.main import rotate_tor_circuit
        with (
            patch("stem.control.Controller.from_port", side_effect=ConnectionError("refused")),
            patch("src.crawler.main.audit_log") as mock_audit,
        ):
            rotate_tor_circuit()
            mock_audit.assert_called_once()


class TestCrawlerGuardVerifyTorExtended:
    def test_socket_exception_returns_false(self):
        from src.crawler.main import CrawlerGuard
        with (
            patch("socket.socket") as mock_sock,
            patch("stem.control.Controller"),
        ):
            mock_sock.side_effect = OSError("permission denied")
            guard = CrawlerGuard()
            result = guard._verify_tor_active()
            assert result is False

    def test_stem_exception_returns_false(self):
        from src.crawler.main import CrawlerGuard
        with (
            patch("socket.socket") as mock_sock,
            patch("stem.control.Controller") as mock_ctrl,
        ):
            mock_sock.return_value.connect_ex.return_value = 0
            mock_ctrl.from_port.return_value.__enter__.return_value.authenticate.side_effect = RuntimeError("auth fail")
            guard = CrawlerGuard()
            result = guard._verify_tor_active()
            assert result is False


class TestCrawlUrlEdgeCases:
    def test_negative_max_redirects_fallthrough(self, mock_session, mock_onion_target):
        import src.crawler.main as m
        with patch.object(m, "MAX_REDIRECTS", -1):
            record = m.crawl_url(mock_session, mock_onion_target)
            assert record is None


class TestCrawlLoop:
    @patch("src.crawler.main.time.sleep")
    def test_crawl_loop_with_source(self, mock_sleep):
        import src.crawler.main as m
        m._publish_buffer.clear()
        target = CrawlTarget(
            source_id="src1", url="http://abc.onion", category="forum",
            status="approved", approved_by="a", approved_date="2026-01-01",
        )
        with (
            patch.object(m.CrawlerGuard, "assert_nominal"),
            patch("src.crawler.main.load_sources", return_value=[target]),
            patch("src.crawler.main.crawl_url", return_value={"id": "r1"}),
            patch("src.crawler.main.QueueClient") as mock_qc,
            patch.object(m, "_requests_since_circuit_rotation", 0),
        ):
            m.crawl_loop()
            mock_qc.return_value.publish.assert_called_once()
            mock_qc.return_value.close.assert_called_once()

    @patch("src.crawler.main.time.sleep")
    def test_crawl_loop_no_sources(self, mock_sleep):
        import src.crawler.main as m
        m._publish_buffer.clear()
        with (
            patch.object(m.CrawlerGuard, "assert_nominal"),
            patch("src.crawler.main.load_sources", return_value=[]),
            patch("src.crawler.main.QueueClient"),
        ):
            m.crawl_loop()

    @patch("src.crawler.main.time.sleep")
    def test_crawl_loop_circuit_rotation(self, mock_sleep):
        import src.crawler.main as m
        m._publish_buffer.clear()
        target = CrawlTarget(
            source_id="src1", url="http://abc.onion", category="forum",
            status="approved", approved_by="a", approved_date="2026-01-01",
        )
        with (
            patch.object(m.CrawlerGuard, "assert_nominal"),
            patch("src.crawler.main.load_sources", return_value=[target]),
            patch("src.crawler.main.crawl_url", return_value=None),
            patch("src.crawler.main.QueueClient"),
            patch.object(m, "_requests_since_circuit_rotation", 50),
            patch.object(m, "CIRCUIT_ROTATION_INTERVAL", 50),
            patch.object(m, "rotate_tor_circuit") as mock_rotate,
        ):
            m.crawl_loop()
            mock_rotate.assert_called_once()

    @patch("src.crawler.main.time.sleep")
    def test_crawl_loop_buffer_remaining_warning(self, mock_sleep):
        import src.crawler.main as m
        m._publish_buffer.clear()
        with (
            patch.object(m.CrawlerGuard, "assert_nominal"),
            patch("src.crawler.main.load_sources", return_value=[]),
            patch("src.crawler.main.QueueClient") as mock_qc,
            patch("src.crawler.main.audit_log") as mock_audit,
        ):
            mock_qc.return_value.publish.side_effect = RuntimeError("queue down")
            m._publish_buffer.append({"id": "r1"})
            m.crawl_loop()
            found = any(
                call.args == ("crawl_buffer_remaining", {"count": 1})
                and call.kwargs == {"severity": "WARNING"}
                for call in mock_audit.call_args_list
            )
            assert found, f"Expected crawl_buffer_remaining call not found in {mock_audit.call_args_list}"


class TestModuleEntry:
    pass


class TestMain:
    @patch("src.crawler.main.time.sleep")
    def test_main_calls_crawl_loop(self, mock_sleep):
        import src.crawler.main as m
        with (
            patch.object(m, "crawl_loop") as mock_loop,
            pytest.raises(SystemExit),
        ):
            mock_loop.side_effect = KeyboardInterrupt
            m.main()
        mock_loop.assert_called_once()

    @patch("src.crawler.main.time.sleep")
    @patch("src.crawler.main.audit_log")
    def test_main_retries_on_error_then_exits(self, mock_audit, mock_sleep):
        import src.crawler.main as m
        with (
            patch.object(m, "crawl_loop", side_effect=[RuntimeError("transient"), KeyboardInterrupt]),
            pytest.raises(SystemExit),
        ):
            m.main()
        assert mock_audit.call_count >= 1
