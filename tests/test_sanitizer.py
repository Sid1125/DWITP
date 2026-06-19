from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestMainFunction:
    def test_startup_and_consumer(self):
        mock_client = MagicMock()
        with (
            patch("src.sanitizer.main.QueueClient", return_value=mock_client),
            pytest.raises(SystemExit),
        ):
            mock_client.consume_with_retry.side_effect = KeyboardInterrupt
            from src.sanitizer.main import main
            main()
        mock_client.consume_with_retry.assert_called_once()
        assert mock_client.consume_with_retry.call_args[0][0] == "raw.crawl"
        mock_client.close.assert_called_once()

    def test_keyboard_interrupt_exit_code(self):
        mock_client = MagicMock()
        with (
            patch("src.sanitizer.main.QueueClient", return_value=mock_client),
            pytest.raises(SystemExit) as exc,
        ):
            mock_client.consume_with_retry.side_effect = KeyboardInterrupt
            from src.sanitizer.main import main
            main()
        assert exc.value.code == 0

    def test_main_calls_consume_with_retry_callback(self):
        mock_client = MagicMock()
        cb_container = {}

        def capture_cb(queue, cb):
            cb_container["cb"] = cb
            cb({"record_id": "r1"})

        mock_client.consume_with_retry.side_effect = capture_cb
        with (
            patch("src.sanitizer.main.QueueClient", return_value=mock_client),
            patch("src.sanitizer.main.process_raw_record") as mock_process,
        ):
            from src.sanitizer.main import main
            main()
        mock_process.assert_called_once_with({"record_id": "r1"}, mock_client)


class TestProcessRawRecord:
    @pytest.fixture
    def mock_client(self):
        return MagicMock()

    def test_safe_parse_strips_dangerous_tags(self, mock_client, tmp_path):
        import src.common.security
        src.common.security.AUDIT_LOG_PATH = str(tmp_path / "audit.log")

        from src.sanitizer.main import process_raw_record

        msg = {
            "record_id": "r1",
            "source": "test",
            "url": "http://abc.onion/",
            "raw_text": '<p>Hello</p><img src="http://evil.com/tracker"><script>alert(1)</script><iframe src="http://evil.com"></iframe>',
        }
        process_raw_record(msg, mock_client)

        published = mock_client.publish.call_args
        assert published is not None
        args, _ = published
        record = args[1]
        assert "Hello" in record["content_sanitized"]
        assert "<img" not in record["content_sanitized"]
        assert "<script" not in record["content_sanitized"]
        assert "<iframe" not in record["content_sanitized"]

    def test_injection_gateway_still_runs(self, mock_client, tmp_path):
        import src.common.security
        src.common.security.AUDIT_LOG_PATH = str(tmp_path / "audit.log")

        from src.sanitizer.main import process_raw_record

        msg = {
            "record_id": "r2",
            "source": "test",
            "url": "http://abc.onion/",
            "raw_text": "Normal content here",
        }
        process_raw_record(msg, mock_client)

        published = mock_client.publish.call_args
        assert published is not None
        args, _ = published
        record = args[1]
        assert "Normal content here" in record["content_sanitized"]
        assert record["injection_patterns_detected"] == []

    def test_output_structure(self, mock_client, tmp_path):
        import src.common.security
        src.common.security.AUDIT_LOG_PATH = str(tmp_path / "audit.log")

        from src.sanitizer.main import process_raw_record

        msg = {
            "record_id": "r3",
            "source": "src1",
            "url": "http://abc.onion/",
            "sha256": "abc123",
            "timestamp_utc": "2026-06-08T00:00:00",
            "raw_text": "test",
        }
        process_raw_record(msg, mock_client)

        published = mock_client.publish.call_args
        assert published is not None
        args, _ = published
        assert args[0] == "sanitized"
        record = args[1]
        assert record["record_id"] == "r3"
        assert record["source"] == "src1"
        assert record["url"] == "http://abc.onion/"
        assert record["sha256"] == "abc123"
        assert record["collected_at"] == "2026-06-08T00:00:00"
        assert "sanitized_at" in record
