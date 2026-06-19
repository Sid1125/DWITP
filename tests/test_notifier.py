from __future__ import annotations

from unittest.mock import patch

from src.common.notifier import notify_critical


class TestNotifyCritical:
    def test_falls_back_to_stderr(self, capsys):
        notify_critical("test_event", {"key": "value"})
        captured = capsys.readouterr()
        assert "test_event" in captured.err
        assert "key" in captured.err
        assert "value" in captured.err

    def test_handles_slack_webhook_failure(self, capsys):
        with patch("src.common.notifier.SLACK_WEBHOOK_URL", "https://invalid/"):
            with patch("src.common.notifier.httpx") as mock_httpx:
                mock_httpx.Client.side_effect = ImportError
                notify_critical("slack_fail", {"msg": "test"})
                captured = capsys.readouterr()
                assert "slack_fail" in captured.err

    def test_slack_raises_on_no_webhook_url(self, capsys):
        with patch("src.common.notifier.SLACK_WEBHOOK_URL", ""):
            notify_critical("no_webhook", {"msg": "test"})
            captured = capsys.readouterr()
            assert "no_webhook" in captured.err
