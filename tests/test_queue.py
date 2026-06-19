from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_pika():
    with patch("src.common.queue.pika") as mock:
        yield mock


class TestQueueClientInit:
    def test_creates_params(self, mock_pika):
        from src.common.queue import QueueClient

        client = QueueClient()
        assert client._connection is None
        assert client._channel is None
        mock_pika.ConnectionParameters.assert_called_once()

    def test_params_use_env_vars(self, mock_pika):
        import src.common.queue as queue_mod
        queue_mod.RABBITMQ_HOST = "myhost"
        queue_mod.RABBITMQ_PORT = 5673
        queue_mod.RABBITMQ_USER = "myuser"
        queue_mod.RABBITMQ_PASSWORD = "mypass"

        from src.common.queue import QueueClient

        QueueClient()
        kwargs = mock_pika.ConnectionParameters.call_args[1]
        assert kwargs["host"] == "myhost"
        assert kwargs["port"] == 5673


class TestQueueClientConnect:
    def test_connect_creates_connection_and_channel(self, mock_pika):
        from src.common.queue import QueueClient

        mock_conn = MagicMock()
        mock_channel = MagicMock()
        mock_pika.BlockingConnection.return_value = mock_conn
        mock_conn.channel.return_value = mock_channel

        client = QueueClient()
        client.connect()

        mock_pika.BlockingConnection.assert_called_once()
        mock_conn.channel.assert_called_once()
        assert client._connection is mock_conn
        assert client._channel is mock_channel

    def test_reconnect_skips_if_already_open(self, mock_pika):
        from src.common.queue import QueueClient

        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_pika.BlockingConnection.return_value = mock_conn

        client = QueueClient()
        client._connection = mock_conn
        client._channel = MagicMock()
        client.connect()

        mock_pika.BlockingConnection.assert_not_called()

    def test_connect_declares_queues(self, mock_pika):
        from src.common.queue import QUEUES, QueueClient

        mock_conn = MagicMock()
        mock_channel = MagicMock()
        mock_pika.BlockingConnection.return_value = mock_conn
        mock_conn.channel.return_value = mock_channel

        client = QueueClient()
        client.connect()

        declared_queues = {
            c[1]["queue"]
            for c in mock_channel.queue_declare.call_args_list
        }
        for q_name in QUEUES:
            assert q_name in declared_queues


class TestQueueClientPublish:
    def test_publish_sends_message(self, mock_pika):
        from src.common.queue import QueueClient

        mock_conn = MagicMock()
        mock_channel = MagicMock()
        mock_pika.BlockingConnection.return_value = mock_conn
        mock_conn.channel.return_value = mock_channel

        client = QueueClient()
        client.publish("raw.crawl", {"key": "value"})

        mock_channel.basic_publish.assert_called_once()
        call_args = mock_channel.basic_publish.call_args[1]
        assert call_args["routing_key"] == "raw.crawl"
        assert "key" in call_args["body"]

    def test_publish_auto_connects(self, mock_pika):
        from src.common.queue import QueueClient

        mock_conn = MagicMock()
        mock_channel = MagicMock()
        mock_pika.BlockingConnection.return_value = mock_conn
        mock_conn.channel.return_value = mock_channel

        client = QueueClient()
        assert client._connection is None
        client.publish("sanitized", {"data": 1})
        assert client._connection is mock_conn

    def test_publish_raises_if_no_channel(self, mock_pika):
        from src.common.queue import QueueClient

        client = QueueClient()
        client._channel = None
        client.connect = MagicMock()
        with pytest.raises(RuntimeError, match="Channel not available"):
            client.publish("raw.crawl", {})


class TestQueueClientStartConsumer:
    def test_consumer_starts_consuming(self, mock_pika):
        from src.common.queue import QueueClient

        mock_conn = MagicMock()
        mock_channel = MagicMock()
        mock_pika.BlockingConnection.return_value = mock_conn
        mock_conn.channel.return_value = mock_channel

        client = QueueClient()
        callback = MagicMock()
        client.start_consumer("sanitized", callback)

        mock_channel.basic_qos.assert_called_once_with(prefetch_count=1)
        mock_channel.basic_consume.assert_called_once()
        mock_channel.start_consuming.assert_called_once()

    def test_consumer_ack_on_success(self, mock_pika):
        from src.common.queue import QueueClient

        mock_channel = MagicMock()
        mock_conn = MagicMock()
        mock_conn.channel.return_value = mock_channel
        mock_pika.BlockingConnection.return_value = mock_conn

        client = QueueClient()
        callback = MagicMock()

        def side_effect(*args, **kwargs):
            wrapper = kwargs.get("on_message_callback") or args[1]
            wrapper(mock_channel, MagicMock(delivery_tag=1), None, b'{"ok": true}')

        mock_channel.basic_consume.side_effect = side_effect

        client.start_consumer("raw.crawl", callback)
        callback.assert_called_once_with({"ok": True})
        mock_channel.basic_ack.assert_called_once()

    def test_consumer_nack_on_failure(self, mock_pika):
        from src.common.queue import QueueClient

        mock_channel = MagicMock()
        mock_conn = MagicMock()
        mock_conn.channel.return_value = mock_channel
        mock_pika.BlockingConnection.return_value = mock_conn

        client = QueueClient()
        callback = MagicMock(side_effect=ValueError("processing failed"))

        def side_effect(*args, **kwargs):
            wrapper = kwargs.get("on_message_callback") or args[1]
            wrapper(mock_channel, MagicMock(delivery_tag=42), None, b'{"bad": true}')

        mock_channel.basic_consume.side_effect = side_effect

        with pytest.raises(ValueError):
            client.start_consumer("raw.crawl", callback)

        mock_channel.basic_nack.assert_called_once_with(
            delivery_tag=42, requeue=False
        )


class TestQueueClientClose:
    def test_close_closes_connection(self, mock_pika):
        from src.common.queue import QueueClient

        mock_conn = MagicMock()
        mock_conn.is_open = True

        client = QueueClient()
        client._connection = mock_conn
        client._channel = MagicMock()
        client.close()

        mock_conn.close.assert_called_once()
        assert client._connection is None
        assert client._channel is None

    def test_close_noop_if_no_connection(self, mock_pika):
        from src.common.queue import QueueClient

        client = QueueClient()
        client.close()


class TestQueueClientConnection:
    def test_is_connected_returns_true_when_open(self, mock_pika):
        from src.common.queue import QueueClient

        mock_conn = MagicMock()
        mock_conn.is_open = True
        client = QueueClient()
        client._connection = mock_conn
        client._channel = MagicMock()
        assert client.is_connected() is True

    def test_is_connected_returns_false_when_closed(self, mock_pika):
        from src.common.queue import QueueClient

        client = QueueClient()
        assert client.is_connected() is False

    def test_reconnect_closes_and_reopens(self, mock_pika):
        from src.common.queue import QueueClient

        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_new_conn = MagicMock()
        mock_pika.BlockingConnection.return_value = mock_new_conn

        client = QueueClient()
        client._connection = mock_conn
        client._channel = MagicMock()
        client.reconnect()

        mock_conn.close.assert_called_once()
        mock_pika.BlockingConnection.assert_called()
        assert client._connection is mock_new_conn


class TestQueueClientConsumeWithRetry:
    def test_retry_reconnects_on_failure(self, mock_pika):
        from src.common.queue import QueueClient

        mock_conn = MagicMock()
        mock_conn.is_open = True
        mock_ch = MagicMock()
        mock_ch.start_consuming.side_effect = [ConnectionError("fail"), None]
        mock_conn.channel.return_value = mock_ch
        mock_pika.BlockingConnection.return_value = mock_conn

        client = QueueClient()
        client._connection = mock_conn
        client._channel = mock_ch

        callback = MagicMock()
        with patch("src.common.queue.time.sleep"):
            with patch("src.common.security.audit_log"):
                with patch("src.common.notifier.notify_critical"):
                    with pytest.raises(ConnectionError):
                        client.consume_with_retry("raw.crawl", callback, max_retries=1, retry_delay=0.01)

        assert mock_ch.start_consuming.call_count >= 1
