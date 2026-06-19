from __future__ import annotations

import json
import os
import ssl
import time
from typing import Callable, Optional

import pika

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", "5671"))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "dwitp")
RABBITMQ_PASSWORD = os.environ.get("RABBITMQ_PASSWORD", "dwitp")
RABBITMQ_USE_SSL = os.environ.get("RABBITMQ_USE_SSL", "true").lower() == "true"
RABBITMQ_CA_CRT = os.environ.get("RABBITMQ_CA_CRT", "/etc/dwitp/tls/ca/ca.crt")
RABBITMQ_CLIENT_CRT = os.environ.get("RABBITMQ_CLIENT_CRT", "")
RABBITMQ_CLIENT_KEY = os.environ.get("RABBITMQ_CLIENT_KEY", "")

QUEUES = {
    "raw.crawl": {"durable": True},
    "sanitized": {"durable": True},
    "analysis.ready": {"durable": True},
    "ai.input": {"durable": True},
    "ai.output": {"durable": True},
    "classified": {"durable": True},
    "discovery.candidate": {"durable": True},
    "telegram.raw": {"durable": True},
}


class QueueClient:
    """Long-lived RabbitMQ client. One connection per service lifetime.
    Connection-per-message is forbidden per DEV-001."""

    def __init__(self) -> None:
        self._connection: Optional[pika.BlockingConnection] = None
        self._channel: Optional[pika.channel.Channel] = None
        self._params = self._build_params()

    def _build_params(self) -> pika.ConnectionParameters:
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASSWORD)
        ssl_options = None
        if RABBITMQ_USE_SSL:
            try:
                context = ssl.create_default_context(cafile=RABBITMQ_CA_CRT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_REQUIRED
                if RABBITMQ_CLIENT_CRT and RABBITMQ_CLIENT_KEY:
                    context.load_cert_chain(RABBITMQ_CLIENT_CRT, RABBITMQ_CLIENT_KEY)
                ssl_options = pika.SSLOptions(context)
            except FileNotFoundError:
                pass
        return pika.ConnectionParameters(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            credentials=credentials,
            virtual_host="/dwitp",
            heartbeat=600,
            blocked_connection_timeout=300,
            connection_attempts=3,
            retry_delay=2.0,
            ssl_options=ssl_options,
        )

    def connect(self) -> None:
        if self._connection and self._connection.is_open:
            return
        self._connection = pika.BlockingConnection(self._params)
        self._channel = self._connection.channel()
        self._declare_queues()

    def _declare_queues(self) -> None:
        if not self._channel:
            return
        for queue_name, kwargs in QUEUES.items():
            self._channel.queue_declare(queue=queue_name, **kwargs)

    def publish(self, queue: str, message: dict) -> None:
        self.connect()
        if not self._channel:
            raise RuntimeError("Channel not available")
        self._channel.basic_publish(
            exchange="",
            routing_key=queue,
            body=json.dumps(message, default=str),
            properties=pika.BasicProperties(
                delivery_mode=2,
                content_type="application/json",
            ),
        )

    def start_consumer(
        self,
        queue: str,
        callback: Callable,
        prefetch_count: int = 1,
    ) -> None:
        self.connect()
        if not self._channel:
            raise RuntimeError("Channel not available")
        self._channel.basic_qos(prefetch_count=prefetch_count)

        def wrapper(ch, method, properties, body):
            ch.basic_ack(delivery_tag=method.delivery_tag)
            try:
                message = json.loads(body)
                callback(message)
            except Exception:
                pass

        self._channel.basic_consume(queue=queue, on_message_callback=wrapper)
        self._channel.start_consuming()

    def publish_to_exchange(self, exchange: str, message: dict) -> None:
        """Broadcast a control message to every bound listener (fanout). Used for
        operator commands like the AI processing kill switch — every consumer
        (e.g. each ai_layer replica) gets its own copy, unlike publish() where
        only one consumer of a queue receives the message."""
        self.connect()
        if not self._channel:
            raise RuntimeError("Channel not available")
        self._channel.exchange_declare(exchange=exchange, exchange_type="fanout", durable=True)
        self._channel.basic_publish(
            exchange=exchange,
            routing_key="",
            body=json.dumps(message, default=str),
            properties=pika.BasicProperties(content_type="application/json"),
        )

    def bind_fanout_queue(self, exchange: str, queue_name: str) -> None:
        self.connect()
        if not self._channel:
            raise RuntimeError("Channel not available")
        self._channel.exchange_declare(exchange=exchange, exchange_type="fanout", durable=True)
        self._channel.queue_declare(queue=queue_name, durable=False, auto_delete=True)
        self._channel.queue_bind(exchange=exchange, queue=queue_name)

    def poll_queue(self, queue_name: str) -> list[dict]:
        """Drain and return all currently-pending messages on a queue without blocking."""
        self.connect()
        if not self._channel:
            raise RuntimeError("Channel not available")
        messages: list[dict] = []
        while True:
            method_frame, _header_frame, body = self._channel.basic_get(queue=queue_name, auto_ack=True)
            if method_frame is None:
                break
            try:
                messages.append(json.loads(body))
            except json.JSONDecodeError:
                continue
        return messages

    def start_multi_consumer(
        self,
        consumers: list[tuple[str, Callable]],
        prefetch_count: int = 1,
    ) -> None:
        self.connect()
        if not self._channel:
            raise RuntimeError("Channel not available")
        self._channel.basic_qos(prefetch_count=prefetch_count)

        def make_wrapper(callback: Callable) -> Callable:
            def wrapper(ch, method, properties, body):
                ch.basic_ack(delivery_tag=method.delivery_tag)
                try:
                    message = json.loads(body)
                    callback(message)
                except Exception:
                    pass
            return wrapper

        for queue, callback in consumers:
            self._channel.basic_consume(queue=queue, on_message_callback=make_wrapper(callback))
        self._channel.start_consuming()

    def consume_multi_with_retry(
        self,
        consumers: list[tuple[str, Callable]],
        prefetch_count: int = 1,
        max_retries: int = 12,
        retry_delay: float = 5.0,
    ) -> None:
        attempt = 0
        while True:
            try:
                self.start_multi_consumer(consumers, prefetch_count)
            except Exception as e:
                attempt += 1
                if attempt >= max_retries:
                    from src.common.notifier import notify_critical
                    notify_critical("queue_consumer_max_retries", {
                        "queues": [q for q, _ in consumers],
                        "attempts": attempt,
                        "error": str(e),
                    })
                    raise
                from src.common.security import audit_log
                audit_log("queue_consumer_reconnect", {
                    "queues": [q for q, _ in consumers],
                    "attempt": attempt,
                    "max_retries": max_retries,
                    "error": str(e),
                }, severity="WARNING")
                time.sleep(retry_delay * min(attempt, 5))
                self.reconnect()

    def is_connected(self) -> bool:
        return self._connection is not None and self._connection.is_open and self._channel is not None

    def reconnect(self) -> None:
        self.close()
        self.connect()

    def consume_with_retry(
        self,
        queue: str,
        callback: Callable,
        prefetch_count: int = 1,
        max_retries: int = 12,
        retry_delay: float = 5.0,
    ) -> None:
        attempt = 0
        while True:
            try:
                self.start_consumer(queue, callback, prefetch_count)
            except Exception as e:
                attempt += 1
                if attempt >= max_retries:
                    from src.common.notifier import notify_critical
                    notify_critical("queue_consumer_max_retries", {
                        "queue": queue,
                        "attempts": attempt,
                        "error": str(e),
                    })
                    raise
                from src.common.security import audit_log
                audit_log("queue_consumer_reconnect", {
                    "queue": queue,
                    "attempt": attempt,
                    "max_retries": max_retries,
                    "error": str(e),
                }, severity="WARNING")
                time.sleep(retry_delay * min(attempt, 5))
                self.reconnect()

    def close(self) -> None:
        if self._connection and self._connection.is_open:
            self._connection.close()
        self._connection = None
        self._channel = None
