import logging
import signal
import threading

logger = logging.getLogger(__name__)

stop_event = threading.Event()


def _handle_signal(signum: int, frame) -> None:
    sig_name = signal.Signals(signum).name
    logger.info("Received %s — graceful shutdown requested", sig_name)
    stop_event.set()


def register_signal_handlers() -> None:
    """Register handlers for SIGINT and SIGTERM. Uses a threading.Event
    so the main loop can check stop_event and exit cleanly.

    NOTE: SIGKILL / forced termination cannot be intercepted by any Python
    code — this is a hard OS-level limitation, not a bug. In that case,
    only the checkpoint file (already flushed record-by-record) survives,
    and stix_converter.py can be re-run against it standalone afterward.
    """
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
