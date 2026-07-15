import logging
import os
import sys
from logging.handlers import RotatingFileHandler

LOG_FILE = "data/pipeline.log"
_LOG_FORMAT_CONSOLE = "%(asctime)s [%(levelname)s] %(message)s"
_LOG_FORMAT_FILE = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("sslbl_pipeline")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(_LOG_FORMAT_CONSOLE))
    logger.addHandler(console)

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT_FILE))
    logger.addHandler(file_handler)

    return logger
