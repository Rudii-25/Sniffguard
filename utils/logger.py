# sniffguard/utils/logger.py

import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logger():
    """Sets up the global logger for the application."""
    logger = logging.getLogger("SniffGuard")
    logger.setLevel(logging.INFO)

    # Prevent duplicate propagation to root logger
    logger.propagate = False

    # ✅ Ensure 'logs' directory exists
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "sniffguard.log")

    # Create Rotating File Handler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8"
    )

    # Create Console Handler
    console_handler = logging.StreamHandler()

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # ✅ Clear existing handlers (to avoid duplicates)
    if logger.hasHandlers():
        logger.handlers.clear()

    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


log = setup_logger()
