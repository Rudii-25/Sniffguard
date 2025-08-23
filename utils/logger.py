# sniffguard/utils/logger.py

import logging
from logging.handlers import RotatingFileHandler

def setup_logger():
    """Sets up the global logger for the application."""
    logger = logging.getLogger('SniffGuard')
    logger.setLevel(logging.INFO)

    # Prevent propagation to avoid duplicate logs in the console
    logger.propagate = False

    # Create a rotating file handler
    handler = RotatingFileHandler(
        'logs/sniffguard.log',
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5
    )

    # Create a formatter and set it for the handler
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)

    # Add the handler to the logger
    # Check if handlers are already added to prevent duplication
    if not logger.handlers:
        logger.addHandler(handler)

    return logger

# Initialize the logger
log = setup_logger()