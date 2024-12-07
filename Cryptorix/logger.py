import logging
import sys

# Create and configure logger
logger = logging.getLogger("Cryptorix")

# Clear existing handlers to avoid duplicate log entries
if logger.hasHandlers():
    logger.handlers.clear()

# Set up the stream handler for stdout
stream_handler = logging.StreamHandler(sys.stdout)

# Define the log message format
log_format = "[%(levelname)s] %(message)s"
formatter = logging.Formatter(log_format)
stream_handler.setFormatter(formatter)

# Add the handler to the logger and set the log level to INFO
logger.addHandler(stream_handler)
logger.setLevel(logging.INFO)

# Disable propagation to prevent duplicate logs in the root logger
logger.propagate = False
