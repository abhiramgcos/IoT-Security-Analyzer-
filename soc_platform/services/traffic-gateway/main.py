import os
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    logger.info("🚀 Traffic Gateway service starting...")
    logger.info(f"Mode: {os.getenv('MODE', 'monitor')}")
    logger.info(f"Interface: {os.getenv('INTERFACE', 'auto')}")
    
    # Stub service - just keep alive
    logger.info("Service running (stub implementation)")
    while True:
        time.sleep(60)
        logger.info("Traffic Gateway heartbeat...")

if __name__ == "__main__":
    main()
