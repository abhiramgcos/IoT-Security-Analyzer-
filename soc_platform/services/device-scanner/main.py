import os
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    logger.info("🔍 Device Scanner service starting...")
    logger.info(f"Scan interval: {os.getenv('SCAN_INTERVAL', '300')}s")
    
    logger.info("Service running (stub implementation)")
    while True:
        time.sleep(60)
        logger.info("Device Scanner heartbeat...")

if __name__ == "__main__":
    main()
