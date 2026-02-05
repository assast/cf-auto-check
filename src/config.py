import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # API Configuration
    API_URL = os.getenv('API_URL', 'https://cfsniext.jvvv.de')
    API_KEY = os.getenv('API_KEY', '')
    
    # API Client Configuration
    API_MAX_RETRIES = int(os.getenv('API_MAX_RETRIES', 3))
    API_RETRY_DELAY = int(os.getenv('API_RETRY_DELAY', 2000))  # ms
    API_USE_SESSION_TOKEN = os.getenv('API_USE_SESSION_TOKEN', 'true').lower() == 'true'
    
    # Schedule Configuration (cron expression)
    # Default: every hour at minute 0 (0 * * * *)
    CHECK_CRON = os.getenv('CHECK_CRON', '0 * * * *')
    
    # Enable/Disable Cron Scheduler (background scheduled checks)
    ENABLE_CRON_SCHEDULER = os.getenv('ENABLE_CRON_SCHEDULER', 'true').lower() == 'true'
    
    # API Trigger Configuration
    ENABLE_API_TRIGGER = os.getenv('ENABLE_API_TRIGGER', 'false').lower() == 'true'
    API_TRIGGER_KEY = os.getenv('API_TRIGGER_KEY', '')
    API_TRIGGER_PORT = int(os.getenv('API_TRIGGER_PORT', 8080))
    
    # CFST Configuration
    CONCURRENT_TESTS = int(os.getenv('CONCURRENT_TESTS', 5))

    # Download speed test count (CFST -dn parameter)
    SPEED_TEST_COUNT = int(os.getenv('SPEED_TEST_COUNT', 20))  # Number of IPs to test download speed (after latency sort)
    SPEED_ENABLE_COUNT = int(os.getenv('SPEED_ENABLE_COUNT', 50))   # Enable top N IPs by speed
    
    # Result cache TTL in hours (skip testing if result file exists within this period)
    RESULT_CACHE_HOURS = float(os.getenv('RESULT_CACHE_HOURS', 8))

    # Test Mode: cfip, proxyip, outbound, all
    TEST_MODE = os.getenv('TEST_MODE', 'cfip')
    
    # Enable/Disable Auto Update
    ENABLE_AUTO_UPDATE = os.getenv('ENABLE_AUTO_UPDATE', 'true').lower() != 'false'
    
    # Telegram Notification Configuration
    TG_ENABLED = os.getenv('TG_ENABLED', 'false').lower() == 'true'
    TG_BOT_TOKEN = os.getenv('TG_BOT_TOKEN', '')
    TG_CHAT_ID = os.getenv('TG_CHAT_ID', '')
    TG_PROXY = os.getenv('TG_PROXY', '')  # e.g., http://127.0.0.1:7890 or socks5://127.0.0.1:1080
