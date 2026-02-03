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
    
    # Test Configuration
    CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', 3600))  # seconds
    CONCURRENT_TESTS = int(os.getenv('CONCURRENT_TESTS', 5))
    
    # Test Mode: cfip, proxyip, outbound, all
    TEST_MODE = os.getenv('TEST_MODE', 'cfip')
    
    # Enable/Disable Auto Update
    ENABLE_AUTO_UPDATE = os.getenv('ENABLE_AUTO_UPDATE', 'true').lower() != 'false'
    
    # Telegram Notification Configuration
    TG_ENABLED = os.getenv('TG_ENABLED', 'false').lower() == 'true'
    TG_BOT_TOKEN = os.getenv('TG_BOT_TOKEN', '')
    TG_CHAT_ID = os.getenv('TG_CHAT_ID', '')
    TG_PROXY = os.getenv('TG_PROXY', '')  # e.g., http://127.0.0.1:7890 or socks5://127.0.0.1:1080
