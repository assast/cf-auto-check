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
    TIMEOUT = int(os.getenv('TIMEOUT', 5000))  # ms
    TEST_URL = os.getenv('TEST_URL', 'https://www.cloudflare.com/cdn-cgi/trace')
    
    # Test Mode: cfip, proxyip, outbound, all
    TEST_MODE = os.getenv('TEST_MODE', 'cfip')
    
    # Enable/Disable Features
    ENABLE_LATENCY_TEST = os.getenv('ENABLE_LATENCY_TEST', 'true').lower() != 'false'
    ENABLE_SPEED_TEST = os.getenv('ENABLE_SPEED_TEST', 'false').lower() == 'true'
    ENABLE_AUTO_UPDATE = os.getenv('ENABLE_AUTO_UPDATE', 'true').lower() != 'false'
    
    # Speed Test Configuration
    SPEED_TEST_SIZE = int(os.getenv('SPEED_TEST_SIZE', 1048576))  # bytes
    SPEED_TEST_DURATION = int(os.getenv('SPEED_TEST_DURATION', 10000))  # ms
