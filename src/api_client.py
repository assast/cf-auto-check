import requests
import time
import json
from .config import Config
from .logger import logger

class ApiClient:
    def __init__(self):
        self.api_url = Config.API_URL
        self.api_key = Config.API_KEY
        self.max_retries = Config.API_MAX_RETRIES
        self.retry_delay = Config.API_RETRY_DELAY / 1000.0  # Convert to seconds
        self.use_session_token = Config.API_USE_SESSION_TOKEN
        self.session_token = None
        
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json'
        })

    def _get_headers(self):
        token = self.session_token if self.session_token else self.api_key
        headers = {
            'Content-Type': 'application/json'
        }
        if token:
            headers['X-API-Key'] = token
        return headers

    def login(self):
        try:
            response = requests.post(
                f"{self.api_url}/api/auth/login",
                json={'apiKey': self.api_key},
                timeout=30
            )
            data = response.json()
            
            if data.get('success') and data.get('apiKey'):
                self.session_token = data.get('apiKey')
                return True
            return False
        except Exception as e:
            logger.error(f"Login failed: {str(e)}")
            return False

    def ensure_authenticated(self):
        if self.use_session_token and not self.session_token:
            self.login()

    def _retry_request(self, method, endpoint, data=None):
        url = f"{self.api_url}{endpoint}"
        
        for i in range(self.max_retries):
            try:
                self.ensure_authenticated()
                headers = self._get_headers()
                
                if method == 'GET':
                    response = self.session.get(url, headers=headers, timeout=30)
                elif method == 'PUT':
                    response = self.session.put(url, headers=headers, json=data, timeout=30)
                elif method == 'POST':
                    response = self.session.post(url, headers=headers, json=data, timeout=30)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                    
                response.raise_for_status()
                return response.json()
                
            except requests.exceptions.HTTPError as e:
                is_last_retry = (i == self.max_retries - 1)
                
                if e.response.status_code == 401:
                    # Token might be expired, reset and retry
                    self.session_token = None
                    self.login()
                
                if is_last_retry:
                    logger.error(f"Request failed after {self.max_retries} retries: {str(e)}")
                    # Try to parse error message from response
                    try:
                        error_data = e.response.json()
                        logger.error(f"Server response: {json.dumps(error_data)}")
                    except:
                        pass
                    raise
                
                time.sleep(self.retry_delay * (i + 1))
                
            except Exception as e:
                if i == self.max_retries - 1:
                    logger.error(f"Request failed: {str(e)}")
                    raise
                time.sleep(self.retry_delay * (i + 1))
                
        return None

    def get_cf_ips(self):
        try:
            data = self._retry_request('GET', '/api/cfip')
            return data.get('data', [])
        except Exception as e:
            logger.error(f"Failed to get CF IPs: {str(e)}")
            return []

    def update_cf_ip(self, id, data):
        try:
            return self._retry_request('PUT', f'/api/cfip/{id}', data)
        except Exception as e:
            logger.error(f"Failed to update CF IP {id}: {str(e)}")
            return None

    def get_proxy_ips(self):
        try:
            data = self._retry_request('GET', '/api/proxyip')
            return data.get('data', [])
        except Exception as e:
            logger.error(f"Failed to get Proxy IPs: {str(e)}")
            return []

    def update_proxy_ip(self, id, data):
        try:
            return self._retry_request('PUT', f'/api/proxyip/{id}', data)
        except Exception as e:
            logger.error(f"Failed to update Proxy IP {id}: {str(e)}")
            return None

    def get_outbounds(self):
        try:
            data = self._retry_request('GET', '/api/outbound')
            return data.get('data', [])
        except Exception as e:
            logger.error(f"Failed to get Outbounds: {str(e)}")
            return []

    def update_outbound(self, id, data):
        try:
            return self._retry_request('PUT', f'/api/outbound/{id}', data)
        except Exception as e:
            logger.error(f"Failed to update Outbound {id}: {str(e)}")
            return None
