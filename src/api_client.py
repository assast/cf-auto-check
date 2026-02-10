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

    def batch_update_cf_ips_api(self, updates):
        """Batch update CF IPs using the batch update API endpoint
        
        Args:
            updates: List of (id, data) tuples where data is a dict of fields to update
        
        Returns:
            Tuple of (success_count, fail_count)
        """
        if not updates:
            return (0, 0)
        
        # Convert (id, data) tuples to items with id included
        items = []
        for ip_id, data in updates:
            item = {'id': ip_id}
            item.update(data)
            items.append(item)
        
        total_count = len(items)
        logger.info(f"Starting batch update API for {total_count} items...")
        
        # Send in chunks of 50 (matching backend BATCH_SIZE)
        CHUNK_SIZE = 50
        total_success = 0
        total_failed = 0
        
        for i in range(0, len(items), CHUNK_SIZE):
            chunk = items[i:i + CHUNK_SIZE]
            try:
                result = self._retry_request('POST', '/api/cfip/batch/update', {'items': chunk})
                if result and result.get('success'):
                    chunk_success = result.get('data', {}).get('success', len(chunk))
                    chunk_failed = result.get('data', {}).get('failed', 0)
                    total_success += chunk_success
                    total_failed += chunk_failed
                else:
                    total_failed += len(chunk)
                
                progress_pct = min(i + len(chunk), total_count) / total_count * 100
                logger.info(f"Batch update progress: {min(i + len(chunk), total_count)}/{total_count} ({progress_pct:.1f}%)")
            except Exception as e:
                logger.warning(f"Batch update API failed for chunk {i//CHUNK_SIZE + 1}: {str(e)}, falling back to individual updates")
                # Fallback to individual updates for this chunk
                for item in chunk:
                    ip_id = item.pop('id')
                    try:
                        self.update_cf_ip(ip_id, item)
                        total_success += 1
                    except Exception as e2:
                        total_failed += 1
                        logger.error(f"Individual update failed for {ip_id}: {str(e2)}")
        
        logger.info(f"Batch update completed: {total_success} success, {total_failed} failed")
        return (total_success, total_failed)

    def batch_status_cf_ips(self, ids, status):
        """Batch update status for multiple CF IPs using the batch status API
        
        Args:
            ids: List of CF IP IDs
            status: New status ('enabled', 'disabled', 'invalid')
        
        Returns:
            bool: True if successful
        """
        if not ids:
            return True
        
        try:
            result = self._retry_request('POST', '/api/cfip/batch/status', {
                'ids': ids,
                'status': status
            })
            if result and result.get('success'):
                logger.info(f"Batch status update: {len(ids)} IPs set to {status}")
                return True
            return False
        except Exception as e:
            logger.error(f"Batch status update failed: {str(e)}")
            return False

    def batch_update_cf_ips(self, updates, max_workers=10):
        """Batch update CF IPs using concurrent requests (legacy fallback)
        
        Args:
            updates: List of (id, data) tuples
            max_workers: Max concurrent requests (default 10)
        
        Returns:
            Tuple of (success_count, fail_count)
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        success_count = 0
        fail_count = 0
        total_count = len(updates)
        completed_count = 0
        
        logger.info(f"Starting batch update (concurrent) for {total_count} items...")
        
        def update_single(id_data):
            id, data = id_data
            try:
                result = self.update_cf_ip(id, data)
                return (id, True, result)
            except Exception as e:
                return (id, False, str(e))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(update_single, item): item for item in updates}
            
            for future in as_completed(futures):
                id, success, _ = future.result()
                completed_count += 1
                if success:
                    success_count += 1
                else:
                    fail_count += 1
                
                if completed_count % 10 == 0 or completed_count == total_count:
                    progress_pct = (completed_count / total_count) * 100
                    logger.info(f"Progress: {completed_count}/{total_count} ({progress_pct:.1f}%) - Success: {success_count}, Failed: {fail_count}")
        
        logger.info(f"Batch update completed: {success_count} success, {fail_count} failed")
        return (success_count, fail_count)
