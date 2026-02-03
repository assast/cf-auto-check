import subprocess
import time
import requests
import platform
import re
import socket
from urllib.parse import urlparse
from .config import Config
from .logger import logger

class Tester:
    def __init__(self):
        self.timeout = Config.TIMEOUT / 1000.0  # seconds
        self.test_url = Config.TEST_URL
        self.speed_test_size = Config.SPEED_TEST_SIZE
        self.speed_test_duration = Config.SPEED_TEST_DURATION / 1000.0  # seconds
    
    def test_latency(self, address, port=443):
        """
        Test latency using system ping command.
        Returns latency in ms, or -1 if failed.
        """
        try:
            # Determine ping command based on OS
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '3', address]
            
            # Start time mostly for fallback, ping output is more accurate for latency
            start_time = time.time()
            
            # Run ping
            result = subprocess.run(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout + 2  # Give ping slightly more time than config timeout
            )
            
            if result.returncode != 0:
                logger.debug(f"Ping failed for {address}: {result.stderr}")
                return -1
                
            # Parse output for average time
            # Linux/Mac: "min/avg/max/mdev = 35.144/35.205/35.262/0.048 ms"
            # Windows: "Average = 35ms"
            output = result.stdout
            
            # Regex for Linux/Mac
            match = re.search(r'min/avg/max/(?:mdev|stddev) = [\d\.]+/([\d\.]+)/', output)
            if match:
                return float(match.group(1))
                
            # Regex for Windows
            match = re.search(r'Average = (\d+)ms', output)
            if match:
                return float(match.group(1))
            
            # Fallback if parsing failed but exit code was 0
            return (time.time() - start_time) * 1000 / 3
            
        except subprocess.TimeoutExpired:
            return -1
        except Exception as e:
            logger.error(f"Error pinging {address}: {str(e)}")
            return -1

    def test_speed(self, address, port=443):
        """
        Test download speed.
        Returns speed in bytes per second.
        """
        try:
            parsed_url = urlparse(self.test_url)
            hostname = parsed_url.hostname
            
            # Construct requests to the IP but with Host header
            url = f"{parsed_url.scheme}://{address}{parsed_url.path}"
            headers = {'Host': hostname}
            
            start_time = time.time()
            bytes_received = 0
            
            with requests.get(url, headers=headers, stream=True, timeout=self.speed_test_duration, verify=False) as response:
                if response.status_code != 200:
                    return 0
                
                for chunk in response.iter_content(chunk_size=8192):
                    bytes_received += len(chunk)
                    elapsed = time.time() - start_time
                    if elapsed >= self.speed_test_duration:
                        break
            
            duration = time.time() - start_time
            if duration <= 0:
                duration = 0.001
                
            speed = bytes_received / duration
            return int(speed)
            
        except Exception as e:
            logger.debug(f"Speed test failed for {address}: {str(e)}")
            return 0

    def test_proxy_latency(self, address):
        """
        Test proxy latency. For HTTP/HTTPS proxies, verify connection.
        For now using simple HTTP check or Ping as fallback.
        """
        if address.startswith('http') or address.startswith('https'):
            # Parse IP/Host from URL
            try:
                parsed = urlparse(address)
                host = parsed.hostname
                return self.test_latency(host)
            except:
                return -1
        
        # Assume it's an IP or Host
        return self.test_latency(address)

    def get_ip_location(self, address):
        """
        Get IP location info.
        First resolves domain to IP if needed, then queries ip-api.com.
        Returns dict with country and organization (ASN).
        """
        try:
            # Resolve domain to IP if it's not already an IP
            try:
                socket.inet_aton(address)  # Check if it's already an IP
                ip = address
            except socket.error:
                # It's a domain, resolve it
                try:
                    ip = socket.gethostbyname(address)
                except socket.gaierror:
                    logger.debug(f"Could not resolve {address}")
                    return {'country': 'Unknown', 'org': 'Unknown'}
            
            # Use ip-api.com (free, no key, 45 req/min limit)
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,org",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country = data.get('countryCode', 'Unknown')
                    org = data.get('isp') or data.get('org') or 'Unknown'
                    return {'country': country, 'org': org}
                    
            return {'country': 'Unknown', 'org': 'Unknown'}
        except Exception as e:
            logger.debug(f"Geo lookup failed for {address}: {str(e)}")
            return {'country': 'Unknown', 'org': 'Unknown'}
