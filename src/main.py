import time
import signal
import sys
import os
import csv
import subprocess
import platform
import urllib3
import socket
from datetime import datetime
from croniter import croniter
from .config import Config
from .logger import logger
from .api_client import ApiClient
from .telegram_notifier import TelegramNotifier

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CFAutoCheck:
    def __init__(self):
        self.api_client = ApiClient()
        self.telegram = TelegramNotifier()
        self.cron_expression = Config.CHECK_CRON
        self.concurrent_tests = Config.CONCURRENT_TESTS
        self.test_mode = Config.TEST_MODE
        self.enable_auto_update = Config.ENABLE_AUTO_UPDATE
        
        self.running = True
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.cfst_dir = os.path.join(self.base_dir, 'cfst_data')
        self.cfst_path = os.path.join(self.cfst_dir, 'cfst')
        self.ips_file = os.path.join(self.cfst_dir, 'ips.txt')
        self.result_file = os.path.join(self.cfst_dir, 'result.csv')
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.handle_exit)
        signal.signal(signal.SIGTERM, self.handle_exit)

    def handle_exit(self, signum, frame):
        logger.info("Shutdown signal received. Stopping service...")
        self.running = False
        sys.exit(0)

    def start(self):
        logger.info("CF Auto Check Service Started (Python + CFST)")
        logger.info(f"API URL: {Config.API_URL}")
        logger.info(f"Cron Schedule: {self.cron_expression}")
        logger.info(f"Test Mode: {self.test_mode}")
        
        # Run immediately on startup
        try:
            self.run_check()
        except Exception as e:
            logger.error(f"Unexpected error in initial check: {str(e)}")
        
        # Then wait for cron schedule
        cron = croniter(self.cron_expression, datetime.now())
        
        while self.running:
            next_run = cron.get_next(datetime)
            wait_seconds = (next_run - datetime.now()).total_seconds()
            
            if wait_seconds > 0:
                logger.info(f"Next check scheduled at: {next_run.strftime('%Y-%m-%d %H:%M:%S')} (in {wait_seconds:.0f}s)")
                
                # Sleep in small intervals to allow for graceful shutdown
                while wait_seconds > 0 and self.running:
                    sleep_time = min(wait_seconds, 60)  # Check every minute
                    time.sleep(sleep_time)
                    wait_seconds -= sleep_time
            
            if self.running:
                try:
                    self.run_check()
                except Exception as e:
                    logger.error(f"Unexpected error in main loop: {str(e)}")

    def run_check(self):
        logger.info("Starting check cycle...")
        
        if self.test_mode in ['all', 'cfip']:
            self.check_cf_ips()
            
        if self.test_mode in ['all', 'proxyip']:
            self.check_proxy_ips()
            
        if self.test_mode in ['all', 'outbound']:
            self.check_outbounds()
            
        logger.info("Check cycle completed")

    def check_cfst_binary(self):
        """Check and download CFST binary if not present"""
        if os.path.exists(self.cfst_path):
            return True
        
        logger.info("CFST binary not found, attempting to download...")
        
        # Determine platform
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        if system == 'darwin':
            if 'arm' in machine:
                filename = 'cfst_darwin_arm64.zip'
            else:
                filename = 'cfst_darwin_amd64.zip'
            is_zip = True
        elif system == 'linux':
            if 'arm' in machine or 'aarch' in machine:
                filename = 'cfst_linux_arm64.tar.gz'
            else:
                filename = 'cfst_linux_amd64.tar.gz'
            is_zip = False
        else:
            logger.error("Windows not supported for auto-download")
            return False
        
        version = "v2.3.4"
        base_url = f"https://github.com/XIU2/CloudflareSpeedTest/releases/download/{version}/{filename}"
        
        # Multiple mirror URLs to try
        mirrors = [
            base_url,
            f"https://ghfast.top/{base_url}",
            f"https://gh-proxy.com/{base_url}",
            f"https://ghproxy.net/{base_url}",
            f"https://mirror.ghproxy.com/{base_url}",
        ]
        
        archive_path = os.path.join(self.cfst_dir, filename)
        
        # Ensure cfst_dir exists
        os.makedirs(self.cfst_dir, exist_ok=True)
        
        for url in mirrors:
            try:
                logger.info(f"Trying to download from: {url}")
                import requests
                response = requests.get(url, timeout=60, stream=True, allow_redirects=True)
                
                # Check content length and status
                content_length = response.headers.get('content-length', '0')
                if response.status_code == 200 and int(content_length) > 1000:
                    with open(archive_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    # Extract archive
                    if is_zip:
                        import zipfile
                        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                            zip_ref.extractall(self.cfst_dir)
                    else:
                        import tarfile
                        with tarfile.open(archive_path, 'r:gz') as tar:
                            tar.extractall(path=self.cfst_dir)
                    
                    # Remove archive file
                    os.remove(archive_path)
                    
                    # Make executable
                    os.chmod(self.cfst_path, 0o755)
                    
                    logger.info("CFST binary downloaded and extracted successfully")
                    return True
                else:
                    logger.debug(f"Download failed, status: {response.status_code}, size: {content_length}")
                    
            except Exception as e:
                logger.debug(f"Download failed from {url}: {str(e)}")
                continue
        
        logger.error("Failed to download CFST binary from all mirrors")
        return False

    def export_ips_by_port(self, cfips):
        """Group CF IPs by port and export to separate files for CFST."""
        # Store mapping from IP to original cfip for later lookup
        # Use list to handle multiple domains resolving to same IP
        self.ip_to_cfip = {}
        # Track unresolved cfips for later
        self.unresolved_cfips = []
        # Group IPs by port
        self.port_groups = {}
        
        for cfip in cfips:
            address = cfip.get('address')
            port = cfip.get('port', 443)
            
            # Check if address is a domain name
            try:
                socket.inet_aton(address)  # This is already an IP
                ip_addr = address
            except socket.error:
                # It's a domain, resolve it with multiple methods
                ip_addr = self._resolve_domain(address)
                if ip_addr is None:
                    logger.warning(f"Could not resolve {address}, will be disabled")
                    self.unresolved_cfips.append(cfip)
                    continue
                logger.info(f"Resolved {address} -> {ip_addr}")
            
            # Group by port
            if port not in self.port_groups:
                self.port_groups[port] = []
            
            # Avoid duplicate IPs in same port group
            if ip_addr not in self.port_groups[port]:
                self.port_groups[port].append(ip_addr)
            
            # Store mapping (IP -> cfip), prefer to keep existing mapping
            if ip_addr not in self.ip_to_cfip:
                self.ip_to_cfip[ip_addr] = cfip
        
        logger.info(f"Grouped {len(self.ip_to_cfip)} IPs into {len(self.port_groups)} port groups, {len(self.unresolved_cfips)} unresolved")

    def _resolve_domain(self, domain):
        """Resolve domain using multiple methods"""
        # Method 1: Standard socket resolution
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            logger.debug(f"socket.gethostbyname failed for {domain}")
        
        # Method 2: Try with getaddrinfo
        try:
            results = socket.getaddrinfo(domain, None, socket.AF_INET)
            if results:
                return results[0][4][0]
        except socket.gaierror:
            logger.debug(f"socket.getaddrinfo failed for {domain}")
        
        # Method 3: Use system dig/nslookup command
        for cmd in [['dig', '+short', domain], ['nslookup', domain]]:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        # Check if line is an IP address
                        try:
                            socket.inet_aton(line)
                            return line
                        except socket.error:
                            continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        return None


    def run_cfst_for_port(self, port, ips, top_count):
        """Run CFST for a specific port group"""
        if not self.check_cfst_binary():
            return None
        
        # Write IPs to temp file for this port
        port_ips_file = os.path.join(self.cfst_dir, f'ips_{port}.txt')
        with open(port_ips_file, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        
        port_result_file = os.path.join(self.cfst_dir, f'result_{port}.csv')
        
        # Run CFST with port-specific parameters, showing output in console
        cmd = [
            self.cfst_path,
            '-f', port_ips_file,
            '-o', port_result_file,
            '-tp', str(port),  # Specify port
            '-url', 'https://download.parallels.com/desktop/v17/17.1.1-51537/ParallelsDesktop-17.1.1-51537.dmg',
            '-dn', str(top_count),
            '-n', str(self.concurrent_tests),
            '-p', str(top_count),  # Show results in console
            '-debug'
        ]
        
        logger.info(f"Running CFST for port {port}: {' '.join(cmd)}")
        
        try:
            # Use Popen to stream output in real-time
            process = subprocess.Popen(
                cmd,
                cwd=self.cfst_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Stream output line by line
            for line in process.stdout:
                line = line.strip()
                if line:
                    print(f"[CFST:{port}] {line}")
            
            process.wait(timeout=600)
            
            if process.returncode != 0:
                logger.error(f"CFST failed for port {port} with exit code {process.returncode}")
                return None
            
            return self.parse_cfst_results(port_result_file)
            
        except subprocess.TimeoutExpired:
            process.kill()
            logger.error(f"CFST timed out for port {port}")
            return None
        except Exception as e:
            logger.error(f"Error running CFST for port {port}: {str(e)}")
            return None

    def run_cfst(self, top_count=50):
        """Run CFST for all port groups and combine results"""
        all_results = []
        
        for port, ips in self.port_groups.items():
            logger.info(f"Testing {len(ips)} IPs on port {port}")
            results = self.run_cfst_for_port(port, ips, len(ips))  # Get all results for this port
            if results:
                all_results.extend(results)
        
        if not all_results:
            return None
        
        # Sort all results based on SORT_MODE
        sort_mode = Config.SORT_MODE
        if sort_mode == 'latency':
            # Sort by latency (ascending, lower is better)
            all_results.sort(key=lambda x: x['latency'] if x['latency'] > 0 else float('inf'))
            logger.info(f"Total {len(all_results)} results from all ports, keeping top {top_count} by latency")
        else:
            # Sort by download speed (descending, higher is better) - default
            all_results.sort(key=lambda x: x['speed'], reverse=True)
            logger.info(f"Total {len(all_results)} results from all ports, keeping top {top_count} by download speed")
        return all_results[:top_count]

    def parse_cfst_results(self, result_file=None):
        """Parse CFST result.csv file"""
        if result_file is None:
            result_file = self.result_file
            
        if not os.path.exists(result_file):
            logger.error(f"Result file not found: {result_file}")
            return None
        
        results = []
        try:
            with open(result_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                header = next(reader, None)  # Skip header
                
                for row in reader:
                    if len(row) >= 6:
                        # Format: IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
                        ip_addr = row[0]
                        latency = float(row[4]) if row[4] else 0
                        speed = float(row[5]) if row[5] else 0
                        region = row[6] if len(row) > 6 else ''
                        
                        results.append({
                            'address': ip_addr,
                            'latency': latency,
                            'speed': speed,
                            'region': region
                        })
            
            logger.info(f"Parsed {len(results)} results from CFST")
            return results
            
        except Exception as e:
            logger.error(f"Error parsing CFST results: {str(e)}")
            return None

    def check_cf_ips(self):
        try:
            logger.info("Fetching CF IPs...")
            cfips = self.api_client.get_cf_ips()
            
            if not cfips:
                logger.warning("No CF IPs found")
                return
                
            logger.info(f"Found {len(cfips)} CF IPs")
            
            # Group IPs by port (this also populates self.ip_to_cfip)
            self.export_ips_by_port(cfips)
            
            # Run CFST
            cfst_results = self.run_cfst(top_count=50)
            
            if cfst_results is None:
                logger.error("CFST failed, no results to update")
                return
            
            # Get top 50 IPs from CFST results
            top_ips = set(r['address'] for r in cfst_results[:50])
            
            # Create mapping from resolved IP to CFST result
            ip_to_result = {r['address']: r for r in cfst_results}
            
            # Update API using ip_to_cfip mapping
            if self.enable_auto_update:
                for ip_addr, cfip in self.ip_to_cfip.items():
                    ip_id = cfip.get('id')
                    original_addr = cfip.get('address')
                    
                    result = ip_to_result.get(ip_addr)
                    
                    if result:
                        should_enable = ip_addr in top_ips
                        latency_str = f"{result['latency']:.2f}ms"
                        speed_str = f"{result['speed']:.2f}MB/s"
                        region = result['region'] or 'Unknown'
                        
                        remark = f"{original_addr} {region}|{latency_str}|{speed_str}"
                        update_data = {
                            'remark': remark,
                            'enabled': should_enable
                        }
                        
                        status_str = "enabled" if should_enable else "disabled"
                        logger.info(f"Updating {original_addr}: {latency_str}, {speed_str} ({status_str})")
                    else:
                        # IP not in CFST results (failed test), disable it
                        update_data = {
                            'enabled': False
                        }
                        logger.info(f"Disabling {original_addr} (not in CFST results)")
                    
                    self.api_client.update_cf_ip(ip_id, update_data)
                
                # Disable unresolved cfips
                for cfip in self.unresolved_cfips:
                    self.api_client.update_cf_ip(cfip.get('id'), {'enabled': False})
                    logger.info(f"Disabling {cfip.get('address')} (could not resolve)")
            
            logger.info(f"CF IP checks completed. Top {len(top_ips)} IPs enabled.")
            
            # Send Telegram notification
            self.telegram.send_cfip_results(cfst_results, top_count=50)
            
        except Exception as e:
            logger.error(f"Error checking CF IPs: {str(e)}")

    def check_proxy_ips(self):
        pass

    def check_outbounds(self):
        pass

if __name__ == "__main__":
    service = CFAutoCheck()
    service.start()
