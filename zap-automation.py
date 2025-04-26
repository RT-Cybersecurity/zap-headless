#!/usr/bin/env python3
"""
ZAP CLI-only Automation Script (Optimized)
This script launches ZAP in headless mode directly, performs spidering (including AJAX/Decibel spidering) 
and active scanning on a specified URL, with support for authenticated scans.
"""

import os
import sys
import time
import argparse
import subprocess
import shutil
import signal
import json
import logging
import asyncio
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('zap-cli')

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Run ZAP completely headless for spider and active scan.')
    parser.add_argument('-t', '--target', required=True, help='Target URL to scan')
    parser.add_argument('-o', '--output', default='zap_report', help='Output directory for reports')
    parser.add_argument('-z', '--zap-path', default=None, help='Path to ZAP installation')
    parser.add_argument('-p', '--port', default='8080', help='Port for ZAP to listen on')
    parser.add_argument('-a', '--api-key', default='', help='ZAP API key if required')
    parser.add_argument('-s', '--spider-timeout', type=int, default=60, help='Spider timeout in minutes')
    parser.add_argument('-c', '--scan-timeout', type=int, default=120, help='Scan timeout in minutes')
    parser.add_argument('-m', '--memory', default='1G', help='Memory allocation for ZAP (e.g., 1G, 2G)')
    
    # New parameters for authentication
    parser.add_argument('--auth', action='store_true', help='Enable authentication')
    parser.add_argument('--auth-url', help='URL for authentication page')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--username-field', help='HTML field name for username')
    parser.add_argument('--password-field', help='HTML field name for password')
    parser.add_argument('--login-url', help='URL to submit login form to')
    parser.add_argument('--logged-in-regex', help='Regex pattern to identify logged-in state')
    
    # Decibel/AJAX spider option
    parser.add_argument('--decibel', action='store_true', help='Use AJAX/Decibel spider in addition to traditional spider')
    parser.add_argument('--threads', type=int, default=2, help='Number of threads for scanning')
    parser.add_argument('--scan-policy', help='Scan policy name to use')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    return parser.parse_args()

@lru_cache(maxsize=1)
def find_zap_path():
    """Try to automatically find ZAP installation path with caching."""
    # Common installation paths
    common_paths = [
        '/usr/share/zaproxy',
        '/opt/zaproxy',
        '/Applications/OWASP ZAP.app/Contents/Java',
        'C:\\Program Files\\OWASP\\Zed Attack Proxy',
        'C:\\Program Files (x86)\\OWASP\\Zed Attack Proxy'
    ]
    
    # Check for ZAP in PATH
    zap_cmd = shutil.which('zap.sh') or shutil.which('zap.bat')
    if zap_cmd:
        return os.path.dirname(os.path.dirname(zap_cmd))
    
    # Check common paths
    for path in common_paths:
        if os.path.exists(path):
            return path
    
    return None

def start_zap(zap_path, port, api_key, memory):
    """Start ZAP in daemon/headless mode with optimized memory usage."""
    if not zap_path:
        zap_path = find_zap_path()
        if not zap_path:
            logger.error("Could not find ZAP installation path. Please specify with --zap-path.")
            sys.exit(1)
    
    logger.info(f"Starting ZAP in headless mode on port {port}")
    
    # Determine which script to run based on OS
    if os.name == 'nt':  # Windows
        zap_script = os.path.join(zap_path, 'zap.bat')
    else:  # Unix/Linux/Mac
        zap_script = os.path.join(zap_path, 'zap.sh')
    
    if not os.path.exists(zap_script):
        logger.error(f"ZAP script not found at {zap_script}")
        sys.exit(1)
    
    # Build command with optimized settings
    cmd = [
        zap_script,
        '-daemon',
        '-port', port,
        '-Xmx' + memory  # Set maximum heap size
    ]
    
    # API key configuration
    if api_key:
        cmd.extend(['-config', f'api.key={api_key}'])
    else:
        cmd.extend(['-config', 'api.disablekey=true'])
    
    # Performance optimizations
    cmd.extend([
        '-config', 'connection.timeoutInSecs=60',
        '-config', 'spider.threadPerHost=5',
        '-config', 'scanner.threadPerHost=5',
        '-nostdout'  # Reduce console output for better performance
    ])
    
    # Start ZAP process
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                 universal_newlines=True)
        return process
    except Exception as e:
        logger.error(f"Error starting ZAP: {e}")
        sys.exit(1)

async def wait_for_zap_to_start_async(port, api_key='', max_attempts=10):
    """Wait for ZAP to start asynchronously."""
    base_url = f"http://localhost:{port}"
    
    logger.info("Waiting for ZAP to initialize...")
    
    for attempt in range(max_attempts):
        try:
            # Try to access ZAP API
            request = urllib.request.Request(f"{base_url}/JSON/core/view/version/")
            if api_key:
                request.add_header('X-ZAP-API-Key', api_key)
            
            with urllib.request.urlopen(request, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                version = data.get('version', 'unknown')
                logger.info(f"ZAP {version} is running")
                return True
        except (urllib.error.URLError, ConnectionRefusedError):
            logger.info(f"ZAP not responsive yet, retrying... ({attempt+1}/{max_attempts})")
            await asyncio.sleep(5)
        except json.JSONDecodeError:
            logger.info("Received invalid response, ZAP still starting...")
            await asyncio.sleep(5)
    
    logger.error("Failed to connect to ZAP after multiple attempts")
    return False

def wait_for_zap_to_start(port, api_key='', max_attempts=10):
    """Synchronous wrapper for async wait function."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(wait_for_zap_to_start_async(port, api_key, max_attempts))

def make_api_request(method, endpoint, params=None, port='8080', api_key=''):
    """Make a request to the ZAP API with caching for repeated identical requests."""
    base_url = f"http://localhost:{port}/JSON"
    url = f"{base_url}/{endpoint}"
    
    # Add parameters to request
    if params:
        query_string = urllib.parse.urlencode(params)
        url = f"{url}/?{query_string}"
    else:
        url = f"{url}/"
    
    # Create request
    request = urllib.request.Request(url)
    if api_key:
        request.add_header('X-ZAP-API-Key', api_key)
    
    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.URLError as e:
        logger.error(f"API request error: {e}")
        return None

def setup_authentication(target, auth_url, username, password, username_field, password_field, 
                        login_url, logged_in_regex, port, api_key):
    """Set up authentication in ZAP."""
    logger.info("Setting up authentication...")
    
    # Set login URL
    form_auth_url = login_url if login_url else auth_url
    
    # Configure authentication method as form-based
    auth_params = {
        'contextId': '1',
        'authMethodName': 'formBasedAuthentication',
        'authMethodConfigParams': f'loginUrl={form_auth_url}&loginRequestData={username_field}%3D{username}%26{password_field}%3D{password}'
    }
    
    make_api_request('action', 'authentication/action/setAuthenticationMethod', auth_params, port, api_key)
    
    # Create a new context
    context_name = "auth-context"
    make_api_request('action', 'context/action/newContext', {'contextName': context_name}, port, api_key)
    
    # Include target in context
    make_api_request('action', 'context/action/includeInContext', 
                    {'contextName': context_name, 'regex': target + ".*"}, port, api_key)
    
    # Set logged in indicator
    if logged_in_regex:
        make_api_request('action', 'authentication/action/setLoggedInIndicator', 
                        {'contextId': '1', 'loggedInIndicatorRegex': logged_in_regex}, port, api_key)
    
    # Create user
    user_params = {
        'contextId': '1',
        'name': username
    }
    user_response = make_api_request('action', 'users/action/newUser', user_params, port, api_key)
    
    if user_response and 'userId' in user_response:
        user_id = user_response['userId']
        
        # Set credentials
        cred_params = {
            'contextId': '1',
            'userId': user_id,
            'authCredentialsConfigParams': f'username={username}&password={password}'
        }
        make_api_request('action', 'users/action/setAuthenticationCredentials', cred_params, port, api_key)
        
        # Enable user
        make_api_request('action', 'users/action/setUserEnabled',
                        {'contextId': '1', 'userId': user_id, 'enabled': 'true'}, port, api_key)
        
        logger.info(f"Authentication configured for user: {username}")
        return True
    
    logger.error("Failed to set up authentication")
    return False

async def run_spider_async(target, port, api_key, timeout_mins, context_id=None, user_id=None):
    """Run the spider against the target asynchronously."""
    logger.info(f"Spidering target: {target}")
    
    # Parameters for spider scan
    params = {'url': target}
    
    # Add context and user if specified (for authenticated scan)
    if context_id is not None:
        params['contextId'] = context_id
    if user_id is not None:
        params['userId'] = user_id
    
    # Start the spider scan
    response = make_api_request('action', 'spider/action/scan', params, port, api_key)
    
    if not response:
        logger.error("Failed to start spider")
        return None
    
    scan_id = response.get('scan')
    if not scan_id:
        logger.error("Invalid spider response")
        return None
    
    logger.info(f"Spider started with ID: {scan_id}")
    
    # Set up time tracking
    start_time = datetime.now()
    timeout_secs = timeout_mins * 60
    last_progress = 0
    
    # Track spider progress
    while True:
        response = make_api_request('view', 'spider/view/status', 
                                  {'scanId': scan_id}, port, api_key)
        
        if not response:
            logger.error("Failed to get spider status")
            return None
        
        status = int(response.get('status', 0))
        
        # Only log if progress has changed by at least 10%
        if status - last_progress >= 10 or status == 100:
            logger.info(f"Spider progress: {status}%")
            last_progress = status
        
        if status >= 100:
            logger.info("Spider completed")
            break
        
        # Check for timeout
        elapsed = (datetime.now() - start_time).total_seconds()
        if elapsed > timeout_secs:
            logger.warning(f"Spider timed out after {timeout_mins} minutes")
            break
        
        await asyncio.sleep(10)
    
    # Allow the passive scanner to finish
    logger.info("Waiting for passive scan to complete...")
    await asyncio.sleep(5)
    
    return scan_id

def spider_target(target, port, api_key, timeout_mins, context_id=None, user_id=None):
    """Synchronous wrapper for spider_async function."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(run_spider_async(target, port, api_key, timeout_mins, context_id, user_id))

async def run_ajax_spider_async(target, port, api_key, timeout_mins, context_id=None, user_id=None):
    """Run the AJAX spider (Decibel) against the target asynchronously."""
    logger.info(f"Running AJAX/Decibel spider on target: {target}")
    
    # Parameters for AJAX spider
    params = {'url': target}
    
    # Add context and user if specified (for authenticated scan)
    if context_id is not None:
        params['contextId'] = context_id
    if user_id is not None:
        params['userId'] = user_id
    
    # Start the AJAX spider scan
    response = make_api_request('action', 'ajaxSpider/action/scan', params, port, api_key)
    
    if not response:
        logger.error("Failed to start AJAX/Decibel spider")
        return False
    
    logger.info("AJAX/Decibel spider started")
    
    # Set up time tracking
    start_time = datetime.now()
    timeout_secs = timeout_mins * 60
    
    # Track AJAX spider progress
    while True:
        response = make_api_request('view', 'ajaxSpider/view/status', None, port, api_key)
        
        if not response:
            logger.error("Failed to get AJAX/Decibel spider status")
            return False
        
        status = response.get('status')
        
        if status == 'stopped':
            logger.info("AJAX/Decibel spider completed")
            break
        
        # Check for timeout
        elapsed = (datetime.now() - start_time).total_seconds()
        if elapsed > timeout_secs:
            logger.warning(f"AJAX/Decibel spider timed out after {timeout_mins} minutes")
            # Stop the AJAX spider
            make_api_request('action', 'ajaxSpider/action/stop', None, port, api_key)
            break
        
        logger.info(f"AJAX/Decibel spider status: {status}")
        await asyncio.sleep(15)
    
    return True

def ajax_spider_target(target, port, api_key, timeout_mins, context_id=None, user_id=None):
    """Synchronous wrapper for ajax_spider_async function."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(run_ajax_spider_async(target, port, api_key, timeout_mins, context_id, user_id))

async def run_active_scan_async(target, port, api_key, timeout_mins, scan_policy=None, threads=2, context_id=None, user_id=None):
    """Run an active scan against the target asynchronously."""
    logger.info(f"Active scanning target: {target}")
    
    # Parameters for active scan
    params = {'url': target}
    
    # Add context and user if specified (for authenticated scan)
    if context_id is not None:
        params['contextId'] = context_id
    if user_id is not None:
        params['userId'] = user_id
    
    # Add scan policy if specified
    if scan_policy:
        params['scanPolicyName'] = scan_policy
    
    # Configure thread count
    make_api_request('action', 'ascan/action/setOptionThreadPerHost', 
                    {'Integer': str(threads)}, port, api_key)
    
    # Start the active scan
    response = make_api_request('action', 'ascan/action/scan', params, port, api_key)
    
    if not response:
        logger.error("Failed to start active scan")
        return None
    
    scan_id = response.get('scan')
    if not scan_id:
        logger.error("Invalid active scan response")
        return None
    
    logger.info(f"Active scan started with ID: {scan_id}")
    
    # Set up time tracking
    start_time = datetime.now()
    timeout_secs = timeout_mins * 60
    last_progress = 0
    
    # Track active scan progress
    while True:
        response = make_api_request('view', 'ascan/view/status', 
                                  {'scanId': scan_id}, port, api_key)
        
        if not response:
            logger.error("Failed to get active scan status")
            return None
        
        status = int(response.get('status', 0))
        
        # Only log if progress has changed by at least 10%
        if status - last_progress >= 10 or status == 100:
            logger.info(f"Active scan progress: {status}%")
            last_progress = status
        
        if status >= 100:
            logger.info("Active scan completed")
            break
        
        # Check for timeout
        elapsed = (datetime.now() - start_time).total_seconds()
        if elapsed > timeout_secs:
            logger.warning(f"Active scan timed out after {timeout_mins} minutes")
            break
        
        await asyncio.sleep(30)
    
    return scan_id

def active_scan(target, port, api_key, timeout_mins, scan_policy=None, threads=2, context_id=None, user_id=None):
    """Synchronous wrapper for active_scan_async function."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(run_active_scan_async(target, port, api_key, timeout_mins, scan_policy, threads, context_id, user_id))

def generate_report(output_dir, target, port, api_key):
    """Generate reports in multiple formats efficiently."""
    logger.info("Generating reports")
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Sanitize target for filename
    target_for_filename = target.replace('://', '_').replace('/', '_').replace(':', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"{output_dir}/zap_report_{target_for_filename}_{timestamp}"
    
    # Function to download a report
    def download_report(report_type, filename):
        url = f"http://localhost:{port}/OTHER/core/other/{report_type}/"
        if api_key:
            url = f"{url}?apikey={api_key}"
        
        try:
            urllib.request.urlretrieve(url, filename)
            logger.info(f"{report_type.capitalize()} report saved to: {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to download {report_type} report: {e}")
            return False
    
    # Download reports in parallel using ThreadPoolExecutor
    report_types = [
        ("htmlreport", f"{base_filename}.html"),
        ("xmlreport", f"{base_filename}.xml"),
        ("jsonreport", f"{base_filename}.json")
    ]
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(lambda x: download_report(*x), report_types))
    
    # Generate summary by parsing the JSON report
    json_filename = f"{base_filename}.json"
    try:
        if os.path.exists(json_filename):
            with open(json_filename, 'r') as f:
                report_data = json.load(f)
            
            # Count alerts by risk level
            risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            
            if 'site' in report_data:
                for site in report_data['site']:
                    if 'alerts' in site:
                        for alert in site['alerts']:
                            risk = alert.get('risk', '')
                            if risk in risk_counts:
                                risk_counts[risk] += 1
            
            logger.info("\nScan Summary:")
            logger.info(f"High Risk Issues: {risk_counts['High']}")
            logger.info(f"Medium Risk Issues: {risk_counts['Medium']}")
            logger.info(f"Low Risk Issues: {risk_counts['Low']}")
            logger.info(f"Informational Issues: {risk_counts['Informational']}")
    except Exception as e:
        logger.error(f"Error generating summary: {e}")
    
    return f"{base_filename}.html"

async def shutdown_zap_async(port, api_key, zap_process):
    """Shutdown ZAP cleanly asynchronously."""
    logger.info("Shutting down ZAP")
    
    # Try API shutdown first
    try:
        make_api_request('action', 'core/action/shutdown', None, port, api_key)
        logger.info("Waiting for ZAP to shut down...")
        
        # Wait for process to terminate
        for _ in range(10):
            if zap_process.poll() is not None:
                logger.info("ZAP has been shut down")
                return
            await asyncio.sleep(1)
    except:
        pass
    
    # Force kill if necessary
    try:
        logger.info("Forcing ZAP to shut down...")
        zap_process.terminate()
        await asyncio.sleep(2)
        if zap_process.poll() is None:
            zap_process.kill()
        logger.info("ZAP has been shut down")
    except:
        logger.error("Failed to shut down ZAP")

def shutdown_zap(port, api_key, zap_process):
    """Synchronous wrapper for shutdown_zap_async function."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(shutdown_zap_async(port, api_key, zap_process))

async def main_async():
    # Parse arguments
    args = parse_arguments()
    
    # Configure logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Start ZAP process
    zap_process = start_zap(args.zap_path, args.port, args.api_key, args.memory)
    
    try:
        # Wait for ZAP to initialize
        if not await wait_for_zap_to_start_async(args.port, args.api_key):
            logger.error("Timeout waiting for ZAP to start. Exiting.")
            await shutdown_zap_async(args.port, args.api_key, zap_process)
            sys.exit(1)
        
        # Authentication setup
        context_id = None
        user_id = None
        
        if args.auth and args.auth_url and args.username and args.password:
            logger.info("Setting up authentication...")
            
            # Create context for auth
            context_name = "auth-context"
            context_response = make_api_request('action', 'context/action/newContext', 
                                              {'contextName': context_name}, args.port, args.api_key)
            
            if context_response and 'contextId' in context_response:
                context_id = context_response['contextId']
                
                # Include target in context
                make_api_request('action', 'context/action/includeInContext', 
                                {'contextId': context_id, 'regex': args.target + ".*"}, 
                                args.port, args.api_key)
                
                # Set authentication method
                auth_method_params = {
                    'contextId': context_id,
                    'authMethodName': 'formBasedAuthentication',
                    'authMethodConfigParams': f'loginUrl={args.auth_url}&' +
                                            f'loginRequestData={args.username_field}%3D{args.username}%26' +
                                            f'{args.password_field}%3D{args.password}'
                }
                
                make_api_request('action', 'authentication/action/setAuthenticationMethod', 
                                auth_method_params, args.port, args.api_key)
                
                # Set logged in indicator if provided
                if args.logged_in_regex:
                    make_api_request('action', 'authentication/action/setLoggedInIndicator', 
                                    {'contextId': context_id, 'loggedInIndicatorRegex': args.logged_in_regex}, 
                                    args.port, args.api_key)
                
                # Create user
                user_params = {
                    'contextId': context_id,
                    'name': args.username
                }
                user_response = make_api_request('action', 'users/action/newUser', 
                                                user_params, args.port, args.api_key)
                
                if user_response and 'userId' in user_response:
                    user_id = user_response['userId']
                    
                    # Set user credentials
                    cred_params = {
                        'contextId': context_id,
                        'userId': user_id,
                        'authCredentialsConfigParams': f'username={args.username}&password={args.password}'
                    }
                    make_api_request('action', 'users/action/setAuthenticationCredentials', 
                                    cred_params, args.port, args.api_key)
                    
                    # Enable user
                    make_api_request('action', 'users/action/setUserEnabled',
                                    {'contextId': context_id, 'userId': user_id, 'enabled': 'true'}, 
                                    args.port, args.api_key)
                    
                    logger.info(f"Authentication configured for user: {args.username}")
        
        # Run traditional spider
        await run_spider_async(args.target, args.port, args.api_key, args.spider_timeout,
                             context_id, user_id)
        
        # Run AJAX/Decibel spider if requested
        if args.decibel:
            await run_ajax_spider_async(args.target, args.port, args.api_key, args.spider_timeout,
                                      context_id, user_id)
        
        # Run active scan
        await run_active_scan_async(args.target, args.port, args.api_key, args.scan_timeout,
                                  args.scan_policy, args.threads, context_id, user_id)
        
        # Generate report
        report_path = generate_report(args.output, args.target, args.port, args.api_key)
        
        logger.info(f"\nScan completed. Full report available at: {report_path}")
    
    finally:
        # Always ensure ZAP is shut down
        await shutdown_zap_async(args.port, args.api_key, zap_process)

def main():
    """Main function to run the ZAP scan."""
    try:
        # Setup event loop properly for Python 3.11+
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        loop.run_until_complete(main_async())
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()
