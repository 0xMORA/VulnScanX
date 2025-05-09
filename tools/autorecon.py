#!/usr/bin/env python3

import os
import subprocess
from bs4 import BeautifulSoup
import requests
import re
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select
from urllib.parse import urljoin, urlparse, parse_qs
import configparser
import logging

# Define colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'
BOLD = '\033[1m'

# Configure logging for crawler
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
config = configparser.ConfigParser()
config_file = 'config.ini'
if os.path.exists(config_file):
    config.read(config_file)
else:
    config['API_KEYS'] = {
        'pentest_tools': '',
        'securitytrails': '',
        'virustotal': '',
        'dnsdumpster': '',
        'crtsh': '',
        'subdomainfinder': '',
        'findsubdomains': '',
        'netcraft': '',
        'socradar': ''
    }
    with open(config_file, 'w') as f:
        config.write(f)
    print(f"{YELLOW}[+] Created default config.ini. Please add your API keys if available.{NC}")

PENTEST_API_KEY = config['API_KEYS'].get('pentest_tools', '')
SECURITYTRAILS_API_KEY = config['API_KEYS'].get('securitytrails', '')
VIRUSTOTAL_API_KEY = config['API_KEYS'].get('virustotal', '')

def print_banner():
    print(f"{CYAN}{BOLD}")
    print(r"                                                    ")
    print(r"                _        _____                      ")
    print(r"     /\        | |      |  __ \                     ")
    print(r"    /  \  _   _| |_ ___ | |__) |___  ___ ___  _ __  ")
    print(r"   / /\ \| | | | __/ _ \|  _  // _ \/ __/ _ \| '_ \ ")
    print(r"  / ____ \ |_| | || (_) | | \ \  __/ (_| (_) | | | |")
    print(r" /_/    \_\__,_|\__\___/|_|  \_\___|\___\___/|_| |_|")
    print(f"{NC}")
    print(f"{YELLOW}{BOLD}By: omar samy{NC}")
    print(f"{BLUE}{BOLD}Twitter: @omarsamy10{NC}")
    print("===================================================\n")

def run_command(command, silent=False, output_file=None):
    try:
        if silent and output_file:
            with open(output_file, 'w') as f:
                subprocess.run(command, shell=True, check=True, stdout=f, stderr=subprocess.DEVNULL)
        elif silent:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error running command: {command} - {e}{NC}")
        return False
    return True

def setup_project(project_name):
    project_path = Path(project_name).resolve()
    project_path.mkdir(parents=True, exist_ok=True)
    print(f"{GREEN}{BOLD}[+] Project directory created: {project_name}{NC}")
    return project_path

def setup_domain_directory(project_path, domain):
    target_path = (project_path / domain).resolve()
    target_path.mkdir(parents=True, exist_ok=True)
    os.chdir(target_path)
    print(f"{BLUE}[+] Directory created: {project_path}/{domain}{NC}")
    return target_path

def get_driver(headless=True):
    """Initialize a browser driver with fallback."""
    try:
        chrome_options = ChromeOptions()
        chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        if headless:
            chrome_options.add_argument("--headless")
        return webdriver.Chrome(options=chrome_options)
    except Exception as e:
        logger.warning(f"Chrome WebDriver failed: {str(e)}. Falling back to Firefox.")
        try:
            firefox_options = FirefoxOptions()
            firefox_options.set_capability("moz:firefoxOptions", {"prefs": {"devtools.console.stdout.content": True}})
            if headless:
                firefox_options.add_argument("--headless")
            return webdriver.Firefox(options=firefox_options)
        except Exception as e:
            logger.error(f"Firefox WebDriver failed: {str(e)}. No browser available.")
            raise Exception("No supported browser WebDriver found.")

def is_valid_url(url, base_domain):
    """Validate if a URL is a legitimate endpoint."""
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ["http", "https"]:
            return False
        if base_domain not in parsed_url.netloc:
            return False
        path = parsed_url.path
        if not path or path == "/":
            return True
        if not re.match(r'^/[a-zA-Z0-9\-_/]*$', path):
            return False
        exclude_extensions = r'\.(css|js|ico|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|map|txt|xml|pdf)$'
        if re.search(exclude_extensions, path, re.IGNORECASE):
            return False
        invalid_patterns = [
            r'function\(', r'\}\}', r'\|\|', r'\(\s*\)', r'\[.*\]', r'\{.*\}', r'==',
            r'\?\d+:e=', r'\bvar\b', r'\bif\b', r'\belse\b', r'#\\|\?\$\|', r',Pt=function'
        ]
        full_url = url.lower()
        if any(re.search(pattern, full_url) for pattern in invalid_patterns):
            return False
        query = parsed_url.query
        if query:
            if any(len(value) > 100 or re.search(r'[^a-zA-Z0-9=&%_]', value) for values in parse_qs(query).values() for value in values):
                return False
        return True
    except Exception:
        return False

def extract_parameters(request_body):
    """Extract body parameters."""
    body_params = {}
    if request_body:
        try:
            body_params = json.loads(request_body)
        except (json.JSONDecodeError, TypeError):
            body_params = {"raw_body": request_body}
    return body_params

def extract_form_data(form, driver):
    """Extract form data without submitting."""
    form_data = {}
    try:
        inputs = form.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='search'], input[type='email'], input[type='password'], input[type='number'], textarea")
        selects = form.find_elements(By.TAG_NAME, "select")
        checkboxes = form.find_elements(By.CSS_SELECTOR, "input[type='checkbox'], input[type='radio']")
        
        for input_field in inputs:
            try:
                if input_field.is_displayed() and input_field.is_enabled():
                    name = input_field.get_attribute("name") or f"input_{len(form_data)}"
                    input_type = input_field.get_attribute("type")
                    value = "test"
                    if input_type == "password":
                        value = "Test123!"
                    elif input_type == "number":
                        value = "42"
                    elif input_field.tag_name == "textarea":
                        value = "Sample text"
                    input_field.send_keys(value)
                    form_data[name] = value
            except Exception as e:
                logger.warning(f"Error processing input field: {str(e)}")
        
        for select in selects:
            try:
                if select.is_displayed() and select.is_enabled():
                    select_obj = Select(select)
                    name = select.get_attribute("name") or f"select_{len(form_data)}"
                    options = select_obj.options
                    if options:
                        select_obj.select_by_index(len(options) - 1)
                        selected_option = select_obj.first_selected_option
                        form_data[name] = selected_option.get_attribute("value")
            except Exception as e:
                logger.warning(f"Error processing dropdown: {str(e)}")
        
        for checkbox in checkboxes:
            try:
                if checkbox.is_displayed() and checkbox.is_enabled():
                    name = checkbox.get_attribute("name") or f"checkbox_{len(form_data)}"
                    if not checkbox.is_selected():
                        checkbox.click()
                    form_data[name] = checkbox.get_attribute("value") or "on"
            except Exception as e:
                logger.warning(f"Error processing checkbox/radio: {str(e)}")
        
        action = form.get_attribute("action")
        method = form.get_attribute("method") or "POST"
        base_url = driver.current_url
        full_url = urljoin(base_url, action) if action else base_url
        
        return {
            "url": full_url,
            "method": method.upper(),
            "body_params": form_data,
            "extra_headers": {}
        }
    except Exception as e:
        logger.error(f"Error extracting form data: {str(e)}")
        return None

def extract_endpoints_from_js(js_content, base_url):
    """Extract valid endpoints from JavaScript content with method inference."""
    endpoints = []
    path_pattern = r'(?:https?:\/\/[^"\s]+)|(?:/[^"\s/][^"\s]*?/[^"\s/][^\s"]*)'
    quoted_path_pattern = r'[\'"](?:https?:\/\/[^"\s]+|/[^"\s/][^"\s]*?/[^"\s/][^\s"]*)[\'"]'
    
    paths = re.findall(path_pattern, js_content) + re.findall(quoted_path_pattern, js_content)
    
    base_domain = urlparse(base_url).netloc
    for path in paths:
        path = path.strip('"\'')
        full_url = urljoin(base_url, path)
        if is_valid_url(full_url, base_domain):
            method = "GET"
            if re.search(r'\.post\s*\(', js_content, re.IGNORECASE) or re.search(r'method:\s*[\'"]POST[\'"]', js_content, re.IGNORECASE):
                method = "POST"
            elif re.search(r'\.put\s*\(', js_content, re.IGNORECASE) or re.search(r'method:\s*[\'"]PUT[\'"]', js_content, re.IGNORECASE):
                method = "PUT"
            elif re.search(r'\.delete\s*\(', js_content, re.IGNORECASE) or re.search(r'method:\s*[\'"]DELETE[\'"]', js_content, re.IGNORECASE):
                method = "DELETE"
            endpoints.append({"url": full_url, "method": method})
    
    return endpoints

def crawl_website(url, headers=None, max_pages=10, output_file="endpoints.json", headless=True):
    """Crawl a website and extract endpoints."""
    if headers is None:
        headers = {}
    
    driver = get_driver(headless)
    endpoints = []
    visited_urls = set()
    urls_to_visit = [url]
    base_domain = urlparse(url).netloc
    js_urls = set()
    
    basic_headers = {
        'Host', 'Connection', 'User-Agent', 'Accept', 'Accept-Encoding', 
        'Accept-Language', 'Content-Length', 'Content-Type', 'Origin', 
        'Referer', 'Sec-Fetch-Site', 'Sec-Fetch-Mode', 'Sec-Fetch-Dest'
    }
    
    try:
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": headers})
        
        while urls_to_visit and len(visited_urls) < max_pages:
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls:
                continue
            
            try:
                driver.get(current_url)
                visited_urls.add(current_url)
                time.sleep(2)
            except Exception as e:
                logger.error(f"Failed to load {current_url}: {str(e)}")
                continue
            
            try:
                clickable_elements = driver.find_elements(By.CSS_SELECTOR, "button, input[type='button'], [onclick]")
                for element in clickable_elements:
                    try:
                        if element.is_displayed() and element.is_enabled():
                            element.click()
                            time.sleep(1)
                    except Exception as e:
                        logger.warning(f"Error clicking element: {str(e)}")
                
                forms = driver.find_elements(By.CSS_SELECTOR, "form")
                for form in forms:
                    try:
                        if form.is_displayed():
                            form_data = extract_form_data(form, driver)
                            if form_data and is_valid_url(form_data["url"], base_domain):
                                form_data["extra_headers"] = headers
                                endpoints.append(form_data)
                    except Exception as e:
                        logger.warning(f"Error processing form: {str(e)}")
                
                search_inputs = driver.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='search']")
                for input_field in search_inputs:
                    try:
                        if input_field.is_displayed() and input_field.is_enabled():
                            input_field.send_keys("test")
                            input_field.send_keys(Keys.RETURN)
                            time.sleep(1)
                    except Exception as e:
                        logger.warning(f"Error interacting with search bar: {str(e)}")
                
                event_elements = driver.find_elements(By.CSS_SELECTOR, "[onchange], [oninput]")
                for element in event_elements:
                    try:
                        if element.is_displayed() and element.is_enabled():
                            if element.tag_name == "input":
                                element.send_keys("test")
                                time.sleep(0.5)
                    except Exception as e:
                        logger.warning(f"Error triggering event on element: {str(e)}")
            
            except Exception as e:
                logger.error(f"Error interacting with elements on {current_url}: {str(e)}")
            
            try:
                logs = driver.get_log("performance")
                for entry in logs:
                    try:
                        message = json.loads(entry["message"])["message"]
                        if message["method"] == "Network.requestWillBeSent":
                            request = message["params"]["request"]
                            request_url = request["url"]
                            if is_valid_url(request_url, base_domain):
                                body_params = extract_parameters(request.get("postData"))
                                request_headers = {k: v for k, v in request.get("headers", {}).items() if k not in basic_headers}
                                endpoints.append({
                                    "url": request_url,
                                    "method": request["method"],
                                    "body_params": body_params,
                                    "extra_headers": request_headers
                                })
                            if request_url.endswith(".js") and is_valid_url(request_url, base_domain):
                                js_urls.add(request_url)
                    except (KeyError, json.JSONDecodeError) as e:
                        logger.warning(f"Error processing log entry: {str(e)}")
            
            except Exception as e:
                logger.error(f"Error capturing network logs: {str(e)}")
            
            try:
                links = driver.find_elements(By.CSS_SELECTOR, "a[href], [href]")
                for link in links:
                    href = link.get_attribute("href")
                    if href:
                        parsed_href = urlparse(href)
                        if parsed_href.netloc == base_domain or base_domain in parsed_href.netloc:
                            full_url = urljoin(current_url, href)
                            if is_valid_url(full_url, base_domain) and full_url not in visited_urls and full_url not in urls_to_visit:
                                urls_to_visit.append(full_url)
            except Exception as e:
                logger.error(f"Error extracting links from {current_url}: {str(e)}")
        
        for js_url in js_urls:
            try:
                response = requests.get(js_url, headers=headers, timeout=5)
                if response.status_code == 200:
                    js_endpoints = extract_endpoints_from_js(response.text, url)
                    for endpoint in js_endpoints:
                        body_params = extract_parameters(None)
                        endpoints.append({
                            "url": endpoint["url"],
                            "method": endpoint["method"],
                            "body_params": body_params,
                            "extra_headers": headers
                        })
            except Exception as e:
                logger.error(f"Error processing JavaScript file {js_url}: {str(e)}")
        
        unique_endpoints = []
        seen_urls = set()
        for endpoint in endpoints:
            if endpoint["url"] not in seen_urls and is_valid_url(endpoint["url"], base_domain):
                seen_urls.add(endpoint["url"])
                unique_endpoints.append(endpoint)
        
        try:
            with open(output_file, "w") as f:
                json.dump(unique_endpoints, f, indent=2)
            print(f"{GREEN}[+] Endpoints saved to {output_file}{NC}")
        except Exception as e:
            logger.error(f"Error saving endpoints to JSON: {str(e)}")
        
        return unique_endpoints
    
    except Exception as e:
        logger.error(f"Error occurred during crawling: {str(e)}")
        return endpoints
    
    finally:
        driver.quit()

def get_subdomains_from_free_services(target):
    subdomains = set()

    if PENTEST_API_KEY:
        headers = {"X-API-Key": PENTEST_API_KEY}
        base_url = "https://pentest-tools.com/api"
        try:
            response = requests.post(f"{base_url}/targets", json={"name": target, "type": "domain"}, headers=headers)
            target_id = response.json().get("id")
            scan_data = {"target_id": target_id, "tool": "subdomain_finder"}
            response = requests.post(f"{base_url}/scans", json=scan_data, headers=headers)
            scan_id = response.json().get("scan_id")
            while True:
                response = requests.get(f"{base_url}/scans/{scan_id}", headers=headers)
                data = response.json()
                if data.get("status") == "finished":
                    subdomains.update(data.get("results", {}).get("subdomains", []))
                    break
                time.sleep(10)
        except Exception as e:
            print(f"{RED}Error with Pentest-Tools API: {e}{NC}")
    else:
        try:
            url = f"https://pentest-tools.com/information-gathering/find-subdomains-of-domain?domain={target}"
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            for div in soup.select("div.subdomain-result"):
                subdomain = div.text.strip()
                if subdomain.endswith(f".{target}"):
                    subdomains.add(subdomain)
            print(f"{GREEN}[+] Retrieved subdomains from Pentest-Tools web{NC}")
        except Exception as e:
            print(f"{RED}Error with Pentest-Tools web: {e}{NC}")

    try:
        response = requests.get("https://dnsdumpster.com", timeout=10)
        csrf_token = re.search(r'name="csrfmiddlewaretoken" value="(.+?)"', response.text).group(1)
        data = {"csrfmiddlewaretoken": csrf_token, "targetip": target}
        headers = {"Referer": "https://dnsdumpster.com"}
        response = requests.post("https://dnsdumpster.com", data=data, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        for td in soup.select("td.col-md-4"):
            subdomain = td.text.strip()
            if subdomain.endswith(f".{target}"):
                subdomains.add(subdomain)
    except Exception as e:
        print(f"{RED}Error with DNSdumpster: {e}{NC}")

    print(f"{YELLOW}[+] Nmmapper.com requires manual retrieval: https://www.nmmapper.com/subdomains{NC}")

    if SECURITYTRAILS_API_KEY:
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        try:
            response = requests.get(f"https://api.securitytrails.com/v1/domain/{target}/subdomains", headers=headers)
            data = response.json()
            for sub in data.get("subdomains", []):
                subdomains.add(f"{sub}.{target}")
        except Exception as e:
            print(f"{RED}Error with SecurityTrails: {e}{NC}")

    try:
        response = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=10)
        for entry in response.json():
            name = entry.get("name_value", "").strip()
            if name.endswith(f".{target}"):
                subdomains.add(name)
    except Exception as e:
        print(f"{RED}Error with Crt.sh: {e}{NC}")

    print(f"{YELLOW}[+] SubdomainFinder.c99.nl requires manual retrieval: https://subdomainfinder.c99.nl{NC}")

    if VIRUSTOTAL_API_KEY:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/domains/{target}/subdomains", headers=headers)
            data = response.json()
            for sub in data.get("data", []):
                subdomains.add(sub.get("id"))
        except Exception as e:
            print(f"{RED}Error with VirusTotal: {e}{NC}")

    print(f"{YELLOW}[+] FindSubDomains.com requires manual retrieval: https://findsubdomains.com{NC}")

    try:
        response = requests.get(f"https://searchdns.netcraft.com/?host=*.{target}", timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        for a in soup.select("a[href*='site=']"):
            subdomain = re.search(r"site=([^&]+)", a["href"]).group(1)
            if subdomain.endswith(f".{target}"):
                subdomains.add(subdomain)
    except Exception as e:
        print(f"{RED}Error with Netcraft: {e}{NC}")

    try:
        response = requests.get(f"https://api.socradar.io/tools/subdomains?domain={target}", timeout=10)
        data = response.json()
        subdomains.update(data.get("subdomains", []))
    except Exception as e:
        print(f"{RED}Error with SOCRadar: {e}{NC}")

    return subdomains

def passive_subdomain_enum(domain, threads=20):
    print(f"{YELLOW}[+] Running passive subdomain enumeration with {threads} threads...{NC}")
    commands = [
        (f"amass enum -passive -d {domain} -o amassoutput.txt", "amassoutput.txt"),
        (f"subfinder -d {domain} -o subfinder.txt", "subfinder.txt"),
        (f"sublist3r -d {domain} -o sublist3r.txt", "sublist3r.txt")
    ]
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(run_command, cmd, True, outfile): outfile 
                  for cmd, outfile in commands}
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"{RED}Error in thread for {futures[future]}: {e}{NC}")
    
    run_command("cat amassoutput.txt subfinder.txt sublist3r.txt | sort -u > domains.txt", silent=True)
    run_command("rm amassoutput.txt subfinder.txt sublist3r.txt", silent=True)

def filter_live_domains():
    print(f"{YELLOW}[+] Filtering live domains...{NC}")
    if os.path.exists("domains.txt"):
        if run_command("cat domains.txt | httpx -silent -o domain.live", silent=True):
            print(f"{GREEN}[+] Live domains filtered{NC}")
        else:
            print(f"{RED}[!] Failed to filter live domains{NC}")
    else:
        print(f"{RED}[!] domains.txt not found, skipping live domain filtering{NC}")

def active_subdomain_enum(domain):
    print(f"{YELLOW}[+] Running active subdomain enumeration with dnsrecon...{NC}")
    try:
        dns_output_file = "dns_servers.txt"
        run_command(f"dig @8.8.8.8 NS {domain} +short > {dns_output_file}", silent=True)
        
        dns_servers = set()
        if os.path.exists(dns_output_file):
            with open(dns_output_file, "r") as f:
                dns_servers = {line.strip().rstrip('.') for line in f if line.strip()}
            os.remove(dns_output_file)
        
        ns_ips = []
        if dns_servers:
            for ns in dns_servers:
                ip_output_file = f"ns_ip_{ns}.txt"
                run_command(f"dig @8.8.8.8 A {ns} +short > {ip_output_file}", silent=True)
                if os.path.exists(ip_output_file):
                    with open(ip_output_file, "r") as f:
                        ips = [line.strip() for line in f if line.strip() and re.match(r"^\d+\.\d+\.\d+\.\d+$", line)]
                        if ips:
                            ns_ips.append(ips[0])
                    os.remove(ip_output_file)
        
        wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        if not os.path.exists(wordlist):
            print(f"{RED}[!] Wordlist not found: {wordlist}{NC}")
            return
        
        live_domains = set()
        if os.path.exists("domain.live"):
            with open("domain.live", "r") as dl:
                live_domains = set(dl.read().splitlines())
        
        if ns_ips:
            ns_list_str = ",".join(ns_ips)
            print(f"{BLUE}[+] Querying name servers: -n {ns_list_str}{NC}")
            
            for i, ns_ip in enumerate(ns_ips):
                ns_option = f"-n {ns_ip}"
                dnsrecon_output = f"dnsrecon_output_{i}.json"
                cmd = f"dnsrecon -d {domain} -t brt -D {wordlist} {ns_option} --lifetime 10 --threads 50 -j {dnsrecon_output} -f"
                
                if run_command(cmd, silent=True):
                    if os.path.exists(dnsrecon_output):
                        try:
                            with open(dnsrecon_output, "r") as f:
                                data = json.load(f)
                                for record in data:
                                    if record.get("type") in ["A", "CNAME"] and record.get("name", "").endswith(f".{domain}"):
                                        live_domains.add(record.get("name"))
                        except json.JSONDecodeError:
                            print(f"{RED}[!] Failed to parse dnsrecon JSON output for {dnsrecon_output}{NC}")
                        os.remove(dnsrecon_output)
                else:
                    print(f"{RED}[!] Failed to run dnsrecon with {ns_option}{NC}")
        else:
            print(f"{YELLOW}[!] No authoritative DNS server IPs resolved, using system resolvers{NC}")
            dnsrecon_output = "dnsrecon_output.json"
            cmd = f"dnsrecon -d {domain} -t brt -D {wordlist} --lifetime 10 --threads 50 -j {dnsrecon_output} -f"
            if run_command(cmd, silent=True):
                if os.path.exists(dnsrecon_output):
                    try:
                        with open(dnsrecon_output, "r") as f:
                            data = json.load(f)
                            for record in data:
                                if record.get("type") in ["A", "CNAME"] and record.get("name", "").endswith(f".{domain}"):
                                    live_domains.add(record.get("name"))
                    except json.JSONDecodeError:
                        print(f"{RED}[!] Failed to parse dnsrecon JSON output{NC}")
                    os.remove(dnsrecon_output)
            else:
                print(f"{RED}[!] Failed to run dnsrecon with system resolvers{NC}")
        
        with open("domain.live", "w") as f:
            f.write("\n".join(sorted(live_domains)))
        print(f"{GREEN}[+] Active subdomain enumeration completed with dnsrecon{NC}")
    except Exception as e:
        print(f"{RED}[!] Error in active subdomain enumeration: {e}{NC}")

def autorecon(url, subdomain_enum=False, url_directory=None, headers=None, max_pages=10, threads=4):
    """Perform reconnaissance on a target URL with optional subdomain enumeration and crawling.
    
    Args:
        url (str): Target URL or domain.
        subdomain_enum (bool): Enable subdomain enumeration if True.
        url_directory (str): Directory to store output files.
        headers (dict, optional): Custom HTTP headers as a dictionary.
        max_pages (int): Maximum number of pages to crawl.
        threads (int): Number of threads for subdomain enumeration.
    
    Returns:
        dict: Results containing subdomains, endpoints, and any errors.
    """
    print_banner()
    
    if not url_directory:
        print(f"{RED}{BOLD}Error: url_directory is required{NC}")
        return {"error": "url_directory is required"}
    
    domain = urlparse(url).netloc or url
    project_name = url_directory
    project_path = setup_project(project_name)
    setup_domain_directory(project_path, domain)
    
    result = {"subdomains": [], "endpoints": [], "error": None}
    
    if subdomain_enum:
        print(f"{CYAN}{BOLD}[+] Performing subdomain enumeration for {domain}{NC}")
        passive_subdomain_enum(domain, threads)
        filter_live_domains()
        active_subdomain_enum(domain)
        
        if os.path.exists("domain.live"):
            with open("domain.live", "r") as f:
                result["subdomains"] = f.read().splitlines()
        else:
            print(f"{YELLOW}[!] No live domains found{NC}")
    
    print(f"{YELLOW}[+] Running URL crawling with Selenium crawler...{NC}")
    output_file = os.path.join(url_directory, "endpoints.json")
    endpoints = crawl_website(url, headers=headers, max_pages=max_pages, output_file=output_file, headless=True)
    result["endpoints"] = endpoints
    
    os.chdir(project_path)
    print(f"{GREEN}{BOLD}[+] All tasks completed. Results in '{url_directory}' directory{NC}")
    return result