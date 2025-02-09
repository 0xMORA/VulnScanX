import subprocess
import re
import urllib.parse
from urllib.parse import urlparse, parse_qs
from .save_json_file import save_to_json
#dalfox outputs the POC only so we decoded the payload

def run_dalfox_on_url(url_file):
    command = ["dalfox", "file", url_file]

    try:
        result = subprocess.run(command, capture_output=True, text=True)
        findings = {}

        if result.returncode != 0:
            error_data = {
                "error": f"Dalfox execution failed: {result.stderr}"
            }
            save_to_json(error_data)
            return

        for line in result.stdout.splitlines():
            url_match = re.search(r"(https?://[^\s]+)", line)
            if not url_match:
                continue

            full_url = url_match.group(0)
            parsed_url = urlparse(full_url)
            base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path  # URL till path
            query_params = parse_qs(parsed_url.query)  # Extract query parameters and payloads

            if base_url not in findings:
                findings[base_url] = []

            for param, payloads in query_params.items():
                for payload in payloads:
                    decoded_payload = urllib.parse.unquote(payload)  # Decode payload
                    findings[base_url].append({
                        "parameter": param,
                        "payload": decoded_payload
                    })

        for url, vulnerabilities in findings.items():
            vulnerability_data = {
                "vulnerability": "XSS",
                "severity": "Medium",  # Adjust severity as needed
                "url": url,
                "description": f"Vulnerable parameters: {vulnerabilities} \nwhat you should do : http://127.0.0.1/blog?post=xss"
            }
            save_to_json(vulnerability_data)

    except FileNotFoundError:
        error_data = {
            "error": f"File not found: {url_file}"
        }
        save_to_json(error_data)
    except Exception as e:
        error_data = {
            "error": str(e)
        }
        save_to_json(error_data)

