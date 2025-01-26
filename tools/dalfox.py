import subprocess
import re
import json
import urllib.parse
from urllib.parse import urlparse, parse_qs
#dalfox outputs the poc only so i decoded the payload

def run_dalfox_on_url(url_file):
    command = ["dalfox", "file", url_file]

    try:
        result = subprocess.run(command, capture_output=True, text=True)
        findings = {}
        results = []

        if result.returncode != 0:
            return json.dumps({
                "error": f"Dalfox execution failed: {result.stderr}"
            }, indent=4)

        for line in result.stdout.splitlines():
            url_match = re.search(r"(https?://[^\s]+)", line)
            if not url_match:
                continue 

            full_url = url_match.group(0)  
            parsed_url=urlparse(full_url)
            base_url = parsed_url.scheme+parsed_url.netloc+parsed_url.path#url till path
            query_params = parse_qs(parsed_url.query)#take the querey which are parameter and payload

            if base_url not in findings:
                findings[base_url] = []

            for param, payloads in query_params.items():
                for payload in payloads:
                    decoded_payload = urllib.parse.unquote(payload)#decode payload
                    findings[base_url].append({
                        "parameter": param,
                        "payload": decoded_payload
                    })

        for url, vulnerabilities in findings.items():
            results.append({"url": url, "vulnerabilities": vulnerabilities})


        return json.dumps(results, indent=4)

    except FileNotFoundError:
        return json.dumps({
            "error": f"File not found: {url_file}"
        }, indent=4)
    except Exception as e:
        return json.dumps({
            "error": str(e)
        }, indent=4)

