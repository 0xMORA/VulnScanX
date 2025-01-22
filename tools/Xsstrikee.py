import subprocess
import re
import json

def run_xsstrike_on_url(url_file):


    command = ["python3", "XSStrike/xsstrike.py", "-u", url, "--crawl"]

    try:
                
        with open(url_file, "r") as f:
            urls = f.readlines()

        for url in urls:
            url = url.strip() 
            if not url:
                continue   

            print(f"Testing URL: {url}")
    


        result = subprocess.run(command, capture_output=True, text=True)
        
        results = []

        if result.returncode != 0:
            print(f"Error testing {url}: {result.stderr}")
            results.append({
                "url": url,
                "error": result.stderr
            })
        else:
            CVE = []  
            webpage_payload_pairs = []  
            vulwebpage_CVE_severity_pairs = []
            
            def clean_string(text):
                return re.sub(r'\x1b\[.*?m', '', text)

            current_webpage = None  
            current_vulnerable_component = None
            current_severity=None
            current_CVE=None
            
            for line in result.stdout.splitlines():
                if "Vulnerable component:" in line:
                    match = re.search(r"Vulnerable component: (.*)", line)
                    if match:
                        current_vulnerable_component = (clean_string(match.group(1)))
                        
                if "Severity:" in line:
                    match = re.search(r"Severity: (.*)", line)
                    if match:
                        current_severity=(clean_string(match.group(1)))

                if "CVE:" in line:
                    match = re.search(r"CVE: (.*)", line)
                    if match and current_vulnerable_component and current_severity:
                        current_CVE=(clean_string(match.group(1)))
                        vulwebpage_CVE_severity_pairs.append({
                            "CVE":current_CVE,
                            "Vulnerable component":current_vulnerable_component,
                            "Severity":current_severity
                        })      

                        
                if "Vulnerable webpage:" in line:
                    match = re.search(r"Vulnerable webpage: (.*)", line)
                    if match:
                        current_webpage = clean_string(match.group(1))
                        
                if "Vector for" in line:
                    match = re.search(r"Vector for (.*)", line)
                    if match and current_webpage:
                        payload = clean_string(match.group(1))
                        webpage_payload_pairs.append({
                            "webpage": current_webpage,
                            "payload": payload
                        })

            results.append({
                "CVES": vulwebpage_CVE_severity_pairs,
                "Vulnerable webpage": webpage_payload_pairs
            })

        json_output = json.dumps(results, indent=4)
        return json_output

    except Exception as e:
        return json.dumps({"error": str(e)}, indent=4)
                
