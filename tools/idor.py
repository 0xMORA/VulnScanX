import json
import requests
import os
from ai_assistant import gemini
from urllib.parse import urlparse, urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor
import threading

# Thread-safe lock for writing to vulnerabilities.json
file_lock = threading.Lock()

def clean_gemini_response(raw_text):
    """
    Removes markdown JSON code block wrappers like ```json ... ```
    to ensure the string is valid JSON for parsing.
    """
    if raw_text.startswith("```json"):
        raw_text = raw_text[len("```json"):].strip()
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3].strip()
    return raw_text

def send_modified_request(req_data):
    method = req_data.get("method", "GET").upper()
    url = req_data["url"]
    headers = req_data.get("extra_headers", {})
    body = req_data.get("body_params", None)

    try:
        parsed = urlparse(url)

        if not parsed.scheme:
            host = headers.get("Host")
            if not host:
                return {"error": "Missing 'Host' header for relative URL"}

            scheme = "https"
            url = f"{scheme}://{host}{url}"

        if isinstance(body, dict) and "application/x-www-form-urlencoded" in headers.get("Content-Type", ""):
            body = urlencode(body)

        if method == "GET":
            res = requests.get(url, headers=headers)
        elif method == "POST":
            res = requests.post(url, headers=headers, data=body)
        elif method == "PUT":
            res = requests.put(url, headers=headers, data=body)
        elif method == "PATCH":
            res = requests.patch(url, headers=headers, data=body)
        elif method == "DELETE":
            res = requests.delete(url, headers=headers, data=body)
        else:
            return {"error": f"Unsupported HTTP method: {method}"}

        return {
            "url": url,
            "status": res.status_code,
            "response_body": res.text
        }

    except Exception as e:
        return {"error": str(e)}

def save_to_json(vulnerability, directory):
    filename = os.path.join(directory, "vulnerabilities.json")

    # Thread-safe write to file
    with file_lock:
        try:
            with open(filename, "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            data = []

        if vulnerability not in data:
            data.append(vulnerability)

        with open(filename, "w") as file:
            json.dump(data, file, indent=4)

def process_single_request(base_request, url_directory, base_url):
    """
    Process a single base request: generate modified requests, send them, and analyze results.
    Runs in a separate thread for each base request.
    """
    try:
        # Generate prompt for Gemini to create modified requests
        prompt = f"""
        You're an expert penetration tester testing for Insecure Direct Object Reference (IDOR).

        Here is an HTTP request:

        {json.dumps(base_request, indent=2)}

        Suggest 2 modified versions for the request to test for IDOR vulnerabilities.

        Return ONLY a JSON array of modified request objects without Markdown formatting.
        Do not include ```json or ``` markers.
        Each object must include:
        - url
        - method
        - body_params (if applicable)
        - extra_headers
        """

        # Send prompt to Gemini
        gemini_output = gemini(prompt)
        gemini_output = clean_gemini_response(gemini_output)

        # Parse Gemini's response
        try:
            test_requests = json.loads(gemini_output)
            if not isinstance(test_requests, list):
                raise ValueError("Gemini didn't return a list of requests")
        except json.JSONDecodeError as e:
            print(f"Failed to parse Gemini response for request {base_request['url']}: {str(e)}")
            print("Raw response was:")
            print(gemini_output)
            return []

        # Send modified requests and collect responses
        responses = []
        for i, req in enumerate(test_requests, 1):
            if 'url' in req:
                parsed_req_url = urlparse(req['url'])
                if not parsed_req_url.netloc:
                    req['url'] = urljoin(base_url + "/", req['url'])

            res = send_modified_request(req)
            responses.append({
                "test_case": req.get("description", f"Test {i}"),
                "request": req,
                "response": res
            })

        # Analyze results with Gemini
        analysis_prompt = f"""
Analyze these IDOR test results:

{json.dumps(responses, indent=2)}

For each response, determine if it indicates an Insecure Direct Object Reference (IDOR) 
For each response, return a JSON object with:
- vulnerable: true or false
- url: the request URL
- method: the HTTP method
- body_params: the request body parameters (if any)
- extra_headers: the request headers
- severity: "High" (if confirmed IDOR with sensitive data like personal info), "Medium" (if less sensitive data), "Low" (if minimal impact), or "None" (if not vulnerable)
- vulnerable_parameter: the parameter modified to test IDOR (e.g., "studentId", "Authorization")
- payload: the modified value used (e.g., "20200759")
- evidence: a brief explanation of why the response is marked vulnerable or not (e.g., "Response contains email of user 20200759", "Same user data returned", "403 Forbidden")

Return a JSON array of these objects.
"""

        final_analysis = gemini(analysis_prompt)
        final_analysis = clean_gemini_response(final_analysis)
    
        # Parse analysis and save vulnerabilities
        try:
            vulnerable_requests = json.loads(final_analysis)
            vulnerabilities = []

            for v in vulnerable_requests:
                url = v.get("url")
                vulnerable=v.get("vulnerable")
                body_params = v.get("body_params", {})
                severity = v.get("severity", "High")
                param = v.get("vulnerable_parameter", list(body_params.keys())[0] if body_params else "unknown")
                payload = v.get("payload", list(body_params.values())[0] if body_params else "unknown")
                evidence = v.get("evidence")

                vulnerability = {
                    "vulnerability": "IDOR",
                    "severity": severity,
                    "url": url,
                    "vulnerable":vulnerable,
                    "evidence":evidence,
                    "description": f'Vulnerable Parameters: [{{"parameter": "{param}", "payloads": "{payload}"}}] <strong>Recommended Action : <a href="http://127.0.0.1/blog?post=IDOR\\"> IDOR Blog </a></strong>'
                }
                # if vulnerable == True:
                save_to_json(vulnerability, url_directory)
                vulnerabilities.append(vulnerability)

            return vulnerabilities

        except json.JSONDecodeError as e:
            print(f"Failed to parse final Gemini analysis for request {base_request['url']}: {str(e)}")
            return []

    except Exception as e:
        print(f"Error during processing of request {base_request['url']}: {str(e)}")
        return []

def idor(url_directory, max_workers=4):
    """
    Process requests from endpoints.json concurrently using ThreadPoolExecutor.
    """
    endpoints_file = os.path.join(url_directory, "endpoints.json")

    # Read base requests
    try:
        with open(endpoints_file, "r") as f:
            base_requests = json.load(f)
            if not isinstance(base_requests, list):
                base_requests = [base_requests]  # Convert single request to list
    except Exception as e:
        print(f"Failed to read endpoints.json: {str(e)}")
        return []

    # Initialize results
    all_vulnerabilities = []

    # Process requests concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Prepare base URL for each request
        futures = []
        for base_request in base_requests:
            parsed_url = urlparse(base_request["url"])
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            # Submit each request for processing
            future = executor.submit(process_single_request, base_request, url_directory, base_url)
            futures.append(future)

        # Collect results
        for future in futures:
            vulnerabilities = future.result()
            all_vulnerabilities.extend(vulnerabilities)

    return all_vulnerabilities

# Example usage
idor(r" path to your json file directory ex. C:\Users\username\OneDrive\Desktop")
