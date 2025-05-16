import json
import requests
import os
from ai_assistant import gemini
from urllib.parse import urlparse, urljoin, urlencode

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

    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        data = []

    if vulnerability not in data:
        data.append(vulnerability)

    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

def idor(url_directory):
    endpoints_file = os.path.join(url_directory, "endpoints.json")

    with open(endpoints_file, "r") as f:
        base_request = json.load(f)

    prompt = f"""
    You're an expert penetration tester testing for Insecure Direct Object Reference (IDOR).

    Here is an HTTP request:

    {json.dumps(base_request, indent=2)}

    Suggest 2 or 3 modified versions of this request to test for IDOR vulnerabilities.

    Return ONLY a JSON array of modified request objects without Markdown formatting.
    Do not include ```json or ``` markers.
    Each object must include:
    - url
    - method
    - body_params (if applicable)
    - extra_headers
    """

    gemini_output = gemini(prompt)
    gemini_output = clean_gemini_response(gemini_output)

    try:
        test_requests = json.loads(gemini_output)

        if not isinstance(test_requests, list):
            raise ValueError("Gemini didn't return a list of requests")

        responses = []
        parsed_url = urlparse(base_request["url"])
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

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

    except json.JSONDecodeError as e:
        print(f"Failed to parse Gemini response: {str(e)}")
        print("Raw response was:")
        print(gemini_output)
        return []
    except Exception as e:
        print(f"Error during testing: {str(e)}")
        return []

    analysis_prompt = f"""
    Analyze these IDOR test results:

    {json.dumps(responses, indent=2)}

    For each response:
    - Look at the URL and the modified parameter.
    - Use the response body or status code to detect unauthorized access.
    - If the response contains another user's data or sensitive information, mark it as "vulnerable".
    - If unclear, say "may need further investigation".

    Only return a JSON array of requests which are vulnerable to IDOR:
    - url
    - method
    - body_params
    - extra_headers
    - severity (High, Medium, Low based on impact)
    - vulnerable_parameter (the parameter name that was modified)
    - payload (the modified value used)
    """

    final_analysis = gemini(analysis_prompt)
    final_analysis = clean_gemini_response(final_analysis)

    try:
        vulnerable_requests = json.loads(final_analysis)
        vulnerabilities = []

        for v in vulnerable_requests:
            url = v.get("url")
            body_params = v.get("body_params", {})
            severity = v.get("severity", "High")
            param = v.get("vulnerable_parameter", list(body_params.keys())[0] if body_params else "unknown")
            payload = v.get("payload", list(body_params.values())[0] if body_params else "unknown")

            vulnerability = {
                "vulnerability": "IDOR",
                "severity": severity,
                "url": url,
                "description": f"Vulnerable Parameters: [{{\"parameter\": \"{param}\", \"payloads\": \"{payload}\"}}]"
            }

            save_to_json(vulnerability, url_directory)
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    except json.JSONDecodeError as e:
        print(f"Failed to parse final Gemini analysis: {str(e)}")
        return []
