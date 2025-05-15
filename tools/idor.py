import json
import requests
from ai_assistant import gemini
from urllib.parse import urlparse, urljoin, urlencode




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



base_request ={
  "method": "GET",
  "url": "/download-transcript/2.txt",
  "headers": {
    "Host": "0a9800d10380b52b801a5d6500d00099.web-security-academy.net",
    "Cookie": "session=4EBrfiBmmfDEJpTT3lSOcWrbr2Coj420",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://0a9800d10380b52b801a5d6500d00099.web-security-academy.net/chat",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Priority": "u=0, i",
    "Te": "trailers"
  },
  "body": {}
}


prompt = f"""
You're an expert penetration tester testing for Insecure Direct Object Reference (IDOR).

Here is an HTTP request:

{json.dumps(base_request, indent=2)}

Suggest modified versions of this request to test for IDOR vulnerabilities.



Return ONLY a JSON array of modified request objects without Markdown formatting.
Do not include ```json or ``` markers.
"""

gemini_output = gemini(prompt)
parsed_url = urlparse(base_request["url"])
BASE_DOMAIN = parsed_url.netloc

try:

    test_requests = json.loads(gemini_output)
    
    if not isinstance(test_requests, list):
        raise ValueError("Gemini didn't return a list of requests")
        
    responses = []
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    for i, req in enumerate(test_requests, 1):
        if 'url' in req:
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
    exit()
except Exception as e:
    print(f"Error during testing: {str(e)}")
    exit()

analysis_prompt = f"""
Analyze these IDOR test results:

{json.dumps(responses, indent=2)}

For each response:
- Look at the URL and the modified parameter.
- Use the response body or status code to detect unauthorized access.
- If the response contains another user's data or sensitive information, mark it as "vulnerable".
- If unclear, say "may need further investigation".

Only return a JSON array with:
- url
- modified_parameter
- vulnerable (either "vulnerable", "not vulnerable", or "may need further investigation")
"""

final_analysis = gemini(analysis_prompt)
print(final_analysis)





