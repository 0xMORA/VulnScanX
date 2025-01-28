import subprocess
import json
import re

def commandinjection(url_file, ws=None):
    """
    Run Commix on a list of URLs, extract parameters and payloads, and send results as JSON with WebSocket.
    """
    try:
        # Read URLs from the file
        with open(url_file, "r") as f:
            urls = f.readlines()

        # Iterate through each URL
        for url in urls:
            url = url.strip()  # Remove leading/trailing whitespace
            if not url:
                continue  # Skip empty lines

            print(f"Testing URL: {url}")

            # Run Commix for the current URL
            command = ["commix", "--url", url, "--batch"]
            result = subprocess.run(command, capture_output=True, text=True)

            # Prepare the result data
            if result.returncode != 0:
                print(f"Error testing {url}: {result.stderr}")
                if ws:
                    # Send an error as a vulnerability with a description
                     ws.send(json.dumps({
                        "vulnerability": "Command Injection",
                        "severity": "Critical",
                        "url": url,
                        "description": f"Error encountered: {result.stderr}"
                    }))
            else:
                # Extract parameters and payloads
                parameter_payload_pairs = []

                for line in result.stdout.splitlines():
                    # Extract vulnerable parameters
                    if "injectable" in line:
                        param_match = re.search(r"Parameter '(.+?)' seems injectable", line)
                        if param_match:
                            parameter = param_match.group(1)

                            # Look for a payload on the following lines
                            payload_match = re.search(r"Payload : (.+)", line)
                            payload = payload_match.group(1) if payload_match else "N/A"

                            # Add the parameter-payload pair to the list
                            parameter_payload_pairs.append((parameter, payload))

                # If parameter-payload pairs are found, send them as results
                if parameter_payload_pairs:
                    description = "\n".join([f"Parameter: {param}, Payload: {payload}" for param, payload in parameter_payload_pairs])
                    result_data = {
                        "vulnerability": "Command Injection",
                        "severity": "Critical",  # Fixed severity for command injection
                        "url": url,
                        "description": description
                    }
                    if ws:
                         ws.send(json.dumps(result_data))

    except Exception as e:
        error_data = {
            "vulnerability": "Command Injection",
            "severity": "Critical",
            "url": "N/A",
            "description": f"Error: {str(e)}"
        }
        if ws:
             ws.send(json.dumps(error_data))
        return json.dumps(error_data, indent=4)
