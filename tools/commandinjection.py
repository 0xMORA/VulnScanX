import subprocess
import json
import re

async def run_commix_on_urls(url_file):
    """
    Run Commix on a list of URLs, extract payloads, and convert results to JSON.
    """
    try:
        # Read URLs from the file
        with open(url_file, "r") as f:
            urls = f.readlines()

        # Store results for all URLs
        results = []

        # Iterate through each URL
        for url in urls:
            url = url.strip()  # Remove leading/trailing whitespace
            if not url:
                continue  # Skip empty lines

            print(f"Testing URL: {url}")

            # Run Commix for the current URL
            command = ["commix", "--url", url, "--batch"]
            result = subprocess.run(command, capture_output=True, text=True)

            # Check if the process completed successfully
            if result.returncode != 0:
                print(f"Error testing {url}: {result.stderr}")
                results.append({
                    "url": url,
                    "error": result.stderr
                })
            else:
                # Extract vulnerabilities and payloads
                vulnerabilities = []
                payloads = []

                for line in result.stdout.splitlines():
                    # Extract vulnerable parameters
                    if "injectable" in line:
                        match = re.search(r"Parameter '(.+?)' seems injectable", line)
                        if match:
                            vulnerabilities.append({
                                "parameter": match.group(1),
                                "status": "Vulnerable"
                            })

                    # Extract payloads
                    if "Payload" in line:
                        match = re.search(r"Payload : (.+)", line)
                        if match:
                            payloads.append(match.group(1))

                # Add the results for this URL
                results.append({
                    "url": url,
                    "vulnerabilities": vulnerabilities,
                    "payloads": payloads
                })

        # Convert the results to JSON
        json_output = json.dumps(results, indent=4)
        return json_output

    except Exception as e:
        return json.dumps({"error": str(e)}, indent=4)

