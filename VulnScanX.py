from flask import Flask, jsonify, render_template, request
import subprocess
import json
from tools import commandinjection, dalfox, sqlinjection
import os
import threading
import argparse

# Initialize Flask app
flask_app = Flask(__name__)

# Path to the scans directory
scans_dir = "scans"
os.makedirs(scans_dir, exist_ok=True)  # Create scans directory if it doesn't exist

# Path to the URLs file inside the scans directory
urls_path = os.path.join(scans_dir, "urls.txt")

# Get the absolute path
absolute_path = os.path.abspath(urls_path)
scan_finished = False

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Run VulnScanX with custom port and number of threads.")
parser.add_argument("-p", "--port", type=int, default=80, help="Port to run the application on (default: 80)")
parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads to use for scanning (default: 1)")
args = parser.parse_args()

# Global variable to store the number of threads
NUM_THREADS = args.threads



# Homepage route
@flask_app.route("/", methods=["GET", "POST"])
def home():
    return render_template("index.html", title="/")

# Start-scan route
@flask_app.route("/start-scan", methods=["POST"])
def start_scan():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400

        url = data.get("url")
        headers = data.get("headers")
        scan_type = data.get("scan-type")
        subdomain_enum = data.get("subdomain-enum")
        crawling = data.get("crawling")
        xss = data.get("xss")
        sqli = data.get("sql-injection")
        commandinj = data.get("command-injection")

        if not url or not scan_type:
            return jsonify({"error": "Missing required parameters"}), 400
        
        # Create a directory for the URL target inside the scans directory
        url_directory = os.path.join("scans", url.replace("/", "_").replace(":", "_"))
        # Convert it to an absolute path and make it 
        url_directory = os.path.abspath(url_directory)
        os.makedirs(url_directory, exist_ok=True)

        # Run scan in a separate thread
        if scan_type == "full":
            scan_thread = threading.Thread(target=full_scan, args=(url, headers,subdomain_enum, url_directory))
        elif scan_type == "custom":
            scan_thread = threading.Thread(target=custom_scan, args=(url, headers, subdomain_enum, crawling, xss, sqli, commandinj, url_directory))
        else:
            return jsonify({"error": "Invalid scan type"}), 400

        scan_thread.start()

        return jsonify({"message": "Scan started successfully. You can check the results later."}), 202

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@flask_app.route("/getresults", methods=["GET"])
def get_results():
    # Get the target URL from the query parameters
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    # Create the target directory name by replacing special characters
    url_directory = os.path.join("scans", url.replace("/", "_").replace(":", "_"))

    # Path to the vulnerabilities.json file inside the target directory
    results_file = os.path.join(url_directory, "vulnerabilities.json")
    
    # Check if the results file exists
    if not os.path.exists(results_file):
        return jsonify({"error": "Results file not found for the specified URL", "scan_finish": False})
    
    # Read the results file
    with open(results_file, "r") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format in results file", "scan_finish": False})

    # If data is a list, wrap it in a dictionary
    if isinstance(data, list):
        response_data = {
            "results": data,  # Wrap the list in a dictionary
            "scan_finish": scan_finished
        }
    else:
        response_data = {**data, "scan_finish": scan_finished}

    return jsonify(response_data)

# Results route
@flask_app.route("/results", methods=["GET", "POST"])
def results():
    return render_template("results.html", title="/results")


# Blog route
BLOG_POSTS = [
    {"id": "command-injection", "title": "Command Injection"},
    {"id": "sql-injection", "title": "SQL Injection"},
    {"id": "xss", "title": "Cross-Site Scripting (XSS)"}
]

@flask_app.route("/blog", methods=["GET"])
def blog():
    # Check if a specific post is requested
    if "post" in request.args:
        post_id = request.args["post"]
        # Render the corresponding post template
        if post_id == "command-injection":
            return render_template("command-injection.html", title="Command Injection")
        elif post_id == "sql-injection":
            return render_template("sql-injection.html", title="SQL Injection")
        elif post_id == "xss":
            return render_template("xss.html", title="XSS")
        else:
            return "Post not found", 404
    else:
        # Render the list of available posts
        return render_template("blog.html", posts=BLOG_POSTS, title="Blog")

# History route
@flask_app.route("/history", methods=["GET"])
def history():
    # Get all scan directories
    scan_directories = [d for d in os.listdir(scans_dir) if os.path.isdir(os.path.join(scans_dir, d))]
    scan_history = []

    # Load vulnerabilities from each directory
    for directory in scan_directories:
        vulnerabilities_file = os.path.join(scans_dir, directory, "vulnerabilities.json")
        if os.path.exists(vulnerabilities_file):
            with open(vulnerabilities_file, "r") as file:
                vulnerabilities = json.load(file)
                scan_history.append({
                    "url": directory.replace("_", ":").replace("_", "/"),
                    "vulnerabilities": vulnerabilities
                })

    return render_template("history.html", scan_history=scan_history, title="Scan History")

# Full scan function
def full_scan(url, headers,subdomain_enum, url_directory):
    global scan_finished

    # Phase 1: Run recon first with all threads
    recon_threads = []
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=recon, args=(url, subdomain_enum,url_directory))
        recon_threads.append(thread)
        thread.start()

    # Wait for all recon threads to complete
    for thread in recon_threads:
        thread.join()

    # Phase 2: Run the rest of the functions with all threads
    scan_threads = []

    # XSS scanning
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=dalfox.run_dalfox_on_url, args=(absolute_path,url_directory))
        scan_threads.append(thread)
        thread.start()

    # Command injection testing
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=commandinjection.commandinjection, args=(absolute_path,url_directory))
        scan_threads.append(thread)
        thread.start()

    # SQL injection testing
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=sqlinjection.sql_injection_test, args=(absolute_path ,url_directory, headers, "1", "1"))
        scan_threads.append(thread)
        thread.start()

    # Wait for all scan threads to complete
    for thread in scan_threads:
        thread.join()

    # Remove urls.txt after scan
    if os.path.exists(urls_path):
        os.remove(urls_path)

    scan_finished = True

# Custom scan function
def custom_scan(url, headers, subdomain_enum, crawling, xss, sqli, commandinj, url_directory):
    global scan_finished

    # Phase 1: Run recon first with all threads (if enabled)
    if crawling == "on" or subdomain_enum == "on":
        recon_threads = []
        for _ in range(NUM_THREADS):
            thread = threading.Thread(target=recon, args=(url, subdomain_enum,url_directory))
            recon_threads.append(thread)
            thread.start()

        # Wait for all recon threads to complete
        for thread in recon_threads:
            thread.join()
    else:
        # Ensure the urls.txt file exists
        if not os.path.exists(urls_path):
            with open(urls_path, "w") as file:
                file.write("")
        with open(urls_path, "a") as file:
            file.write(url + "\n")

    # Phase 2: Run the rest of the functions with all threads (if enabled)
    scan_threads = []

    # XSS scanning
    if xss == "on":
        for _ in range(NUM_THREADS):
            thread = threading.Thread(target=dalfox.run_dalfox_on_url, args=(absolute_path,url_directory))
            scan_threads.append(thread)
            thread.start()

    # Command injection testing
    if commandinj == "on":
        for _ in range(NUM_THREADS):
            thread = threading.Thread(target=commandinjection.commandinjection, args=(absolute_path,url_directory))
            scan_threads.append(thread)
            thread.start()

    # SQL injection testing
    if sqli == "on":
        for _ in range(NUM_THREADS):
            thread = threading.Thread(target=sqlinjection.sql_injection_test, args=(absolute_path ,url_directory, headers, "1", "1",url_directory))
            scan_threads.append(thread)
            thread.start()

    # Wait for all scan threads to complete
    for thread in scan_threads:
        thread.join()

    # Remove urls.txt after scan
    if os.path.exists(urls_path):
        os.remove(urls_path)

    scan_finished = True

# Recon function
def recon(url, subdomain_enum,url_directory):
    try:
        if subdomain_enum == "on":
            sub = "-sub"
        else:
            sub = ""

        result = subprocess.run(
            ["./tools/automate.sh", url, url_directory, "-sub"],
            capture_output=True,
            text=True,
            check=True
        )
            
    except subprocess.CalledProcessError as e:
        return {
            "error": str(e),
            "stdout": e.stdout,
            "stderr": e.stderr,
            "returncode": e.returncode
        }

# Run the app with the specified port
if __name__ == '__main__':
    flask_app.run(host='127.0.0.1', port=args.port, debug=True)