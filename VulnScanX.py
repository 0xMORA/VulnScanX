from flask import Flask, jsonify,render_template,request
import subprocess
import json
from tools import commandinjection,dalfox,sqlinjection
import os



flask_app=Flask(__name__)
flask_app.secret_key="hello"


urls_path="urls.txt"
scan_finished=False

#homepage
@flask_app.route("/",methods=["GET","POST"])
def home():
            return render_template("index.html",
                                title="/")
        


# Start-scan route
@flask_app.route("/start-scan", methods=["POST"])
def start_scan():
    url = request.form.get("url")
    headers = request.form.get("headers")
    scan_type = request.form.get("scan-type")
    subdomain_enum = request.form.get("subdomain-enum")
    xss = request.form.get("xss") 
    sqli = request.form.get("sql-injection") 
    commandinj = request.form.get("command-injection") 
    try:
        if scan_type == "full":
            full_scan(url, headers)
        elif scan_type == "custom":
            custom_scan(url, headers, subdomain_enum, xss, sqli, commandinj)
        return "Scan initiated."
    except Exception as e:
        return


#results
@flask_app.route("/results",methods=["GET","POST"])
def results():
            return render_template("results.html",
                                title="/results")
    


@flask_app.route("/getresults", methods=["GET"])
def get_results():
    results_file = "vulnerabilities.json"
    
    if not os.path.exists(results_file):
        return jsonify({"error": "Results file not found", "scan_finish": False})
    
    with open(results_file, "r") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format", "scan_finish": False})

    return jsonify({**data, "scan_finish": scan_finished})





def full_scan(url,headers):
    global scan_finished
    subdomain_enum=True
    recon(url,subdomain_enum)
    dalfox(urls_path)
    commandinjection(urls_path)
    sqlinjection(urls_path,headers,level="1",risk="1")
    scan_finished=True


def custom_scan(url,headers,subdomain_enum,xss,sqli,commandinj):
    global scan_finished
    recon(url,subdomain_enum)

    if(xss =="on"):
        dalfox(urls_path)
    if(commandinj =="on"):
        commandinjection(urls_path)
    if(sqli =="on"):
        sqlinjection(urls_path,headers,level="1",risk="1")
    scan_finished=True


#recon function is a bash script that automates subdomain enum & passive and active crawling     
def recon(url,subdomain_enum):
    try:
        if subdomain_enum == "on":
            sub="-sub"
        else:
            sub=""

        # Run the bash script
        result = subprocess.run(
            ["/tools/automate.sh"] + url +sub,  # Path to the bash script
            capture_output=True,  # Capture stdout and stderr
            text=True,            # Return output as a string
            check=True            # Raise an error if the script fails
        )
            
    except subprocess.CalledProcessError as e:
        # Handle errors (e.g., script returns a non-zero exit code)
        return {
            "error": str(e),
            "stdout": e.stdout,
            "stderr": e.stderr,
            "returncode": e.returncode
        }    




if __name__=="__main__":
    from gevent.pywsgi import WSGIServer
    from geventwebsocket.handler import WebSocketHandler

    http_server = WSGIServer(('127.0.0.1', 80), flask_app, handler_class=WebSocketHandler)
    http_server.serve_forever()

