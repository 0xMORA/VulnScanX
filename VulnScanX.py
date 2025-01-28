from flask import Flask, jsonify,render_template,redirect,url_for,request,session,flash
import subprocess
import json
from tools import commandinjection,dalfox,sqlinjection
from flask_sockets import Sockets

flask_app=Flask(__name__)
flask_app.secret_key="hello"
sockets = Sockets(__name__)


urls_path="urls.txt"

#homepage
@flask_app.route("/",methods=["GET","POST"])
def home():
            return render_template("index.html",
                                title="/")
        


# Start-scan route
@flask_app.route("/start-scan", methods=["POST"])
def start_scan():
    global url,headers,scan_type,subdomain_enum,xss,sqli,commandinj
    url = request.form.get("url")
    headers = request.form.get("headers")
    scan_type = request.form.get("scan-type")
    subdomain_enum = request.form.get("subdomain-enum")
    xss = request.form.get("xss") 
    sqli = request.form.get("sql-injection") 
    commandinj = request.form.get("command-injection") 
       
    return "Scan initiated."


#results
@flask_app.route("/results",methods=["GET","POST"])
def results():
            return render_template("results.html",
                                title="/results")


# WebSocket endpoint to stream scan results
@sockets.route("/results")
def results(ws):
    while not ws.closed:
        if scan_type == "full":
            full_scan(url,headers,ws)
        elif scan_type == "custom":
            custom_scan(url,headers,subdomain_enum,xss,sqli,commandinj,ws)



def full_scan(url,headers,ws):
    subdomain_enum=True
    recon(url,subdomain_enum)
    dalfox(urls_path,ws)
    commandinjection(urls_path,ws)
    sqlinjection(urls_path,ws,headers,level="1",risk="1")

def custom_scan(url,headers,subdomain_enum,xss,sqli,commandinj,ws):

    recon(url,subdomain_enum)

    if(xss):
        dalfox(urls_path,ws)
    if(commandinj):
        commandinjection(urls_path,ws)
    if(sqli):
        sqlinjection(urls_path,ws,headers,level="1",risk="1")


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
    flask_app.run(host='127.0.0.1',port=80,debug=True)
