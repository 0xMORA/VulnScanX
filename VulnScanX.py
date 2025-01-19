from flask import Flask, jsonify,render_template,redirect,url_for,request,session,flash
import subprocess
import asyncio
import json
from tools import commandinj


flask_app=Flask(__name__)

flask_app.secret_key="hello"


#homepage
@flask_app.route("/",methods=["GET","POST"])
def home():
        if request.method=="GET":
            return render_template("index.html",
                                title="/",
                                custom_css="home",
                                custom_script="home",)
        elif request.method=="POST":
            url=request.form["url"]
            scan_type=request.form["scan-type"]
            subdomaincheck=request.form["Include subdomains"]
            results = asyncio.run(run_scan_concurrently(url,scan_type,subdomaincheck))
            return jsonify(results)
        else:
            flash("method not allowed")

        

#scan function that calls all tools and other functions 
async def run_scan_concurrently(url,scan_type,subdomaincheck):
    recon(url,subdomaincheck)
    tasks = [commandinj("/path/to/urls")]
    results = await asyncio.gather(*tasks)
    return results
     
#recon function is a bash script that automates subdomain enum & passive and active crawling     
def recon(url,subdomaincheck):
    try:
        # Run the bash script
        result = subprocess.run(
            ["/tools/automate.sh"] + url +subdomaincheck,  # Path to the bash script
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
