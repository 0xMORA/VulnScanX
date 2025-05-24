
from urllib.parse import urlparse, parse_qs, unquote
import pprint

import json
import requests
from ai_assistant import gemini
def read_request_from_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

# ai function that sends prompt with file attachment
def ai(prompt,filePath):
    client = genai.Client(api_key="APIKEY")

    myfile = client.files.upload(file=filePath)

    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=[prompt, myfile]
    )
    return response
# functio to convert string to json object
def json_string_to_object(json_string):
    try:
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON string: {e}")
        return None
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
# function that asks the ai to check wether there is a csrf defense mechanism in the rquest 
req = json_string_to_object("""
[
  {
    "url": "https://0a5d001d03901f1880006cc600200021.web-security-academy.net/my-account/change-email",
    "method": "POST",
    "body_params": {
      "email": "test15111%40test.co"
    },
    "extra_headers": {
      "Cookie": "session=IKge1YqKsbomF0kzTJ2mubgursic2XoJ",
      "Referer": "https://0a5d001d03901f1880006cc600200021.web-security-academy.net/my-account?id=wiener"
    }
  }
]
""")

# function to send a prompt to gemini and clean the JSON response 
def aiCall(prompt,request):
    try:
        ai_response = gemini(prompt)
        
        trimedRes = clean_gemini_response(ai_response)
        jsonRes = json_string_to_object(trimedRes)
        return jsonRes
    except Exception as e:
        print("Error while sending prmopt to AI")


def index_of_first(items, key, target):
    """
    Return the index of the first dict in `items`
    whose `key` equals `target`.
    """
    return next(                      # generator-based search
        (i for i, obj in enumerate(items) if obj.get(key) == target),
        None                          # default if nothing matches
    )
def returnJson(aiRes,defense=0,missingInput=0):
    if defense==0:
        msg = f"exploitParam:{aiRes["relevantParam"]};No Defense Mechanism used in this request"
    else:
        msg = f"exploitParam:{aiRes["relevantParam"]};defense: {defense}; defenseParamerter: {aiRes["parameter"]}"
    vuln = "CSRF"
    if missingInput != 0:
        vuln = f"Could Be CSRF 'Some Tests couldn't be done because {missingInput}for another user is missing'" 
    data = {
                "vulnerability":vuln,
                "severity":aiRes["severity"].lower(),
                "url":aiRes["url"],
                "description": msg
            }
    return data

def csrfTests(aiJsonResponse,reqs,validToken="",validCsrfKey=""):
    data = "Not Vulnerable"
    if(aiJsonResponse["vulnerable"].lower() == "yes"):
        data = returnJson(aiJsonResponse)
        return data
    elif(aiJsonResponse["vulnerable"].lower() == "needtocheck"):
        if aiJsonResponse["defense"] == "csrfToken":
            body = {k: unquote(v) for k, v in reqs[body_params].items()}
            relevantParam = aiJsonResponse["relevantParam"]
            url = aiJsonResponse["url"]
            cookieVal = reqs["extra_headers"]["Cookie"][8:]
            csrfTokenName = aiJsonResponse["parameter"]
            csrfTokenVal = reqs["body_params"][csrfTokenName]
            invalidTokenVal = csrfTokenVal+"0"
            # test 1 : submit with invalid scrt Token
            tempBody= body
            tempBody[aiJsonResponse["parameter"]] = invalidTokenVal
            test1 = requests.post(url,data=tempBody,cookies={"session":cookieVal})
            if test1.status_code == 200:
                data = returnJson(aiJsonResponse,aiJsonResponse["defense"])
                print("Test1 :Done")
                print(test1.text)
                return data
            #test 2: change the method to GET with submiting invalid scrfToken
            getUrl = url+f"?{relevantParam}={body[relevantParam]}&{invalidTokenVal}={csrfTokenVal}"
            test2 = requests.get(getUrl,cookies={"session":cookieVal})
            if test2.status_code == 200:
                data = returnJson(aiJsonResponse,aiJsonResponse["defense"])
                print("Test2 :Done")
                print(test2.text)
                return data
            #test3 : remove the csrf Token
            tempBody= body
            tempBody.pop(aiJsonResponse["parameter"])
            test3 = requests.post(url,data=tempBody,cookies={"session":cookieVal})
            if test3.status_code == 200:
                data = returnJson(aiJsonResponse,aiJsonResponse["defense"])
                print("Test3 :Done")
                print(test3.text)
                return data
            #test4: sumbit with valid csrfToken from another user "test will be skiped if user didn't enter a valid csrfToken"
            
            if validToken !="":
                tempBody= body
                tempBody[aiJsonResponse["parameter"]] = validToken
                test4 = requests.post(url,data=tempBody,cookies={"session":cookieVal})
                if test4.status_code == 200:
                    data = returnJson(aiJsonResponse,aiJsonResponse["defense"])
                    print("Test4 :Done")
                    print(test4.text)
                    return data
            else:
                data = returnJson(aiJsonResponse,aiJsonResponse["defense"],"Valid CSRF Token")
                vulnerability.append(data)
        if aiJsonResponse["defense"] == "Referer-based validation":
            body = {k: unquote(v) for k, v in reqs["body_params"].items()}
            relevantParam = aiJsonResponse["relevantParam"]
            url = aiJsonResponse["url"]
            cookieVal = reqs["extra_headers"]["Cookie"][8:]
            RefererHeader = reqs["extra_headers"]["Referer"][8:]
            
            # test 1: submit without Refere header
            test1 = requests.post(url,data=body,cookies={"session":cookieVal})
            if test1.status_code == 200:
                data = returnJson(aiJsonResponse,aiJsonResponse["defense"])
                print("Test1 for Referer :Done")
                print(test1.text)
                return data
            prompt = f"""
                    You're an expert penetration tester testing for CSRT vulnerablity
                    Here is a request:
                    {reqs} 
                    This request has a referer-based defense mechanism
                    i want to test it through checking which portion of the Referer header is the application validation
                    suggest modifed requests that uses a different portion of the original referer in each request
                    don't edit the original referer, just use different portions of it
                    return the answer in the format of JSON array consists of:
                    - url
                    - body_params
                    - same header as the original request + the modified referer
                    keep the key names of the JSON array same as in the modified request as the original
                    and leave the original referer as the first suggestion
            """
            respond = aiCall(prompt)
            for res in respond:
                cookieVal = res["extra_headers"]["Cookie"][8:]

                test = requests.post(res["url"],data=res["body_params"],headers={"Referer":res["extra_headers"]["Referer"]},cookies={"session":cookieVal})
                if test.status_code == 200:
                    tempRes = res
                    
                    tempRes["body_params"]["email"] = "test15151@gmail.c"
                    tempRes["extra_headers"]["Referer"] = f"{res["extra_headers"]["Referer"][0:8]}www.google.com/{res["extra_headers"]["Referer"][8:]}"
                    test2 = requests.post(res["url"],data=res["body_params"],headers={"Referer":tempRes["extra_headers"]["Referer"]},cookies={"session":cookieVal})
                    if test2.status_code == 200:
                        
                        data = returnJson(aiJsonResponse,aiJsonResponse["defense"])
                        print("Test2 for Referer :Done")
                        return data
                            
                    

    return data

def csrf(url_directory=0):
    p = f""" You're an expert penetration tester testing for CSRT vulnerablity
                    here is the request:
                    {req}
                    check if this request is vulnerable to csrf or not 
                    to know if a request is vulnerable check for theses three condition
                    1- Relavent action
                    2- Cookie-based session handling
                    3- No unpredictable parameters
                    there could be defense mechanism like: scrfToken,SameSite Cookies, Refere-based validation
                    if you found any defense mecahnism respond with json format exactly like that: {{ url:value; relevantParam:Param Name that will be exploited;vulnerable:NeedToCheck; defense:value; parameter: defense parameter Name; severity:value }}
                    if there is Referer header in the request return that there is a defense Refere-based validation and don't forget to mention the defense parameter name
                    and in case you found csrfToken with Referer Header then the defense is csrfToken only
                    in case there is a defense mechanism tell me what will the seveirity will be in case the defense mechanism is implemented incorrectly
                    relevantParameter is the parameter the attacker will edit to exloit the vulnerablility
                    if it has no defense respond with: {{ url:value; vulnerable:YES; relevantParam:Param that will be exploited;severity:value }}
                    and do not explain any thing
                    if the request is not Vulnerable just return No
                    make the whole output in the same JSON"""
                    
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
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Prepare base URL for each request
        futures = []
        for base_request in base_requests:
            # parsed_url = urlparse(base_request["url"])
            # base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Submit each request for processing
            future = executor.submit(aiCall, p, base_request)
            futures.append(future)

        # Collect results
        for future in futures:
            vulnerabilities = future.result()
            all_vulnerabilities.extend(vulnerabilities)

    return all_vulnerabilities

    #this is what the code i used to test on hard coded request 


    # aiRes = aiCall(p)
    
    # res = csrfTests(aiRes,req[0])
    # return res
print(csrf())

