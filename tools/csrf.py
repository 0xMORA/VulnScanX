
from urllib.parse import urlparse, parse_qs, unquote
import pprint
from google import genai
import json
import requests
def read_request_from_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

# ai function that sends prompt with file attachment
def ai(prompt,filePath):
    client = genai.Client(api_key="API KEY")

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
# function that asks the ai to check wether there is a csrf defense mechanism in the rquest 
def csrfCheck(valid_csrfToken=0):
    ai_res = ai("""check if theses requests are vulnerable to csrf or not 
                    to know if a request is vulnerable check for theses three condition
                    1- Relavent action
                    2- Cookie-based session handling
                    3- No unpredictable parameters
                    there could be defense mechanism like: scrfToken,SameSite Cookies, Refere-based validation
                    if it has no defense respons with:{ url:value; vulnerable:YES; relevantParam:Param that will be exploited;severity:value }
                    relevantParameter is the parameter the attacker will edit to exloit the vulnerablility
                    and if you found any defense mecahnism respond with json format: { url:value; relevantParam:Param Name that will be exploited;vulnerable:NeedToCheck;defense:value; parameter:parameterName; severity:value }
                    in case there is a defense mechanism tell me what will the seveirity will be in case the defense mechanism is implemented incorrectly
                    and do not explain any thing
                    and don't display a rquest that is not vulnerable
                    make the whole output in the same JSON""","endpoints.txt")
    trimedRes= ai_res.text[ai_res.text.find('[')-1:ai_res.text.rfind(']')+1]
    jsonRes = json_string_to_object(trimedRes)
    return jsonRes

reqs= read_request_from_file("endpoints.json")
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
    vulnerability = []
    for i in range (0,len(aiJsonResponse),1):
        if(aiJsonResponse[i]["vulnerable"].lower() == "yes"):
            data = returnJson(aiJsonResponse[i])
            vulnerability.append(data)
        elif(aiJsonResponse[i]["vulnerable"].lower() == "needtocheck"):
            if aiJsonResponse[i]["defense"] == "csrfToken":
                index = index_of_first(reqs,"url",aiJsonResponse[i]["url"])
                body = {k: unquote(v) for k, v in reqs[index].get("body_params", {}).items()}
                relevantParam = aiJsonResponse[i]["relevantParam"]
                url = aiJsonResponse[i]["url"]
                cookieVal = reqs[index]["extra_headers"]["Cookie"][8:]
                csrfTokenName = aiJsonResponse[i]["parameter"]
                csrfTokenVal = reqs[index]["body_params"][csrfTokenName]
                invalidTokenVal = csrfTokenVal+"0"
                # test 1 : submit with invalid scrt Token
                tempBody= body
                tempBody[aiJsonResponse[i]["parameter"]] = invalidTokenVal
                test1 = requests.post(url,data=tempBody,cookies={"session":cookieVal})
                if test1.status_code == 200:
                    data = returnJson(aiJsonResponse[i],aiJsonResponse[i]["defense"])
                    vulnerability.append(data)
                    print("Test1 :Done")
                    print(test1.text)
                    continue
                #test 2: change the method to GET with submiting invalid scrfToken
                getUrl = url+f"?{relevantParam}={body[relevantParam]}&{invalidTokenVal}={csrfTokenVal}"
                test2 = requests.get(getUrl,cookies={"session":cookieVal})
                if test2.status_code == 200:
                    data = returnJson(aiJsonResponse[i],aiJsonResponse[i]["defense"])
                    vulnerability.append(data)
                    print("Test2 :Done")
                    print(test2.text)
                    continue
                #test3 : remove the csrf Token
                tempBody= body
                tempBody.pop(aiJsonResponse[i]["parameter"])
                test3 = requests.post(url,data=tempBody,cookies={"session":cookieVal})
                if test3.status_code == 200:
                    data = returnJson(aiJsonResponse[i],aiJsonResponse[i]["defense"])
                    vulnerability.append(data)
                    print("Test3 :Done")
                    print(test3.text)
                    continue
                #test4: sumbit with valid csrfToken from another user "test will be skiped if user didn't enter a valid csrfToken"
                
                if validToken !="":
                    tempBody= body
                    tempBody[aiJsonResponse[i]["parameter"]] = validToken
                    test4 = requests.post(url,data=tempBody,cookies={"session":cookieVal})
                    if test4.status_code == 200:
                        data = returnJson(aiJsonResponse[i],aiJsonResponse[i]["defense"])
                        vulnerability.append(data)
                        print("Test4 :Done")
                        print(test4.text)
                        continue
                else:
                    data = returnJson(aiJsonResponse[i],aiJsonResponse[i]["defense"],"Valid CSRF Token")
                    vulnerability.append(data)
                
    return vulnerability

def csrf(url_directory):
    aiRes = csrfCheck()
    print(aiRes)
    res = csrfTests(aiRes,reqs)
    print(res.dumps())

csrf()