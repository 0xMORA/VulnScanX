import subprocess
import re
import json


def sql_injection_test(file_path):
    results = []
    command = ["sqlmap",
               "--flush-session",
               "-m",
                file_path,
               "--batch",
               "--answers=Do you want to skip further tests involving it?=N",
               "-v",
               "0"
               ]
    
    try:
        
        with open(file_path,"r") as file:
            urls = file.readlines()
        urls = [url.strip() for url in urls]

        
        result = subprocess.run(command, capture_output=True, text=True)
        outputs = re.findall(r"---\s*(.*?)\s*---|ERROR",result.stdout,re.DOTALL)
        outputs = [output.strip() for output in outputs]
        for output in outputs:
            print("===")
            print(output)
        index = 0
        for output in outputs:
            if output == "":
                json_output={
                    "url":urls[index],
                    "Vulnerable to SQL Injection": "NO"
                }
            else:
                lines = output.strip().split("\n")
                json_output={
                "url":urls[index],
                "parameter": "",
                "method": "",
                "types": [],
                
                }      

                current_type = {

                }

                # Parse the lines
                for line in lines:
                    line = line.strip()
                    if line.startswith("Parameter:"):
                        parts = line.split(" ", 2)
                        json_output["parameter"] = parts[1]
                        json_output["method"] = parts[2].strip("()")
                    elif line.startswith("Type:"):
                        # If there's an existing type, append it to the list
                        if current_type:
                            json_output["types"].append(current_type)
                        # Start a new type
                        current_type = {"type": line.split(": ", 1)[1]}
                    elif line.startswith("Title:"):
                        current_type["title"] = line.split(": ", 1)[1]
                    elif line.startswith("Payload:"):
                        current_type["payload"] = line.split(": ", 1)[1]

                # Append the last type
                if current_type:
                    json_output["types"].append(current_type)
            results.append(json.dumps(json_output, indent=4))
            index+=1

        for res in results:
            print("----")
            print(res)


    except Exception as error:
        return json.dumps({"Error": str(error)}, indent=4)



sql_injection_test("q.txt")