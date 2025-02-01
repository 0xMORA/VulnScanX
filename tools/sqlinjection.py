import subprocess
import re
from .save_json_file import save_to_json

def sql_injection_test(file_path, cookies="", level="", risk="", request_file=""):
    command = [
        "sqlmap",
        "--flush-session",
        "-m", file_path,
        "--batch",
        "--answers=Do you want to skip further tests involving it?=N",
        "-v", "0",
    ]
    if cookies:
        command.extend(["--cookie", cookies])
    if level:
        command.extend(["--level", level])
    if risk:
        command.extend(["--risk", risk])
    if request_file:
        command.extend(["-r", request_file])

    try:
        with open(file_path, "r") as file:
            urls = file.readlines()
        urls = [url.strip() for url in urls]

        result = subprocess.run(command, capture_output=True, text=True)
        outputs = re.findall(r"---\s*(.*?)\s*---|ERROR", result.stdout, re.DOTALL)
        outputs = [output.strip() for output in outputs]

        for index, output in enumerate(outputs):
            if output == "":
                vulnerability_data = {
                    "vulnerability": "SQL Injection",
                    "severity": "None",
                    "url": urls[index],
                    "description": "No parameters vulnerable"
                }
            else:
                lines = output.strip().split("\n")
                vulnerability_data = {
                    "vulnerability": "SQL Injection",
                    "severity": "High",  # Adjust severity as needed
                    "url": urls[index],
                    "parameter": "",
                    "method": "",
                    "types": []
                }

                current_type = {}
                for line in lines:
                    line = line.strip()
                    if line.startswith("Parameter:"):
                        parts = line.split(" ", 2)
                        vulnerability_data["parameter"] = parts[1]
                        vulnerability_data["method"] = parts[2].strip("()")
                    elif line.startswith("Type:"):
                        if current_type:
                            vulnerability_data["types"].append(current_type)
                        current_type = {"type": line.split(": ", 1)[1]}
                    elif line.startswith("Title:"):
                        current_type["title"] = line.split(": ", 1)[1]
                    elif line.startswith("Payload:"):
                        current_type["payload"] = line.split(": ", 1)[1]

                if current_type:
                    vulnerability_data["types"].append(current_type)

            save_to_json(vulnerability_data)

    except Exception as error:
        error_data = {
            "error": str(error)
        }
        save_to_json(error_data)