import json

def save_to_json(vulnerability, filename="../vulnerabilities.json"):
    """
    Appends a vulnerability to a JSON file.

    :param vulnerability: A dictionary containing vulnerability details.
    :param filename: The name of the JSON file to save the data.
    """
    try:
        # Try to load existing data from the file
        with open(filename, "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        # If the file doesn't exist, initialize with an empty list
        data = []

    # Append the new vulnerability
    data.append(vulnerability)

    # Save the updated data back to the file
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)