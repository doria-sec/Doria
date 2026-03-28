import requests
import json
import time
import os

safe_packages =["react", "express", "lodash"]
# poisoned_packages =["express-mongoose","co1ors","huggingface-cli"]

def fetch_package_metadata (package_name:str, target_folder:str):
    
    package_url = "https://registry.npmjs.org/"+package_name
    
    response = requests.get(package_url)

    if response.status_code == 200:
        print("Success")
        package_data = response.json()

        target_file = os.path.join(target_folder, package_name + ".json")

        with open(target_file, "w") as file:
            json.dump(package_data, file, indent=4)


    else:
        print("Package not found")
    

def generate_typos(package_name:str):
    fake_names = []
    for i in range(len(package_name)):

        fake_name = package_name[:i]+package_name[i+1:]
        fake_names.append(fake_name)
    
    duplicate_last_letter = package_name[-1]
    fake_names.append(package_name+duplicate_last_letter)
    return fake_names


for safe_package in safe_packages:


    hit_list = generate_typos(safe_package)

    for typo in hit_list:
        fetch_package_metadata(typo, "data/poisoned_packages")
        time.sleep(1)

    fetch_package_metadata(safe_package, "data/safe_packages")
    time.sleep(1)


