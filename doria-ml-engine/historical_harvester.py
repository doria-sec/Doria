import requests
import json
import time
import os

historical_packages = []
try:
    with open("historical_poison.txt", "r") as file:
        for line in file:
            clean_name = line.strip()
            if clean_name:
                historical_packages.append(clean_name)
except FileNotFoundError:
    print("Error: historical_poison.txt not found.")
    exit()

target_folder = "data/poisoned_packages"

def fetch_historical_metadata(package_name: str):
    
    safe_filename = package_name.replace("/", "_")
    target_file = os.path.join(target_folder, safe_filename + ".json")

    if os.path.exists(target_file):
        print(f"Already exists, skipping: {package_name}")
        return

    package_url = "https://registry.npmjs.org/" + package_name
    response = requests.get(package_url)

    if response.status_code == 404:
        print(f"Purged: {package_name} (NPM completely deleted this record)")
        return

    if response.status_code == 200:
        package_data = response.json()
        description = package_data.get("description", "")
        
        if description == "security holding package":
            print(f"Discarded: {package_name} (NPM placeholder replaced the malware)")
            return
        
        print(f"SUCCESS! Golden Record Found: {package_name}")
        with open(target_file, "w") as file:
            json.dump(package_data, file, indent=4)
            
    else:
        print(f"Failed: {package_name} returned status code {response.status_code}")

print(f"Starting historical harvest for {len(historical_packages)} packages...")

for package in historical_packages:
    fetch_historical_metadata(package)
    time.sleep(1) 

print("Historical harvest complete.")