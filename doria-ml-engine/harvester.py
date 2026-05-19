import requests
import json
import os
import time
import concurrent.futures

# ANSI Color Codes for better terminal output
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
GRAY = "\033[90m"

session = requests.Session()

CACHE_FILE = "data/checked_packages.txt"

def fetch_package_metadata(package_name: str, target_folder: str):
    safe_filename = package_name.replace("/", "_")
    target_file = os.path.join(target_folder, f"{safe_filename}.json")

    if os.path.exists(target_file):
        return f"{CYAN}Skipped (Already downloaded): {package_name}{RESET}"

    package_url = f"https://registry.npmjs.org/{package_name}"

    max_retries = 3


    for attempt in range(1, max_retries + 1):
        try:
            response = session.get(package_url, timeout=10)

            # IF WE GET RATE LIMITED? (HTTP 429)
            if response.status_code == 429:
                wait_time = 3 ** attempt  # Waits 3s, then 9s, then 27s
                print(f"{YELLOW}RATE LIMITED! NPM told us to slow down on '{package_name}'. Pausing this thread for {wait_time}s... (Attempt {attempt}/{max_retries}){RESET}")
                time.sleep(wait_time)
                continue # Go back to the start of the loop and try again

            # IF THEY SOMEHOW CRASH  (HTTP 500+)
            if response.status_code >= 500:
                wait_time = 3 ** attempt
                print(f"{RED}NPM SERVER ERROR ({response.status_code}) on '{package_name}'. Pausing {wait_time}s... (Attempt {attempt}/{max_retries}){RESET}")
                time.sleep(wait_time)
                continue

            # DID WE FIND A POISONED PACKAGE??? (HTTP 200)
            if response.status_code == 200:
                package_data = response.json()
                if package_data.get("description") == "security holding package":
                    return f"{MAGENTA}Skipped: {package_name} (NPM Security Holding){RESET}"

                with open(target_file, "w") as file:
                    json.dump(package_data, file, indent=4)
                return f"{GREEN}SUCCESS: Data for '{package_name}' found and saved!{RESET}"

            # TYPO DOESN'T EXIST (HTTP 404)
            if response.status_code == 404:
                return f"{GRAY}Not found: {package_name}{RESET}"

            # WEIRD UNKNOWN ERROR
            return f"{YELLOW}WEIRD STATUS {response.status_code} for '{package_name}'{RESET}"

        except requests.exceptions.RequestException as e:
            wait_time = 3 ** attempt
            print(f"{RED}NETWORK ERROR on '{package_name}': {e}. Retrying in {wait_time}s...{RESET}")
            time.sleep(wait_time)

    return f"{RED}GAVE UP: Could not fetch '{package_name}' after {max_retries} attempts.{RESET}"

def generate_typos(package_name: str):
    fake_names = set()
    for i in range(len(package_name)):
        fake_name = package_name[:i] + package_name[i+1:]
        fake_names.add(fake_name)

    duplicate_last_letter = package_name + package_name[-1]
    fake_names.add(duplicate_last_letter)

    return list(fake_names)

if __name__ == "__main__":
    os.makedirs("data/poisoned_packages", exist_ok=True)
    os.makedirs("data/safe_packages", exist_ok=True)

    completed_packages = set()
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            completed_packages = {line.strip() for line in f if line.strip()}

    print(f"{BLUE}Loaded {len(completed_packages)} previously checked packages from cache.{RESET}")

    with open("top_packages.txt", "r") as file:
        safe_packages = [line.strip() for line in file if line.strip()]

    tasks = {}
    for safe_package in safe_packages:
        if safe_package not in completed_packages:
            tasks[safe_package] = "data/safe_packages"

        for typo in generate_typos(safe_package):
            if typo not in completed_packages and typo not in tasks:
                tasks[typo] = "data/poisoned_packages"

    print(f"{BLUE}Remaining unique requests to make: {len(tasks)}{RESET}")
    print(f"{BLUE}Starting workers... \n{RESET}")

    with open(CACHE_FILE, "a") as cache_file:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(fetch_package_metadata, pkg, folder): pkg
                for pkg, folder in tasks.items()
            }

            for future in concurrent.futures.as_completed(futures):
                pkg_name = futures[future]
                try:
                    result = future.result()

                    print(result)

                    cache_file.write(f"{pkg_name}\n")
                    cache_file.flush()

                except Exception as e:
                    print(f"{RED}FATAL THREAD ERROR fetching {pkg_name}: {e}{RESET}")

# BROOOOOOOOOOOO its like 60x faster lmfaoooo
