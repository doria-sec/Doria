import os, json, csv
from datetime import datetime, timezone



def main():

    path_safe = "data/safe_packages"
    path_poison = "data/poisoned_packages"
    json_files_safe = [f for f in os.listdir(path_safe) if f.endswith('.json')]
    json_files_poison = [f for f in os.listdir(path_poison) if f.endswith('.json')]

    with open('training_data.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["maintainers", "versions", "has_repo", "age_days", "label"])
        
        for safe_file in json_files_safe:
            safe_row = package_score(f"{path_safe}/{safe_file}")
            writer.writerow(safe_row)
        
        for poison_file in json_files_poison:
            poison_row = package_score(f"{path_poison}/{poison_file}")
            writer.writerow(poison_row)

        

def package_score(json_file:str):

    with open(json_file, "r") as file:
        package_data = json.load(file)


    version_count = len(package_data.get("versions", {}))
    maintainer_count = len(package_data.get("maintainers", []))    
    time_created = package_data.get("time", {}).get("created", "")   

    target_date = datetime.fromisoformat(time_created.replace("Z", "+00:00"))

    now = datetime.now(timezone.utc)

    diff = now - target_date
    age_in_days = diff.days

    if "poisoned_packages" in json_file:
        label = 1
    elif "safe_packages" in json_file:
        label=0
    
    repository_check = package_data.get("repository", "")

    if isinstance(repository_check, dict):
        repo_url = package_data.get("repository").get("url", "")
        if "npm/security-holder" in repo_url:
            has_repository =0
        else:
            has_repository =1
    else:
        has_repository=0
    

    readme = package_data.get("readme", "")
    if readme:
        if "ERROR" in readme:
            has_readme = 0
        else:
            has_readme =1
    else:
        has_readme = 0
    
    time_last_maintained = package_data.get("time", {}).get("modified", "")   
    try:
        target_date_maintain = datetime.fromisoformat(time_last_maintained.replace("Z", "+00:00"))

        now = datetime.now(timezone.utc)

        maintain_diff = now - target_date_maintain
        maintain_age_in_days = maintain_diff.days
    except ValueError:
        maintain_age_in_days = 0
    

    num_of_users = len(package_data.get("users", {}))

    if age_in_days >365 and maintain_age_in_days<14 and maintainer_count ==1:
        maintainer_is_new = 1
    else:
        maintainer_is_new = 0


    return [age_in_days,maintain_age_in_days,num_of_users,maintainer_count,maintainer_is_new,has_readme,version_count,has_repository,label]




if __name__ == "__main__":
    main()