import os, json, csv
from datetime import datetime, timezone
from similarity import (
    get_min_edit_distance, 
    char_substitution_detected, 
    underscore_substition_detected, 
    prefix_or_suffix_trickery, 
    conflation_pattern_detection,
    known_slopsquat_detection )

def main():
    try:
        with open("top_packages.txt", "r") as file:
            TOP_PACKAGES = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        TOP_PACKAGES = []

    path_safe = "data/safe_packages"
    path_poison = "data/poisoned_packages"
    
    json_files_safe = [f"{path_safe}/{f}" for f in os.listdir(path_safe) if f.endswith('.json')]
    json_files_poison = [f"{path_poison}/{f}" for f in os.listdir(path_poison) if f.endswith('.json')]
    
    all_json_files = json_files_safe + json_files_poison

    with open('model1_features.csv', 'w', newline='') as f1, \
         open('model2_features.csv', 'w', newline='') as f2:
        
        writerModel1 = csv.writer(f1)
        writerModel2 = csv.writer(f2)
        
        writerModel1.writerow(["age_in_days", "maintain_age_in_days", "num_of_users", "maintainer_count", "maintainer_is_new", "has_readme", "version_count", "has_repository", "label"])
        writerModel2.writerow(['edit_distance', 'char_sub', 'underscore_sub', 'prefix_suffix', 'conflation', 'known_slopsquat', 'label'])
        
        for json_file in all_json_files:
            model1_row, package_name, label = package_score(json_file)
            
            writerModel1.writerow(model1_row)

            model2_row = package_similarity(package_name, TOP_PACKAGES)
            model2_row.append(label)
            writerModel2.writerow(model2_row)

            
            
            

def package_score(json_file:str):

    with open(json_file, "r", encoding="utf-8") as file:
        package_data = json.load(file)

    package_name = package_data.get("name", "")

    version_count = len(package_data.get("versions", {}))
    maintainer_count = len(package_data.get("maintainers", []))    
    time_created = package_data.get("time", {}).get("created", "")   

    try:
        target_date = datetime.fromisoformat(time_created.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = now - target_date
        age_in_days = diff.days
    except ValueError:
        age_in_days = 0

    if "poisoned_packages" in json_file:
        label = 1
    elif "safe_packages" in json_file:
        label = 0
    
    repository_check = package_data.get("repository", "")

    if isinstance(repository_check, dict):
        repo_url = package_data.get("repository").get("url", "")
        if "npm/security-holder" in repo_url:
            has_repository = 0
        else:
            has_repository = 1
    else:
        has_repository = 0
    
    readme = package_data.get("readme", "")
    if readme:
        if "ERROR" in readme:
            has_readme = 0
        else:
            has_readme = 1
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

    if age_in_days > 365 and maintain_age_in_days < 14 and maintainer_count == 1:
        maintainer_is_new = 1
    else:
        maintainer_is_new = 0

    model1_row = [age_in_days, maintain_age_in_days, num_of_users, maintainer_count, maintainer_is_new, has_readme, version_count, has_repository, label]

    return model1_row, package_name, label

def package_similarity(package_name:str, top_packages):


    edit_distance = get_min_edit_distance(package_name, top_packages)
    char_sub = char_substitution_detected(package_name, top_packages)
    underscore_sub = underscore_substition_detected(package_name, top_packages)
    prefix_suffix = prefix_or_suffix_trickery(package_name, top_packages)
    conflation = conflation_pattern_detection(package_name, top_packages)
    known_slop = known_slopsquat_detection(package_name)

    
    model2_row = [edit_distance, char_sub, underscore_sub, prefix_suffix, conflation, known_slop]
    return model2_row
if __name__ == "__main__":
    main()