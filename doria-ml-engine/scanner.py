import json
import pandas as pd
from xgboost import XGBClassifier
from calculate_score import package_similarity, package_score

# 1. The Global Brain Load
model1 = XGBClassifier()
model1.load_model("model1_behavior.json")

model2 = XGBClassifier()
model2.load_model("model2_nlp.json")

try:
    with open("top_packages.txt", "r") as file:
        TOP_PACKAGES = [line.strip() for line in file.readlines()]
except FileNotFoundError:
    TOP_PACKAGES = []

def main():
    result = scan_package("data/poisoned_packages/canva.json")
    print(json.dumps(result, indent=4))

def scan_package(pacakage_path):
    model1_row, package_name, label = package_score(pacakage_path)
    model1_row = model1_row[:-1]
    model2_row = package_similarity(package_name, TOP_PACKAGES)

    # FIX 1 & 2: Added [brackets] to make rows 2D, and corrected "known_slopsquat"
    model1_df = pd.DataFrame([model1_row], columns=[
        "age_in_days", "maintain_age_in_days", "num_of_users", 
        "maintainer_count", "maintainer_is_new", "has_readme", 
        "version_count", "has_repository"
    ])
    
    model2_df = pd.DataFrame([model2_row], columns=[
        "edit_distance", "char_sub", "underscore_sub", 
        "prefix_suffix", "conflation", "known_slopsquat"
    ])

    # Unpacking the probabilities safely
    model1prob_safe, model1prob_poisoned = model1.predict_proba(model1_df)[0]
    model2prob_safe, model2prob_poisoned = model2.predict_proba(model2_df)[0]

    # The "Defense in Depth" Logic
    behavioral_anomaly = False
    naming_anomaly = False

    if model1prob_poisoned >= 0.5:
        behavioral_anomaly = True
    if model2prob_poisoned >= 0.5:
        naming_anomaly = True
    
    if behavioral_anomaly or naming_anomaly:
        is_safe = False
    else: 
        is_safe = True

    return {
        "package_name": package_name,
        "is_safe": is_safe,
        "threat_details": {
            # JSON Serialization Fix
            "model1_safe_proba": float(model1prob_safe) * 100,
            "model2_safe_proba": float(model2prob_safe) * 100,
            "model1_poisoned_proba": float(model1prob_poisoned) * 100,
            "model2_poisoned_proba": float(model2prob_poisoned) * 100,
            "model_1_trigger": behavioral_anomaly,
            "model_2_trigger": naming_anomaly
        }
    }

if __name__ == "__main__":
    main()