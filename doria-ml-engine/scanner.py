import json
import argparse
import os
import sys
import pandas as pd
from xgboost import XGBClassifier
from calculate_score import package_similarity, package_score

# ── Model loading ────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

model1 = XGBClassifier()
model1.load_model(os.path.join(SCRIPT_DIR, "model1_behavior.json"))

model2 = XGBClassifier()
model2.load_model(os.path.join(SCRIPT_DIR, "model2_nlp.json"))

try:
    with open(os.path.join(SCRIPT_DIR, "top_packages.txt"), "r") as f:
        TOP_PACKAGES = [line.strip() for line in f.readlines()]
except FileNotFoundError:
    TOP_PACKAGES = []

# ── Helpers ───────────────────────────────────────────────────────────────────

def find_local_json(package_name: str):
    """Find the package JSON in our local data folders (offline demo mode)."""
    safe_name = package_name.replace("/", "_") + ".json"
    for folder in ("poisoned_packages", "safe_packages"):
        path = os.path.join(SCRIPT_DIR, "data", folder, safe_name)
        if os.path.exists(path):
            return path
    return None


def parse_ast_findings(rust_ast_json: str) -> list:
    """Parse the JSON that doria-scanner writes to stdout."""
    try:
        data = json.loads(rust_ast_json)
        findings = data.get("findings", [])
        # Make sure every finding is a plain dict (serialisable)
        return [f if isinstance(f, dict) else vars(f) for f in findings]
    except (json.JSONDecodeError, Exception):
        return []

# ── Main scan function ────────────────────────────────────────────────────────

def scan_package(package_name: str, rust_ast_json: str) -> dict:
    """
    Full Doria scan pipeline.

    Parameters
    ----------
    package_name  : the npm package name to evaluate
    rust_ast_json : the JSON string that doria-scanner printed to stdout
    """

    # ── Parse AST findings from Rust ─────────────────────────────────────
    ast_findings = parse_ast_findings(rust_ast_json)
    has_ast_threats = len(ast_findings) > 0

    # ── Try to find registry metadata locally ────────────────────────────
    package_path = find_local_json(package_name)

    if not package_path:
        # Package not found locally → likely a slopsquat hallucination
        return {
            "package_name": package_name,
            "is_safe": False,
            "action": "BLOCK",
            "threat_details": {
                "error": (
                    "Package not found in local registry cache. "
                    "This may be an AI-hallucinated (slopsquatting) package name."
                ),
                "model1_safe_proba": 0.0,
                "model2_safe_proba": 0.0,
                "model1_poisoned_proba": 100.0,
                "model2_poisoned_proba": 100.0,
                "model_1_trigger": True,
                "model_2_trigger": True,
                "ast_threats": ast_findings,
            }
        }

    # ── Feature engineering ───────────────────────────────────────────────
    model1_row, parsed_package_name, _label = package_score(package_path)
    model1_row = model1_row[:-1]  # drop the label column
    model2_row = package_similarity(parsed_package_name, TOP_PACKAGES)

    model1_df = pd.DataFrame([model1_row], columns=[
        "age_in_days", "maintain_age_in_days", "num_of_users",
        "maintainer_count", "maintainer_is_new", "has_readme",
        "version_count", "has_repository",
    ])

    model2_df = pd.DataFrame([model2_row], columns=[
        "edit_distance", "char_sub", "underscore_sub",
        "prefix_suffix", "conflation", "known_slopsquat",
    ])

    # ── Model inference ───────────────────────────────────────────────────
    model1_safe_p, model1_poison_p = model1.predict_proba(model1_df)[0]
    model2_safe_p, model2_poison_p = model2.predict_proba(model2_df)[0]

    behavioral_anomaly = bool(model1_poison_p >= 0.5)
    naming_anomaly     = bool(model2_poison_p >= 0.5)

    # ── Final decision (OR-gate) ──────────────────────────────────────────
    is_safe = not (behavioral_anomaly or naming_anomaly or has_ast_threats)

    return {
        "package_name": parsed_package_name,
        "is_safe": is_safe,
        "action": "BLOCK" if not is_safe else "ALLOW",
        "threat_details": {
            "model1_safe_proba":     float(model1_safe_p)   * 100,
            "model2_safe_proba":     float(model2_safe_p)   * 100,
            "model1_poisoned_proba": float(model1_poison_p) * 100,
            "model2_poisoned_proba": float(model2_poison_p) * 100,
            "model_1_trigger": behavioral_anomaly,
            "model_2_trigger": naming_anomaly,
            "ast_threats": ast_findings,
        }
    }

# ── CLI entry point (called by Rust via subprocess) ───────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Doria ML Brain")
    parser.add_argument("--package", required=True, help="NPM package name to scan")
    parser.add_argument("--ast",     required=True, help="JSON string from doria-scanner (Rust)")
    args = parser.parse_args()

    result = scan_package(args.package, args.ast)

    # One JSON line to stdout — Rust reads exactly this
    print(json.dumps(result))
    sys.stdout.flush()
