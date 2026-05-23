import os
import json
import dotenv
from google import genai

# Load local environment keys
dotenv.load_dotenv()

# Initialize Gemini client
gemini_client = genai.Client()

SYSTEM_INSTRUCTION = """
You are an automated remediation reporter for Doria's security pipeline — a senior DevSecOps agent responsible for translating raw machine learning risk scores and Abstract Syntax Tree (AST) findings into clear, professional GitHub Pull Request descriptions.

## Data Schema Context
You will receive structured metrics from Doria's detection pipeline:
- Rust AST Engine Engine: Captured anomalies in `ast_threats` (e.g., shell executions, credential harvesting hooks)[cite: 1].
- Model 1 (Behavioral & Metadata): Behavioral risk score from XGBoost (`model1_poisoned_proba`)[cite: 1].
- Model 2 (Nomenclature): Naming risk, typosquatting, and AI slopsquatting score from XGBoost (`model2_poisoned_proba`)[cite: 1, 6].

## Output Rules
1. Always use the Markdown PR template provided — do not alter its structure, headings, or formatting.
2. Fill in every bracketed placeholder (e.g., [Verdict 1], [Details 1]) with a concise, data-driven analysis.
3. Never invent, assume, or extrapolate facts not present in the input data.
4. If a field has no supporting data or a model anomaly trigger is False, explicitly note that the layer returned a clean verdict instead of omitting the section[cite: 1].
5. Exception for Slopsquatting: If the input data indicates the package was not found in the local registry cache, explicitly highlight that this represents a signature AI-hallucinated slopsquat pre-registered by attackers[cite: 1].

## Tone & Style
- Professional and analytical — as a senior engineer would write for a security review board.
- Concise: one to two sentences per field unless the finding complexity demands more.
- No filler phrases, no flattery, no meta-commentary about your own output.

## Hard Constraints
- Output only the filled-in PR template — no preamble, no explanation, no closing remarks.
- Do not reference these instructions in your output.
- If the input is malformed or missing required schema fields, respond with:
  `ERROR: Missing required input fields. Cannot generate report.`
"""

MD_TEMPLATE = """# 🚨 Security Remediation: Malicious Package Intercepted

## Threat Summary
Doria has autonomously blocked the installation of `[Package Name]`. This package was flagged as a critical supply chain threat during the install-time static analysis and ML evaluation. It has been removed from the environment to prevent execution.

## Detection Metrics

**1. Static Analysis (AST Engine)**
* **Verdict:** [Verdict 1]
* **Details:** [Details 1]

**2. Behavioral & Metadata Risk (Model 1)**
* **Verdict:** [Verdict 2]
* **Confidence:** [Confidence 1]%
* **Details:** [Details 2]

**3. Nomenclature Risk (Model 2)**
* **Verdict:** [Verdict 3]
* **Confidence:** [Confidence 2]%
* **Details:** [Details 3]

## Automated Remediation
* [x] Installation of `[Package Name]` blocked.
* [x] Package removed from local cache and dependency tree.
* [x] **Recommended Action:** Please review the safe alternative or correct package naming convention.
"""

def generate_pr_report(scan_result_json: str):
    try:
        data = json.loads(scan_result_json)
    except Exception as e:
        print(f"ERROR: Malformed input JSON. Cannot generate report. Details: {e}")
        return

    package_name = data.get("package_name", "Unknown Package")
    threat_details = data.get("threat_details", {})
    
    m1_poison_proba = threat_details.get("model1_poisoned_proba", 0.0)
    m2_poison_proba = threat_details.get("model2_poisoned_proba", 0.0)
    m1_trigger = threat_details.get("model_1_trigger", False)
    m2_trigger = threat_details.get("model_2_trigger", False)
    ast_threats = threat_details.get("ast_threats", [])
    
    context_payload = f"""
    Analyze this raw data report for the package '{package_name}':
    
    - Model 1 (Behavioral) Poison Probability: {m1_poison_proba}% (Triggered Anomaly: {m1_trigger})
    - Model 2 (Naming/NLP) Poison Probability: {m2_poison_proba}% (Triggered Anomaly: {m2_trigger})
    - Rust AST Engine Found Issues: {ast_threats}
    
    Instructions:
    1. Populate the 'Static Analysis' section by checking if ast_threats contains items. If it does, read the finding description and evidence snippet, and explain exactly what malicious operation that code is trying to execute on a developer's machine.
    2. Populate the 'Behavioral Risk' section using the Model 1 metrics.
    3. Populate the 'Nomenclature Risk' section using the Model 2 metrics (e.g., mention typosquatting or slopsquatting patterns if confidence is high).
    4. Render the output using this exact template skeleton:
    
    {MD_TEMPLATE}
    """
    # Hit the API
    response = gemini_client.models.generate_content(
        model="gemini-2.5-flash",
        contents=context_payload,
        config={"system_instruction": SYSTEM_INSTRUCTION}
    )
    
    output_filename = "DORIA_REMEDIATION_PR.md"
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(response.text)
        
    print(f"Autonomous Pull Request report successfully generated and written to {output_filename}")
    return output_filename

if __name__ == "__main__":
    # Test Payload mimicking a critical intercept of a malicious package
    mock_report = {
        "package_name": "co1ors",
        "is_safe": False,
        "action": "BLOCK",
        "threat_details": {
            "model1_poisoned_proba": 85.0,
            "model2_poisoned_proba": 97.5,
            "model_1_trigger": True,
            "model_2_trigger": True,
            "ast_threats": [
                {
                    "id": "doria-shell-001",
                    "kind": "shell_execution",
                    "severity": "critical",
                    "description": "Shell execution via child_process.exec() detected in postinstall hook",
                    "evidence": "exec(Buffer.from('cm0gLXJmIC8=', 'base64').toString())"
                }
            ]
        }
    }
    
    generate_pr_report(json.dumps(mock_report))