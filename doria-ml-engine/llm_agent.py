import os
import dotenv
import google.genai
import json

dotenv.load_dotenv()

gemini_client = google.genai.Client()

def generate_pr_report(scan_result_json):
    ...