"""
AIAgentCodeReview.py
--------------------
Handles AI-based vulnerability analysis of uploaded code.
Uses the Llamar API (Llama model) to analyze JSON-structured file contents.

Expected input:
{
  "filename": "example.py",
  "contents": [
    {"line": 1, "text": "import os"},
    {"line": 2, "text": "eval(input('> '))"}
  ]
}

Expected output:
{
  "status": "success",
  "model": "Llama-3.3-70B-Instruct",
  "analysis": "Summary of vulnerabilities...",
  "recommendations": [
    {"line": 2, "issue": "Unsafe eval()", "fix": "Use safer parsing methods"}
  ]
}
"""

import os
import json
from llamaapi import LlamaAPI
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()

# --- 🔑 API Initialization ---
LLAMA_API_KEY = os.getenv("LLAMA_API_KEY")
if not LLAMA_API_KEY:
    raise ValueError("Missing LLAMA_API_KEY in environment variables (.env)")

llama = LlamaAPI(LLAMA_API_KEY)

# --- 🧠 Prompt Section (You Can Modify Freely) ---
SYSTEM_PROMPT = """
You are VulSheriff 🤠 — a code security auditor and AI agent specialized in identifying vulnerabilities.
Your job:
1. Review the provided source code (structured as JSON: line numbers + code text).
2. Detect common security issues (SQL injection, XSS, unsafe eval, weak encryption, etc.).
3. Explain the issue clearly and give a secure coding fix.
4. Return your findings in concise JSON format.

Always output valid JSON with this structure:
{
  "analysis": "short summary of the scan",
  "recommendations": [
    {"line": <int>, "issue": "<description>", "fix": "<suggestion>"}
  ]
}
Avoid markdown or additional text.
"""

# --- ⚙️ Agent Dispatcher ---
def callAIAgent(agent_name: str, file_json: dict) -> dict:
    """
    Generic dispatcher to call different AI models.
      """
    match agent_name.upper():
        case "LLAMA":
            return AIAgentCodeReview(file_json)
        case _:
            return AIAgentCodeReview(file_json)
    # This is a placeholder for future model routing.
    # For now, it defaults to the primary Llama agent.
    return AIAgentCodeReview(file_json)

# --- ⚙️ Main Function ---
def AIAgentCodeReview(file_json: dict) -> dict:
    """
    Sends file JSON to the AI model and returns a structured JSON analysis.
    """

    try:
        # Convert JSON to string for readability
        code_text = json.dumps(file_json, indent=2)

        # Build messages for the model
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT.strip()},
            {"role": "user", "content": f"Here is the file for review:\n\n{code_text}"}
        ]

        # Call the Llama API
        response = llama.run({
            "model": "Llama-3.3-70B-Instruct",
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 1024,
        })
        print("DEBUG raw response:", response.json())
        # --- Defensive Parsing Logic ---
        try:
            raw = response.json()
            # Log (optional)
            # print("DEBUG raw LlamaAPI response:", raw)

            # Handle list-style responses
            if isinstance(raw, list):
                raw = raw[0]

            # Handle possible keys
            if "choices" in raw:
                reply_content = raw["choices"][0]["message"]["content"]
            elif "content" in raw:
                reply_content = raw["content"]
            elif "output" in raw:
                reply_content = raw["output"]
            else:
                reply_content = json.dumps(raw)

            # Attempt to parse AI JSON output
            try:
                ai_json = json.loads(reply_content)
            except json.JSONDecodeError:
                ai_json = {"analysis": reply_content}

        except Exception as parse_error:
            ai_json = {
                "analysis": "Failed to parse LlamaAPI response.",
                "error": str(parse_error)
            }

        return {
            "status": "success",
            "model": "Llama-3.3-70B-Instruct",
            "result": ai_json
        }

    except Exception as e:
        return {"status": "error", "error": str(e)}
test_file = {
    "filename": "hello.py",
    "contents": [
        {"line": 1, "text": "print('Hello, world!')"}
    ]
}

print("🚀 Sending test to VulSheriff AI Agent...\n")

# Call your AI function
result = AIAgentCodeReview(test_file)

# Print formatted result
print(json.dumps(result, indent=2))