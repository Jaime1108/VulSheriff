# AIAgents/vuln_sheriff_agent.py

import os
import requests
import logging
from typing import List, Dict

# ---------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openrouter/auto"
temperature = 0.2

# Read API key from environment or .env file
API_KEY = os.getenv("OPEN_ROUTING", "").strip()

# ---------------------------------------------------------------------
# LOGGER
# ---------------------------------------------------------------------
logger = logging.getLogger("VulnSheriffAgent")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

# ---------------------------------------------------------------------
# PROMPT TEMPLATE
# ---------------------------------------------------------------------
VULN_PROMPT = (
    "You are VulnSherif, an expert application security auditor. "
    "Analyze the provided website/application source code for security vulnerabilities, "
    "misconfigurations, insecure defaults, and risky patterns. Prioritize actionable, accurate findings.\n\n"
    "Guidelines:\n"
    "- Assume modern best practices (OWASP ASVS, Top 10, CWE).\n"
    "- Identify: severity (Critical/High/Medium/Low), impact, likelihood, affected files, and code snippets.\n"
    "- Provide concrete remediation with code patches or configuration changes.\n"
    "- Prefer minimal, targeted fixes.\n"
    "- If context is insufficient, state assumptions and offer validation steps.\n\n"
    "Output Formatting:\n"
    "1) A concise executive summary.\n"
    "2) A JSON block with the following shape (keep it compact):\n"
    "{\n"
    "\"summary\": \"...\",\n"
    "\"findings\": [\n"
    "  {\n"
    "    \"title\": \"...\",\n"
    "    \"severity\": \"Critical|High|Medium|Low\",\n"
    "    \"cwe\": \"CWE-XXX (name)\",\n"
    "    \"owasp\": \"AXX (name)\",\n"
    "    \"files\": [\"path1\", \"path2\"],\n"
    "    \"description\": \"...\",\n"
    "    \"evidence\": \"short snippet or reference\",\n"
    "    \"remediation\": \"specific steps\",\n"
    "    \"patch\": \"unified diff or code block if feasible\"\n"
    "  }\n"
    "]\n"
    "}\n"
    "3) Then a human-readable detailed report."
)

# ---------------------------------------------------------------------
# AI AGENT CLASS
# ---------------------------------------------------------------------
class VulnSheriffAgent:
    """
    AI Agent for vulnerability scanning using OpenRouter API.
    """

    def __init__(self):
        self.api_key = API_KEY
        self.model = DEFAULT_MODEL
        self.temperature = temperature
        self.prompt = VULN_PROMPT

        if not self.api_key:
            logger.warning("⚠️  OPENROUTER_API_KEY not set. API calls will fail.")

    # 👇 Suggestion: rename `callAgent()` → `invoke()` for clarity
    def invoke(self, user_input: str, timeout: int = 120) -> Dict:
        """
        Send the prompt and user input to the OpenRouter model and return JSON.
        """
        logger.info(f"Invoking {self.model} on input length={len(user_input)}")
        print("I manage to run this")
        messages = [
            {"role": "system", "content": self.prompt},
            {"role": "user", "content": user_input},
        ]

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "X-Title": "VulnSherif",
            "HTTP-Referer": "http://localhost",
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }

        logger.debug(f"POST {OPENROUTER_API_URL} payload={payload}")

        try:
            resp = requests.post(OPENROUTER_API_URL, headers=headers, json=payload, timeout=timeout)
            logger.debug(f"Status={resp.status_code}, bytes={len(resp.content)}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request to OpenRouter failed: {e}")
            raise

        if resp.status_code != 200:
            raise RuntimeError(f"OpenRouter API error {resp.status_code}: {resp.text}")
        print(resp.json())
        return resp.json()
