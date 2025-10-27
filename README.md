# 🤠 Site Sheriff — Ethical Web Vulnerability Scanner

**Site Sheriff** is an educational and interactive web-based vulnerability scanner designed to simulate real-world web security testing in a safe, ethical environment.  
The goal of the project is to **teach, detect, and visualize** common web vulnerabilities such as SQL injection, XSS, and weak authentication while promoting **ethical hacking** and **secure coding practices**.

---

## 🔥 Features

- 🔍 **Vulnerability Scanning in file content**  
  Detects common web vulnerabilities including SQL Injection, Cross-Site Scripting (XSS), broken authentication, and insecure admin portals.

- 🤖 **AI-Powered Code Auditor**  
  Uses an integrated AI model (Llama/OpenAI) to analyze uploaded code and identify insecure patterns with explanations and recommended fixes.

- 🧠 **Safe Sandbox Testing**  
  Includes a test website environment for students and developers to practice penetration testing legally and safely.

- 📊 **Interactive Report Dashboard**  
  Displays vulnerability scan results, severity ratings, and suggested remediations.  
  Each discovered issue rewards a “bounty” — themed with a fun **cyber-cowboy** aesthetic 🤠.

- 💬 **Real-Time Feedback System**  
  The scanner explains why an issue exists, its risk level, and how to mitigate it.

---

## 🧩 Tech Stack

| Layer | Technology |
|:------|:------------|
| **Frontend** | HTML5, TailwindCSS / Bootstrap, Jinja2 Templates |
| **Backend** | Flask (Python 3) |
| **Database** | SQLite / MySQL |
| **AI Integration** | Llama / OpenAI API |
| **Security Tools** | `nmap`, custom Python scripts, regex-based vulnerability detection |
| **Environment** | VirtualBox + Kali Linux (for ethical testing) |

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/your-username/VulSheriff.git
cd VulSheriff
```
### 2. Install Dependencies
```bash
python -m venv venv
source venv/bin/activate     # On Windows use: venv\Scripts\activate
```
### 3. Install dependencies
```bash
pip install -r requirements.txt
```
### 4. Configuring the environment
```bash
GEMINI_API_KEY=your_api_key_here
```
### 5. Run the Flask application
```bash
python main.py
```
### 6. Visit the app
```
https://localhost:5000
```
git clone https://github.com/your-username/VulSheriff.git
cd VulSheriff
