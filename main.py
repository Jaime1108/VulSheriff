import os
import io
import json
import zipfile
import shutil
import tempfile
import logging
from FileHandler import DEFAULT_EXTS,  MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES,  format_bytes, safe_extract_zip, collect_files, format_files_for_prompt, is_text_file
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

# Import the agent (your new AI module)
from AIAgent.SheriffAgent import VulnSheriffAgent

# ----------------------------
# FLASK APP CONFIG
# ----------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64MB upload cap


# ----------------------------
# LOGGER
# ----------------------------
def setup_logger():
    level_name = os.getenv("VULNSHERIF_LOG_LEVEL") or ("DEBUG" if os.getenv("VULNSHERIF_DEBUG") else "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    return logging.getLogger("vulnsherif")

logger = setup_logger()



# ----------------------------
# ROUTES
# ----------------------------
@app.get("/")
def index():
    return render_template(
        "web.html",
        default_api_key=os.getenv("OPENROUTER_API_KEY", ""),
        max_files=MAX_FILES,
        max_total=format_bytes(MAX_TOTAL_BYTES),
        max_file=format_bytes(MAX_FILE_BYTES),
    )

@app.post("/analyze")
def analyze():
    """Main route — collects input, delegates to VulnSheriffAgent."""
    #api_key = request.form.get("api_key") or os.getenv("OPENROUTER_API_KEY", "")
    #model = request.form.get("model") or "openrouter/auto"
    notes = request.form.get("notes") or ""
    file = request.files.get("zip_file")
    '''
    if not api_key:
        flash("Missing API key.", "error")
        return redirect(url_for("index"))
    '''
    tmp_root = tempfile.mkdtemp(prefix="vulnsherif_")
    try:
        files = []
        if file and file.filename:
            filename = file.filename.lower()
            if filename.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(file.read())) as zf:
                    safe_extract_zip(zf, tmp_root)
                files, _, _ = collect_files(tmp_root)
            else:
                try:
                    content = file.read().decode("utf-8", errors="ignore")
                except Exception:
                    flash("Unable to read uploaded file.", "error")
                    return redirect(url_for("index"))
        # Prepare text context for the agent
                files = [{
            "path": filename,
            "size": len(content.encode("utf-8")),
            "truncated": False,
            "text": content,
        }]
        
        
        packaged = format_files_for_prompt(files)
        user_context = (f"User Context:\n{notes.strip()}\n\n" if notes.strip() else "") + packaged

        # 🔥 Use the VulnSheriffAgent (no need to rebuild prompt or API call)
        agent = VulnSheriffAgent()
        response_json = agent.invoke(user_context)
        content = response_json.get("choices", [{}])[0].get("message", {}).get("content", "")
        findings = json.loads(content).get("findings", [])
        print("Agent is called")
        return render_template(
            "result.html",
            findings=findings,
            files_included=len(files),
            #model=model from AIAgent.SheriffAgent,
            text_size=format_bytes(sum(f["size"] for f in files)),
        )

    except Exception as e:
        logger.exception(f"Analysis failed: {e}")
        flash(f"Analysis failed: {e}", "error")
        return redirect(url_for("index"))
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

@app.get("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
