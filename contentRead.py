import os
import json
import shutil

def readFileContent(filepath):
    """
    Reads a file line by line and returns its contents as a JSON-like dict.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    file_contents = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f, start=1):
            file_contents.append({
                "line": i,
                "text": line.strip()
            })

    return {
        "filename": os.path.basename(filepath),
        "contents": file_contents
    }

# Optional helper: convert result to JSON string for debugging
def to_json(data):
    return json.dumps(data, indent=2)
def clearUploadFolder(upload_dir="uploads"):
    """
    Recursively delete all files and subdirectories inside the upload folder,
    but keep the folder itself.
    """
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
        return

    for filename in os.listdir(upload_dir):
        file_path = os.path.join(upload_dir, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)  # remove file or symlink
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)  # remove directory recursively
        except Exception as e:
            print(f"⚠️ Failed to delete {file_path}: {e}")