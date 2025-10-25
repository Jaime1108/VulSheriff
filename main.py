from flask import Flask, request, jsonify, render_template
from AIHelper import AIAgentCodeReview
from contentRead import readFileContent
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handles file upload, reads the file contents,
    and sends it to the AI agent for review.
    """
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400

    # --- Save the uploaded file ---
    filename = file.filename
    upload_dir = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)

    try:
        # --- Parse file contents ---
        file_json = readFileContent(filepath)  # Your custom parser

        # --- Pass to AI agent for review ---
        ai_response = AIAgentCodeReview(file_json)

        # --- Combine results for front-end ---
        result = {
            "filename": filename,
            "file_contents": file_json,
            "ai_analysis": ai_response
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "error": f"Processing failed: {str(e)}"
        }), 500


if __name__ == '__main__':
    app.run(debug=True)
