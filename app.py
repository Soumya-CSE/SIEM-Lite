from flask import Flask, render_template, request, jsonify
import os
from analyzer import analyze_logs
app = Flask(__name__)

# Get the directory containing app.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Create the full path to the uploads folder
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

# Create the folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("logfile")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    try:
        result = analyze_logs(file.stream)
    except Exception:
        return jsonify({"error": "Unable to parse uploaded log file"}), 400

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port= 5001)