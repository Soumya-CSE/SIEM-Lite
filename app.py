from flask import Flask, render_template, request
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

    file = request.files["logfile"]

    path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        file.filename
    )
    print(path)
    file.save(path)

    result = analyze_logs(path)

    return render_template(
        "result.html",
        data=result
    )


if __name__ == "__main__":
    app.run(debug=True, port= 5001)