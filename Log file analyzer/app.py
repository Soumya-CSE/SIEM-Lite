from flask import Flask, render_template, request
import os
from analyzer import analyze_logs

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"

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

    file.save(path)

    result = analyze_logs(path)

    return render_template(
        "result.html",
        data=result
    )


if __name__ == "__main__":
    app.run(debug=True)
    