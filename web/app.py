from flask import Flask, render_template, request
import subprocess
import os

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

@app.route("/", methods=["GET", "POST"])
def index():
    threats = ""
    summary = ""

    if request.method == "POST":
        # Save uploaded log file
        file = request.files["file"]
        log_path = os.path.join(BASE_DIR, "logs", "sample_logs.txt")
        file.save(log_path)

        # Run analyzer
        subprocess.run(["python", "analyzer.py"], cwd=BASE_DIR)

        # Run AI summary
        subprocess.run(["python", "ai_summary.py"], cwd=BASE_DIR)

        # Read outputs
        with open(os.path.join(BASE_DIR, "detected_threats.txt")) as f:
            threats = f.read()

        with open(os.path.join(BASE_DIR, "ai_summary.txt")) as f:
            summary = f.read()

    return render_template("index.html", threats=threats, summary=summary)

if __name__ == "__main__":
    app.run(debug=True)
