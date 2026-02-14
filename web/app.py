import os
import subprocess
from flask import Flask, render_template, request, send_file

app = Flask(__name__)

# Get base project directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "logs")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    threats = ""
    summary = ""

    if request.method == "POST":
        if "file" not in request.files:
            return "No file uploaded"

        file = request.files["file"]

        if file.filename == "":
            return "No file selected"

        # Save uploaded file
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        try:
            # Run analyzer
            subprocess.run(
                ["python", "analyzer.py"],
                cwd=BASE_DIR,
                check=True
            )

            # Run AI summary generator
            subprocess.run(
                ["python", "ai_summary.py"],
                cwd=BASE_DIR,
                check=True
            )

        except subprocess.CalledProcessError as e:
            return f"Error running analysis: {e}"

        # Read generated files
        threats_file = os.path.join(BASE_DIR, "detected_threats.txt")
        summary_file = os.path.join(BASE_DIR, "ai_summary.txt")

        if os.path.exists(threats_file):
            with open(threats_file, "r") as f:
                threats = f.read()

        if os.path.exists(summary_file):
            with open(summary_file, "r") as f:
                summary = f.read()

    return render_template("index.html", threats=threats, summary=summary)


# Download CSV report
@app.route("/download-csv")
def download_csv():
    file_path = os.path.join(BASE_DIR, "detected_threats.csv")
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "CSV file not found."


# Download AI summary
@app.route("/download-summary")
def download_summary():
    file_path = os.path.join(BASE_DIR, "ai_summary.txt")
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "Summary file not found."


@app.route("/threat-chart")
def threat_chart():
    chart_path = os.path.join(BASE_DIR, "threat_chart.png")
    if os.path.exists(chart_path):
        return send_file(chart_path, mimetype="image/png", as_attachment=False)
    return "Chart not found.", 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
