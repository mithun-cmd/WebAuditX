from flask import Flask, render_template, request, send_file, jsonify
from scanner.main_scanner import scan_target

import threading
import uuid

import traceback

from scanner.utils.progress_tracker import init_scan, get_progress

app = Flask(__name__)


# -------------------------------
# Home Page
# -------------------------------
@app.route('/')
def home():
    return render_template('index.html')


# -------------------------------
# Start Scan (Async)
# -------------------------------
@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['url']

    scan_id = str(uuid.uuid4())

    # ✅ initialize task properly
    init_scan(scan_id, target)

    def background_scan():
        try:
            scan_target(target, scan_id)

        except Exception as e:
            traceback.print_exc()

            # fallback safe failure state
            from scanner.utils.progress_tracker import complete_scan

            complete_scan(scan_id, {
                "score": 0,
                "risk": "Error",
                "vulnerabilities": [],
                "safe_checks": ["Scan failed due to internal error"],
                "recommendations": [],
                "report": None
            })

    threading.Thread(target=background_scan, daemon=True).start()

    return jsonify({"scan_id": scan_id})


# -------------------------------
# Scan Progress API
# -------------------------------
@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    return jsonify(get_progress(scan_id))


# -------------------------------
# Show Report Page
# -------------------------------
@app.route('/report/<scan_id>')
def report(scan_id):
    data = get_progress(scan_id)

    if not data or data.get("status") != "completed":
        return "⏳ Scan not completed yet. Please wait...", 202

    result = data.get("result")

    return render_template(
        'results.html',
        score=result["score"],
        risk=result["risk"],
        vulnerabilities=result["vulnerabilities"],
        safe_checks=result["safe_checks"],
        recommendations=result["recommendations"],
        report=result["report"]
    )


# -------------------------------
# Download PDF
# -------------------------------
@app.route('/download')
def download():
    path = request.args.get('file')

    if not path:
        return "File not found", 404

    return send_file(path, as_attachment=True)


# -------------------------------
# Run App
# -------------------------------
if __name__ == '__main__':
    app.run(debug=True)