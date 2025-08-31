from flask import Flask, request, jsonify
from flask_cors import CORS  # type: ignore
from dotenv import load_dotenv
load_dotenv()
import os
import requests

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
PORT = int(os.getenv("PORT", "5000"))

# --- URL Scan Endpoint ---
@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    url = request.json.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = f"url={url}"
    try:
        # Submit URL for scanning
        submit_resp = requests.post(vt_url, headers=headers, data=payload)
        submit_data = submit_resp.json()
        analysis_id = submit_data.get("data", {}).get("id")
        if not analysis_id:
            return jsonify({"error": "Failed to get analysis id.", "details": submit_data}), 400
        
        # Fetch scan result
        analysis_resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        analysis_data = analysis_resp.json()
        
        # Extract stats and results
        attrs = analysis_data.get("data", {}).get("attributes", {})
        stats = attrs.get("stats", {}) or attrs.get("last_analysis_stats", {})
        results = attrs.get("results", {}) or attrs.get("last_analysis_results", {})
        
        malicious_count = stats.get("malicious", 0)
        total_count = sum(stats.values()) if stats else 0
        status = "Malicious" if malicious_count > 0 else "Clean"
        timestamp = attrs.get("date", "")
        
        return jsonify({
            "type": "URL",
            "target": url,
            "detections": f"{malicious_count}/{total_count}",
            "status": status,
            "date": timestamp,
            "analysisResults": results
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- File (PDF) Scan Endpoint ---
@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "File is required"}), 400

    vt_file_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    files = {"file": (file.filename, file.stream, file.mimetype)}
    try:
        submit_resp = requests.post(vt_file_url, headers=headers, files=files)
        submit_data = submit_resp.json()
        analysis_id = submit_data.get("data", {}).get("id")
        if not analysis_id:
            return jsonify({"error": "Failed to get analysis id.", "details": submit_data}), 400
        
        analysis_resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        analysis_data = analysis_resp.json()

        attrs = analysis_data.get("data", {}).get("attributes", {})
        stats = attrs.get("stats", {}) or attrs.get("last_analysis_stats", {})
        results = attrs.get("results", {}) or attrs.get("last_analysis_results", {})

        malicious_count = stats.get("malicious", 0)
        total_count = sum(stats.values()) if stats else 0
        status = "Malicious" if malicious_count > 0 else "Clean"
        timestamp = attrs.get("date", "")

        return jsonify({
            "type": "File",
            "target": file.filename,
            "detections": f"{malicious_count}/{total_count}",
            "status": status,
            "date": timestamp,
            "analysisResults": results
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Image Scan Endpoint (same as file) ---
@app.route('/api/scan/image', methods=['POST'])
def scan_image():
    image = request.files.get('image')
    if not image:
        return jsonify({"error": "Image file is required"}), 400

    vt_file_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    files = {"file": (image.filename, image.stream, image.mimetype)}
    try:
        submit_resp = requests.post(vt_file_url, headers=headers, files=files)
        submit_data = submit_resp.json()
        analysis_id = submit_data.get("data", {}).get("id")
        if not analysis_id:
            return jsonify({"error": "Failed to get analysis id.", "details": submit_data}), 400
        
        analysis_resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        analysis_data = analysis_resp.json()

        attrs = analysis_data.get("data", {}).get("attributes", {})
        stats = attrs.get("stats", {}) or attrs.get("last_analysis_stats", {})
        results = attrs.get("results", {}) or attrs.get("last_analysis_results", {})

        malicious_count = stats.get("malicious", 0)
        total_count = sum(stats.values()) if stats else 0
        status = "Malicious" if malicious_count > 0 else "Clean"
        timestamp = attrs.get("date", "")

        return jsonify({
            "type": "Image",
            "target": image.filename,
            "detections": f"{malicious_count}/{total_count}",
            "status": status,
            "date": timestamp,
            "analysisResults": results
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Optional: Polling Endpoint ---
@app.route('/api/scan/status/<analysis_id>', methods=['GET'])
def scan_status(analysis_id):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print(f"VirusShield backend running on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=True)
