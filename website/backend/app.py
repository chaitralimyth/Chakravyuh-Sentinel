from flask import Flask, render_template, jsonify
import requests

app = Flask(__name__)

# Sentinel API endpoint
SENTINEL_API_URL = "http://localhost:8000"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/incidents')
def get_incidents():
    """Proxy to get incidents from Sentinel API"""
    try:
        response = requests.get(f"{SENTINEL_API_URL}/incidents")
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/incidents/<session_id>/timeline')
def get_timeline(session_id):
    """Proxy to get timeline from Sentinel API"""
    try:
        response = requests.get(f"{SENTINEL_API_URL}/incidents/{session_id}/timeline")
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
