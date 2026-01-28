#!/usr/bin/env python3
"""
Web Dashboard for Security Scanner
Visualizza risultati delle scansioni in tempo reale
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_cors import CORS
import json
import os
from pathlib import Path
from datetime import datetime
import threading
import subprocess
import sys

app = Flask(__name__)
CORS(app)

# Configuration
SCAN_RESULTS_DIR = Path("scan_results") 
SCAN_RESULTS_DIR.mkdir(exist_ok=True)

# In-memory storage per scan attive
active_scans = {}


@app.route('/')
def index():
    """Dashboard principale"""
    return render_template('dashboard.html')


@app.route('/api/scans')
def get_scans():
    """Ottieni lista di tutte le scansioni"""
    scans = []
    
    for file in SCAN_RESULTS_DIR.glob("summary_*.json"):
        try:
            with open(file) as f:
                data = json.load(f)
                scans.append({
                    "scan_id": data.get("scan_id"),
                    "target": data.get("target"),
                    "start_time": data.get("start_time"),
                    "end_time": data.get("end_time"),
                    "total_vulnerabilities": data.get("summary", {}).get("total_vulnerabilities", 0),
                    "status": "completed"
                })
        except Exception as e:
            print(f"Error loading {file}: {e}")
    
    # Ordina per data (più recenti prima)
    scans.sort(key=lambda x: x.get("start_time", ""), reverse=True)
    
    return jsonify(scans)


@app.route('/api/scan/<scan_id>')
def get_scan_details(scan_id):
    """Ottieni dettagli di una scansione specifica"""
    file = SCAN_RESULTS_DIR / f"summary_{scan_id}.json"
    
    if not file.exists():
        return jsonify({"error": "Scan not found"}), 404
    
    try:
        with open(file) as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    """Avvia una nuova scansione"""
    data = request.json
    target_url = data.get('target_url')
    
    if not target_url:
        return jsonify({"error": "Target URL required"}), 400
    
    # Validazione URL
    if not target_url.startswith(('http://', 'https://')):
        return jsonify({"error": "Invalid URL format"}), 400
    
    # Genera scan ID
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Avvia scansione in background
    def run_scan_background():
        try:
            active_scans[scan_id] = {
                "status": "running",
                "target": target_url,
                "start_time": datetime.now().isoformat()
            }
            
            # Esegui orchestrator
            cmd = [
                sys.executable,
                "scanner.py",
                target_url,
                "-o", str(SCAN_RESULTS_DIR)
            ]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            active_scans[scan_id]["status"] = "completed"
            active_scans[scan_id]["end_time"] = datetime.now().isoformat()
            
        except Exception as e:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)
    
    thread = threading.Thread(target=run_scan_background)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan started successfully"
    })


@app.route('/api/scan_status/<scan_id>')
def get_scan_status(scan_id):
    """Ottieni lo stato di una scansione attiva"""
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    
    # Controlla se è completata
    file = SCAN_RESULTS_DIR / f"summary_{scan_id}.json"
    if file.exists():
        return jsonify({"status": "completed"})
    
    return jsonify({"status": "unknown"}), 404


@app.route('/api/vulnerabilities/<scan_id>')
def get_vulnerabilities(scan_id):
    """Ottieni vulnerabilità di una scansione"""
    file = SCAN_RESULTS_DIR / f"summary_{scan_id}.json"
    
    if not file.exists():
        return jsonify({"error": "Scan not found"}), 404
    
    try:
        with open(file) as f:
            data = json.load(f)
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        # Filtra per severità se richiesto
        severity_filter = request.args.get('severity')
        if severity_filter:
            vulnerabilities = [
                v for v in vulnerabilities 
                if v.get("severity", "").lower() == severity_filter.lower()
            ]
        
        # Filtra per tool se richiesto
        tool_filter = request.args.get('tool')
        if tool_filter:
            vulnerabilities = [
                v for v in vulnerabilities 
                if v.get("tool", "").lower() == tool_filter.lower()
            ]
        
        return jsonify(vulnerabilities)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/statistics')
def get_statistics():
    """Ottieni statistiche aggregate"""
    stats = {
        "total_scans": 0,
        "total_vulnerabilities": 0,
        "vulnerabilities_by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "vulnerabilities_by_tool": {},
        "recent_scans": []
    }
    
    for file in SCAN_RESULTS_DIR.glob("summary_*.json"):
        try:
            with open(file) as f:
                data = json.load(f)
            
            stats["total_scans"] += 1
            
            summary = data.get("summary", {})
            stats["total_vulnerabilities"] += summary.get("total_vulnerabilities", 0)
            
            # Aggregate by severity
            by_severity = summary.get("by_severity", {})
            for severity, count in by_severity.items():
                if severity in stats["vulnerabilities_by_severity"]:
                    stats["vulnerabilities_by_severity"][severity] += count
            
            # Aggregate by tool
            for vuln in data.get("vulnerabilities", []):
                tool = vuln.get("tool", "unknown")
                stats["vulnerabilities_by_tool"][tool] = stats["vulnerabilities_by_tool"].get(tool, 0) + 1
            
            # Recent scans
            stats["recent_scans"].append({
                "scan_id": data.get("scan_id"),
                "target": data.get("target"),
                "vulnerabilities": summary.get("total_vulnerabilities", 0),
                "date": data.get("start_time")
            })
            
        except Exception as e:
            print(f"Error processing {file}: {e}")
    
    # Sort recent scans
    stats["recent_scans"].sort(key=lambda x: x.get("date", ""), reverse=True)
    stats["recent_scans"] = stats["recent_scans"][:10]  # Keep only 10 most recent
    
    return jsonify(stats)


@app.route('/api/export/<scan_id>')
def export_scan(scan_id):
    """Esporta risultati di una scansione"""
    file = SCAN_RESULTS_DIR / f"summary_{scan_id}.json"
    
    if not file.exists():
        return jsonify({"error": "Scan not found"}), 404
    
    return send_from_directory(
        SCAN_RESULTS_DIR,
        f"summary_{scan_id}.json",
        as_attachment=True
    )


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy"})


# Template HTML per dashboard
def create_templates():
    """Crea template HTML se non esiste"""
    templates_dir = Path("templates")
    templates_dir.mkdir(exist_ok=True)
    
    dashboard_html = """<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scanner Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }
        .header h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .scan-form {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .scan-form h2 {
            color: #333;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #666;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 1em;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            font-size: 1em;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .scans-list {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .scan-item {
            padding: 20px;
            border-bottom: 1px solid #eee;
            cursor: pointer;
            transition: background 0.2s;
        }
        .scan-item:hover {
            background: #f5f5f5;
        }
        .severity-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .critical { background: #ff4444; color: white; }
        .high { background: #ff9800; color: white; }
        .medium { background: #ffeb3b; color: #333; }
        .low { background: #4caf50; color: white; }
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Security Scanner Dashboard</h1>
            <p>Advanced Web Application Security Testing Platform</p>
        </div>

        <div class="stats-grid" id="stats">
            <div class="stat-card">
                <h3>Total Scans</h3>
                <div class="value" id="totalScans">0</div>
            </div>
            <div class="stat-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value" id="totalVulns">0</div>
            </div>
            <div class="stat-card">
                <h3>Critical Issues</h3>
                <div class="value" id="criticalIssues" style="color: #ff4444;">0</div>
            </div>
            <div class="stat-card">
                <h3>High Issues</h3>
                <div class="value" id="highIssues" style="color: #ff9800;">0</div>
            </div>
        </div>

        <div class="scan-form">
            <h2>Start New Scan</h2>
            <form id="scanForm">
                <div class="form-group">
                    <label for="targetUrl">Target URL</label>
                    <input type="url" id="targetUrl" placeholder="https://example.com" required>
                </div>
                <button type="submit" class="btn">🚀 Start Scan</button>
            </form>
        </div>

        <div class="scans-list">
            <h2>Recent Scans</h2>
            <div id="scansList" class="loading">Loading scans...</div>
        </div>
    </div>

    <script>
        // Load statistics
        async function loadStats() {
            const response = await fetch('/api/statistics');
            const data = await response.json();
            
            document.getElementById('totalScans').textContent = data.total_scans;
            document.getElementById('totalVulns').textContent = data.total_vulnerabilities;
            document.getElementById('criticalIssues').textContent = data.vulnerabilities_by_severity.critical;
            document.getElementById('highIssues').textContent = data.vulnerabilities_by_severity.high;
        }

        // Load scans list
        async function loadScans() {
            const response = await fetch('/api/scans');
            const scans = await response.json();
            
            const container = document.getElementById('scansList');
            
            if (scans.length === 0) {
                container.innerHTML = '<p class="loading">No scans yet. Start your first scan!</p>';
                return;
            }
            
            container.innerHTML = scans.map(scan => `
                <div class="scan-item" onclick="viewScan('${scan.scan_id}')">
                    <strong>${scan.target}</strong>
                    <br>
                    <small>${new Date(scan.start_time).toLocaleString()}</small>
                    <br>
                    <span class="severity-badge medium">${scan.total_vulnerabilities} vulnerabilities</span>
                </div>
            `).join('');
        }

        // Start new scan
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const targetUrl = document.getElementById('targetUrl').value;
            
            if (!confirm(`Start security scan on ${targetUrl}?\\n\\nMake sure you have authorization!`)) {
                return;
            }
            
            const response = await fetch('/api/start_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_url: targetUrl })
            });
            
            const result = await response.json();
            
            if (response.ok) {
                alert(`Scan started! ID: ${result.scan_id}`);
                document.getElementById('targetUrl').value = '';
                setTimeout(() => {
                    loadScans();
                    loadStats();
                }, 2000);
            } else {
                alert(`Error: ${result.error}`);
            }
        });

        // View scan details
        function viewScan(scanId) {
            window.location.href = `/scan/${scanId}`;
        }

        // Load data on page load
        loadStats();
        loadScans();
        
        // Auto-refresh every 30 seconds
        setInterval(() => {
            loadStats();
            loadScans();
        }, 30000);
    </script>
</body>
</html>"""
    
    (templates_dir / "dashboard.html").write_text(dashboard_html)

# Crea template all'avvio 
create_templates()

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔐 Security Scanner Dashboard")
    print("="*60)
    print("\n📡 Dashboard running on http://0.0.0.0:5000")
    print("🌐 Access from browser: http://localhost:5000\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)