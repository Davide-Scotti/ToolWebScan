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
            
            # 🔧 FIX: Usa orchestrator.py invece di scanner.py
            cmd = [
                sys.executable,
                "orchestrator.py",  # ✅ Cambiato da scanner.py
                target_url,
                "-o", str(SCAN_RESULTS_DIR),
                "--yes"  # ✅ Skip interactive prompt
            ]
            
            print(f"🚀 Starting scan with command: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            # Log output per debugging
            if process.stdout:
                print(f"📊 Scan output:\n{process.stdout}")
            if process.stderr:
                print(f"⚠️ Scan errors:\n{process.stderr}")
            
            active_scans[scan_id]["status"] = "completed"
            active_scans[scan_id]["end_time"] = datetime.now().isoformat()
            active_scans[scan_id]["return_code"] = process.returncode
            
        except subprocess.TimeoutExpired:
            active_scans[scan_id]["status"] = "timeout"
            active_scans[scan_id]["error"] = "Scan exceeded 1 hour timeout"
        except Exception as e:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)
            print(f"❌ Scan failed: {e}")
    
    thread = threading.Thread(target=run_scan_background)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan started successfully",
        "check_status_url": f"/api/scan_status/{scan_id}"
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
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "scan_results_dir": str(SCAN_RESULTS_DIR),
        "active_scans": len(active_scans)
    })


# Template HTML per dashboard
def create_templates():
    """Crea template HTML se non esiste"""
    templates_dir = Path("templates")
    templates_dir.mkdir(exist_ok=True)
    
    # Load template from separate HTML file artifact
    dashboard_html = open('dashboard_template.html').read() if Path('dashboard_template.html').exists() else """<!DOCTYPE html>
<html><head><title>Security Scanner</title></head>
<body><h1>Dashboard Loading...</h1>
<p>Please copy the HTML template from the artifact to templates/dashboard.html</p>
</body></html>"""
    
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