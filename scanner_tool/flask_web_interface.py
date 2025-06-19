"""
Flask Web Interface - Provides a web interface for the port scanner

This module is responsible for:
1. Creating and configuring the Flask web application
2. Handling HTTP requests for scanning and exporting results
3. Managing the web interface templates and static files
4. Coordinating between user input and the scanner engine
"""

# Step 1: Import standard Python libraries
import os              # For file and directory operations
import json            # For JSON serialization/deserialization
import socket          # For network operations
import ipaddress       # For IP address validation
import threading       # For running scans in background threads
import time            # For timing operations
from datetime import datetime  # For timestamping
from typing import Dict, List, Tuple, Optional  # Type hints
from dotenv import load_dotenv

# Step 2: Import Flask framework components
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash
from scanner_tool.auth import auth, init_db, login_required, admin_required, get_supabase

# Step 3: Import local modules
# These are the core components of the scanning system
from scanner_tool.scanner_engine import ScannerEngine         # Handles actual port scanning
from scanner_tool.threading_module import ThreadingModule     # Manages multithreaded execution
from scanner_tool.data_export_layer import DataExportLayer    # Handles exporting results

# Load environment variables
load_dotenv()

# Step 4: Create and configure Flask app
# The app serves templates from the templates folder and static files from the static folder
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.getenv("FLASK_SECRET_KEY", "scanner_tool_secret_key_dev")  # Use environment variable

# Register the auth blueprint
app.register_blueprint(auth)

# Initialize the database
init_db()

# Step 5: Initialize core components
# These instances will be used throughout the application
scanner_engine = ScannerEngine()       # Creates scanner engine instance
threading_module = ThreadingModule()   # Creates threading module instance
data_export = DataExportLayer()        # Creates data export layer instance

# Step 6: Define global variables to track scan state
# These dictionaries store information about active scans and their results
active_scans = {}  # Maps scan_id to scan state information
scan_results = {}  # Maps scan_id to final scan results

# Step 7: Define constants
# DEFAULT_PORTS is a list of commonly open ports to scan by default
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 389, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Step 8: Define directory setup function
def ensure_directories():
    """
    Step 8.1: Ensure required directories exist.
    This function creates all necessary directories for the application to function properly.
    These directories store templates, static files, and scan results.
    """
    # Create directories for templates
    os.makedirs('scanner_tool/templates', exist_ok=True)
    # Create directories for static files
    os.makedirs('scanner_tool/static', exist_ok=True)
    os.makedirs('scanner_tool/static/css', exist_ok=True)
    os.makedirs('scanner_tool/static/js', exist_ok=True)
    # Create directory for scan results
    os.makedirs('scan_results', exist_ok=True)

# Generate HTML templates
def create_templates():
    """Create HTML templates if they don't exist."""
    # Index template
    index_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Port Scanner</title>
        <link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    </head>
    <body>
        <div class="cyber-lines-top"></div>
        <div class="cyber-lines-bottom"></div>
        
        <div class="container">
            <header>
                <div class="cyber-header">
                    <div class="cyber-glitch" data-text="PORT·SCAN·v1.0">PORT·SCAN·v1.0</div>
                    <h1>Multi-Threaded Port Scanner</h1>
                    <p class="subtitle">Discover network services with precision</p>
                    <div class="cyber-scanner"></div>
                </div>
            </header>
            
            <div class="card scan-config tech-card">
                <div class="card-corner top-left"></div>
                <div class="card-corner top-right"></div>
                <div class="card-corner bottom-left"></div>
                <div class="card-corner bottom-right"></div>
                
                <h2><span class="tech-icon">⚙</span> Scan Configuration</h2>
                <div class="form-group">
                    <label for="target">Target Host:</label>
                    <div class="input-group">
                        <input type="text" id="target" name="target" placeholder="Enter IP address or hostname" class="form-control tech-input">
                        <button onclick="useLocalIP()" class="btn btn-secondary tech-btn">
                            <span class="btn-text">Use Local IP</span>
                            <span class="btn-icon">⟲</span>
                        </button>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="port-range">Port Range:</label>
                    <div class="input-group">
                        <input type="text" id="port-range" name="port-range" placeholder="e.g., 80,443,8000-8100" class="form-control tech-input" value="21,22,23,25,80,443,3306,8080">
                        <div class="checkbox-wrapper tech-checkbox">
                            <input type="checkbox" id="use-predefined" name="use-predefined" checked>
                            <label for="use-predefined">Use Predefined Ports</label>
                        </div>
                    </div>
                </div>
                
                <div class="form-group advanced tech-panel">
                    <label for="threads">Threads:</label>
                    <input type="number" id="threads" name="threads" value="10" min="1" max="100" class="form-control-sm tech-input">
                    <div id="thread-warning" class="warning-message" style="display: none; color: #ff5722; font-size: 0.8rem; margin-top: 5px;">
                        Warning: High thread count may be limited for optimal performance
                    </div>
                    
                    <label for="timeout">Timeout (s):</label>
                    <input type="number" id="timeout" name="timeout" value="1.0" min="0.1" max="10" step="0.1" class="form-control-sm tech-input">
                </div>
                
                <div class="button-group">
                    <button id="scan-button" onclick="startScan()" class="btn btn-primary tech-btn pulse-btn">
                        <span class="btn-text">Start Scan</span>
                        <span class="btn-icon">⚡</span>
                    </button>
                    <button id="stop-button" onclick="stopScan()" class="btn btn-danger tech-btn" disabled>
                        <span class="btn-text">Stop Scan</span>
                        <span class="btn-icon">✕</span>
                    </button>
                    <button id="export-button" onclick="showExportOptions()" class="btn btn-success tech-btn" disabled>
                        <span class="btn-text">Export Results</span>
                        <span class="btn-icon">↓</span>
                    </button>
                    <button onclick="clearResults()" class="btn btn-secondary tech-btn">
                        <span class="btn-text">Clear</span>
                        <span class="btn-icon">⟲</span>
                    </button>
                </div>
            </div>
            
            <div class="progress-section tech-progress">
                <div class="progress-label">Progress:</div>
                <div class="progress tech-progress-bar">
                    <div id="progress-bar" class="progress-bar"></div>
                </div>
                <div id="status-label" class="status-label tech-status">Ready</div>
            </div>
            
            <div class="card results-section tech-card">
                <div class="card-corner top-left"></div>
                <div class="card-corner top-right"></div>
                <div class="card-corner bottom-left"></div>
                <div class="card-corner bottom-right"></div>
                
                <div class="tab-navigation tech-tabs">
                    <button class="tab-button active" onclick="showTab('table-view')">
                        <span class="tab-icon">◉</span> Table View
                    </button>
                    <button class="tab-button" onclick="showTab('log-view')">
                        <span class="tab-icon">⋮</span> Log View
                    </button>
                </div>
                
                <div id="table-view" class="tab-content active">
                    <div class="table-container tech-table">
                        <table id="results-table">
                            <thead>
                                <tr>
                                    <th>Host</th>
                                    <th>Port</th>
                                    <th>Status</th>
                                    <th>Service</th>
                                </tr>
                            </thead>
                            <tbody id="results-body">
                                <!-- Results will be inserted here -->
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div id="log-view" class="tab-content">
                    <div class="tech-console-header">
                        <div class="console-controls">
                            <span class="console-btn"></span>
                            <span class="console-btn"></span>
                            <span class="console-btn"></span>
                        </div>
                        <div class="console-title">SYSTEM CONSOLE</div>
                    </div>
                    <div id="log-container" class="log-container tech-console">
                        <!-- Logs will be inserted here -->
                    </div>
                </div>
            </div>
            
            <div id="export-modal" class="modal tech-modal">
                <div class="modal-content tech-modal-content">
                    <div class="modal-header">
                        <h2>Export Options</h2>
                        <span class="close-button" onclick="closeExportModal()">&times;</span>
                    </div>
                    <div class="export-options">
                        <button onclick="exportResults('csv')" class="btn btn-primary tech-btn">
                            <span class="btn-text">CSV File</span>
                            <span class="btn-icon">↓</span>
                        </button>
                        <button onclick="exportResults('excel')" class="btn btn-primary tech-btn">
                            <span class="btn-text">Excel File</span>
                            <span class="btn-icon">↓</span>
                        </button>
                        <button onclick="exportResults('pdf')" class="btn btn-primary tech-btn">
                            <span class="btn-text">PDF File</span>
                            <span class="btn-icon">↓</span>
                        </button>
                        <button onclick="closeExportModal()" class="btn btn-secondary tech-btn">
                            <span class="btn-text">Cancel</span>
                            <span class="btn-icon">✕</span>
                        </button>
                    </div>
                </div>
            </div>
            
            <footer class="tech-footer">
                <div class="footer-line"></div>
                <p>PORT SCANNER v1.0.0 | <span id="current-time"></span></p>
                <div class="tech-badge">MULTITHREADED</div>
            </footer>
        </div>
        
        <script src="{{ url_for('static', filename='js/script.js') }}"></script>
    </body>
    </html>
    """
    
    if not os.path.exists('scanner_tool/templates/index.html'):
        with open('scanner_tool/templates/index.html', 'w') as f:
            f.write(index_html)

# Generate CSS styles
def create_css():
    """Create CSS styles if they don't exist."""
    css = """
    /* Variables */
    :root {
        --primary-color: #0a0a0a;
        --secondary-color: #00FF9C;
        --background-color: #0a0a0a;
        --text-color: #00FF9C;
        --success-color: #00FF9C;
        --warning-color: #FFD700;
        --info-color: #00FFFF;
        --card-bg: #0F1F0F;
        --border-color: #00FF9C;
        --highlight-color: #00FF9C;
        --grid-line-color: rgba(0, 255, 156, 0.1);
        --tech-glow: 0 0 15px rgba(0, 255, 156, 0.7);
        --tech-accent: #00FF9C;
        --terminal-bg: #000800;
        --matrix-color: #00FF9C;
    }
    
    /* Base Styles */
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    
    /* Cyber elements */
    .cyber-lines-top,
    .cyber-lines-bottom {
        position: fixed;
        left: 0;
        width: 100%;
        height: 4px;
        background: linear-gradient(90deg, transparent 0%, var(--highlight-color) 50%, transparent 100%);
        z-index: 1000;
    }
    
    .cyber-lines-top {
        top: 0;
    }
    
    .cyber-lines-bottom {
        bottom: 0;
    }
    
    .cyber-header {
        position: relative;
        margin-bottom: 20px;
    }
    
    .cyber-glitch {
        font-size: 1rem;
        letter-spacing: 3px;
        color: var(--tech-accent);
        margin-bottom: 10px;
        position: relative;
        display: inline-block;
        text-shadow: var(--tech-glow);
    }
    
    .cyber-glitch::before,
    .cyber-glitch::after {
        content: attr(data-text);
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
    }
    
    .cyber-glitch::before {
        left: 2px;
        text-shadow: -2px 0 var(--secondary-color);
        animation: glitch-1 2s infinite linear alternate-reverse;
    }
    
    .cyber-glitch::after {
        left: -2px;
        text-shadow: 2px 0 var(--highlight-color);
        animation: glitch-2 3s infinite linear alternate-reverse;
    }
    
    @keyframes glitch-1 {
        0%, 100% { clip-path: inset(50% 0 30% 0); }
        20% { clip-path: inset(33% 0 33% 0); }
        40% { clip-path: inset(10% 0 60% 0); }
        60% { clip-path: inset(70% 0 20% 0); }
        80% { clip-path: inset(40% 0 43% 0); }
    }
    
    @keyframes glitch-2 {
        0%, 100% { clip-path: inset(20% 0 50% 0); }
        20% { clip-path: inset(60% 0 20% 0); }
        40% { clip-path: inset(30% 0 40% 0); }
        60% { clip-path: inset(50% 0 30% 0); }
        80% { clip-path: inset(10% 0 60% 0); }
    }
    
    .cyber-scanner {
        position: absolute;
        bottom: -10px;
        left: 50%;
        transform: translateX(-50%);
        width: 50%;
        height: 2px;
        background: var(--highlight-color);
        box-shadow: 0 0 10px var(--highlight-color);
        animation: scanner-move 2s infinite;
    }
    
    @keyframes scanner-move {
        0%, 100% { transform: translateX(-100%); }
        50% { transform: translateX(100%); }
    }
    
    .tech-card {
        position: relative;
        border: 1px solid var(--border-color);
        background: var(--card-bg);
        box-shadow: 0 0 20px rgba(0, 0, 0, 0.3);
        overflow: visible;
    }
    
    .card-corner {
        position: absolute;
        width: 10px;
        height: 10px;
        border: 1px solid var(--highlight-color);
        z-index: 1;
    }
    
    .top-left {
        top: -2px;
        left: -2px;
        border-right: none;
        border-bottom: none;
    }
    
    .top-right {
        top: -2px;
        right: -2px;
        border-left: none;
        border-bottom: none;
    }
    
    .bottom-left {
        bottom: -2px;
        left: -2px;
        border-right: none;
        border-top: none;
    }
    
    .bottom-right {
        bottom: -2px;
        right: -2px;
        border-left: none;
        border-top: none;
    }
    
    .tech-icon {
        color: var(--highlight-color);
        margin-right: 8px;
        text-shadow: var(--tech-glow);
    }
    
    .tech-input {
        background-color: rgba(10, 15, 20, 0.7);
        border: 1px solid var(--border-color);
        color: var(--text-color);
        font-family: 'JetBrains Mono', monospace;
        transition: all 0.3s;
    }
    
    .tech-input:focus {
        border-color: var(--highlight-color);
        box-shadow: var(--tech-glow);
    }
    
    .tech-checkbox {
        display: flex;
        align-items: center;
    }
    
    .tech-panel {
        background-color: rgba(0, 0, 0, 0.3);
        border: 1px solid var(--border-color);
        position: relative;
    }
    
    .tech-panel::before {
        content: "ADVANCED";
        position: absolute;
        top: -8px;
        left: 10px;
        font-size: 0.6rem;
        background-color: var(--card-bg);
        padding: 0 5px;
        color: var(--highlight-color);
    }
    
    .tech-btn {
        background-color: var(--primary-color);
        border: none;
        color: white;
        border-radius: 4px;
        transition: all 0.3s;
        position: relative;
        overflow: hidden;
    }
    
    .tech-btn:after {
        content: "";
        position: absolute;
        top: -50%;
        left: -60%;
        width: 200%;
        height: 200%;
        background: linear-gradient(60deg, transparent, rgba(255, 255, 255, 0.1), transparent);
        transform: rotate(30deg);
        transition: all 0.6s;
    }
    
    .tech-btn:hover:after {
        left: 100%;
    }
    
    .tech-btn:hover {
        box-shadow: 0 0 10px rgba(2, 179, 228, 0.5);
    }
    
    .btn-text, .btn-icon {
        position: relative;
        z-index: 2;
    }
    
    .pulse-btn {
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% {
            box-shadow: 0 0 0 0 rgba(2, 179, 228, 0.4);
        }
        70% {
            box-shadow: 0 0 0 10px rgba(2, 179, 228, 0);
        }
        100% {
            box-shadow: 0 0 0 0 rgba(2, 179, 228, 0);
        }
    }
    
    .tech-progress {
        position: relative;
        border: 1px solid var(--border-color);
    }
    
    .tech-progress::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(90deg, 
            transparent 0%, 
            rgba(2, 179, 228, 0.05) 50%, 
            transparent 100%);
        animation: progress-bg 2s infinite;
        z-index: 0;
    }
    
    @keyframes progress-bg {
        0% { background-position: -100% 0; }
        100% { background-position: 100% 0; }
    }
    
    .tech-progress-bar {
        height: 12px;
        background-color: rgba(0, 0, 0, 0.3);
        border-radius: 6px;
        overflow: hidden;
        position: relative;
    }
    
    .tech-status {
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        background-color: rgba(0, 0, 0, 0.3);
        border: 1px solid var(--border-color);
    }
    
    .tech-tabs {
        background-color: rgba(0, 0, 0, 0.2);
        padding: 5px;
        border-radius: 4px;
    }
    
    .tab-icon {
        color: var(--highlight-color);
        margin-right: 5px;
    }
    
    .tech-table {
        border: 1px solid var(--border-color);
    }
    
    .tech-table th {
        background-color: rgba(0, 0, 0, 0.3);
        color: var(--highlight-color);
        text-transform: uppercase;
        font-size: 0.7rem;
        letter-spacing: 1px;
    }
    
    .tech-console-header {
        display: flex;
        align-items: center;
        background-color: rgba(0, 0, 0, 0.3);
        padding: 5px 10px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
    }
    
    .console-controls {
        display: flex;
        gap: 5px;
    }
    
    .console-btn {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background-color: #555;
    }
    
    .console-btn:nth-child(1) {
        background-color: #FF5F56;
    }
    
    .console-btn:nth-child(2) {
        background-color: #FFBD2E;
    }
    
    .console-btn:nth-child(3) {
        background-color: #27C93F;
    }
    
    .console-title {
        margin-left: auto;
        margin-right: auto;
        font-size: 0.7rem;
        color: #999;
    }
    
    .tech-console {
        background-color: var(--terminal-bg);
        border: 1px solid var(--border-color);
        border-top: none;
        border-bottom-left-radius: 6px;
        border-bottom-right-radius: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        line-height: 1.4;
        padding: 10px;
        height: 350px;
        box-shadow: inset 0 0 20px rgba(0, 255, 156, 0.1);
        position: relative;
        overflow: auto;
    }
    
    .tech-console::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: repeating-linear-gradient(
            0deg,
            transparent,
            transparent 2px,
            rgba(0, 255, 156, 0.03) 3px,
            rgba(0, 255, 156, 0.03) 3px
        );
        pointer-events: none;
    }
    
    .tech-modal {
        background-color: rgba(0, 0, 0, 0.8);
        backdrop-filter: blur(5px);
    }
    
    .tech-modal-content {
        background-color: var(--card-bg);
        border: 1px solid var(--border-color);
        box-shadow: 0 0 30px rgba(0, 0, 0, 0.5);
        position: relative;
    }
    
    .tech-modal-content::before {
        content: "";
        position: absolute;
        top: -2px;
        left: -2px;
        right: -2px;
        bottom: -2px;
        border: 1px solid var(--highlight-color);
        opacity: 0.3;
        pointer-events: none;
    }
    
    .modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 15px;
        margin-bottom: 20px;
    }
    
    .tech-footer {
        position: relative;
        text-align: center;
        padding: 20px 0;
        color: #718096;
        font-size: 0.8rem;
    }
    
    .footer-line {
        position: absolute;
        top: 0;
        left: 50%;
        transform: translateX(-50%);
        width: 100px;
        height: 1px;
        background: linear-gradient(90deg, transparent, var(--highlight-color), transparent);
    }
    
    .tech-badge {
        display: inline-block;
        margin-top: 10px;
        padding: 3px 10px;
        background-color: rgba(0, 0, 0, 0.3);
        border: 1px solid var(--border-color);
        border-radius: 15px;
        font-size: 0.7rem;
        color: var(--highlight-color);
        letter-spacing: 1px;
    }
    
    body {
        font-family: 'JetBrains Mono', 'Source Code Pro', monospace;
        background-color: var(--background-color);
        color: var(--text-color);
        line-height: 1.6;
        position: relative;
        overflow-x: hidden;
    }
    
    body::before {
        content: "";
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-image: 
            linear-gradient(var(--grid-line-color) 1px, transparent 1px),
            linear-gradient(90deg, var(--grid-line-color) 1px, transparent 1px);
        background-size: 20px 20px;
        z-index: -1;
    }
    
    /* Matrix rain effect in the background */
    body::after {
        content: "";
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: linear-gradient(0deg, 
            rgba(0, 255, 156, 0.03) 25%, 
            rgba(0, 255, 156, 0.01) 50%, 
            transparent 75%);
        opacity: 0.5;
        z-index: -1;
        animation: matrix-rain 20s linear infinite;
    }
    
    @keyframes matrix-rain {
        0% { background-position: 0% 0%; }
        100% { background-position: 0% 1000%; }
    }
    
    .container {
        max-width: 1000px;
        margin: 0 auto;
        padding: 20px;
    }
    
    /* Header */
    header {
        text-align: center;
        margin-bottom: 30px;
        position: relative;
        padding: 20px 0;
    }
    
    header::before {
        content: "";
        position: absolute;
        top: 0;
        left: 50%;
        transform: translateX(-50%);
        width: 100px;
        height: 3px;
        background: linear-gradient(90deg, var(--highlight-color), var(--secondary-color));
        border-radius: 3px;
    }
    
    h1 {
        color: var(--highlight-color);
        margin-bottom: 10px;
        font-size: 2.2rem;
        letter-spacing: 1px;
        text-shadow: 0 0 10px rgba(2, 179, 228, 0.3);
    }
    
    .subtitle {
        color: var(--secondary-color);
        font-style: italic;
        font-size: 1rem;
        opacity: 0.9;
    }
    
    /* Cards */
    .card {
        background: var(--card-bg);
        border-radius: 8px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        padding: 25px;
        margin-bottom: 25px;
        border: 1px solid var(--border-color);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .card::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        width: 3px;
        height: 100%;
        background: linear-gradient(to bottom, var(--highlight-color), var(--secondary-color));
    }
    
    .card:hover {
        transform: translateY(-3px);
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
    }
    
    h2 {
        color: var(--text-color);
        margin-bottom: 20px;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 15px;
        position: relative;
        font-size: 1.4rem;
    }
    
    h2::after {
        content: "";
        position: absolute;
        bottom: -1px;
        left: 0;
        width: 80px;
        height: 3px;
        background: linear-gradient(90deg, var(--highlight-color), transparent);
    }
    
    /* Form Elements */
    .form-group {
        margin-bottom: 20px;
    }
    
    label {
        display: block;
        margin-bottom: 8px;
        font-weight: bold;
        color: var(--highlight-color);
        font-size: 0.9rem;
        letter-spacing: 0.5px;
    }
    
    .input-group {
        display: flex;
        gap: 10px;
    }
    
    .form-control {
        width: 100%;
        padding: 10px 15px;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        font-family: inherit;
        background-color: rgba(17, 24, 39, 0.7);
        color: var(--text-color);
        transition: all 0.3s;
    }
    
    .form-control:focus {
        outline: none;
        border-color: var(--highlight-color);
        box-shadow: 0 0 0 2px rgba(2, 179, 228, 0.2);
    }
    
    .form-control-sm {
        width: 80px;
        padding: 8px 10px;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        font-family: inherit;
        background-color: rgba(17, 24, 39, 0.7);
        color: var(--text-color);
    }
    
    .checkbox-wrapper {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    .checkbox-wrapper input[type="checkbox"] {
        appearance: none;
        width: 18px;
        height: 18px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        background-color: rgba(17, 24, 39, 0.7);
        position: relative;
        cursor: pointer;
    }
    
    .checkbox-wrapper input[type="checkbox"]:checked::before {
        content: "✓";
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        font-size: 12px;
        color: var(--highlight-color);
    }
    
    .advanced {
        display: flex;
        gap: 20px;
        align-items: center;
        padding: 15px;
        background-color: rgba(0, 0, 0, 0.2);
        border-radius: 6px;
        margin-top: 15px;
    }
    
    /* Buttons */
    .button-group {
        display: flex;
        gap: 12px;
        margin-top: 25px;
    }
    
    .btn {
        padding: 10px 18px;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        font-family: inherit;
        font-weight: bold;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        font-size: 0.8rem;
        transition: all 0.3s;
        position: relative;
        overflow: hidden;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
    }
    
    .btn::before {
        content: "";
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
        transition: left 0.7s;
    }
    
    .btn:hover::before {
        left: 100%;
    }
    
    .btn-primary {
        background-color: var(--primary-color);
        color: white;
        box-shadow: 0 4px 6px rgba(44, 62, 80, 0.3);
    }
    
    .btn-danger {
        background-color: var(--secondary-color);
        color: white;
        box-shadow: 0 4px 6px rgba(231, 76, 60, 0.3);
    }
    
    .btn-success {
        background-color: var(--success-color);
        color: white;
        box-shadow: 0 4px 6px rgba(39, 174, 96, 0.3);
    }
    
    .btn-secondary {
        background-color: #34495e;
        color: white;
        box-shadow: 0 4px 6px rgba(52, 73, 94, 0.3);
    }
    
    .btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 10px rgba(0, 0, 0, 0.3);
    }
    
    .btn:active {
        transform: translateY(1px);
    }
    
    .btn:disabled {
        background-color: #4a5568;
        color: #a0aec0;
        cursor: not-allowed;
        box-shadow: none;
    }
    
    .btn:disabled:hover {
        transform: none;
    }
    
    /* Icon styles for buttons */
    .btn::after {
        font-family: monospace;
        font-size: 1rem;
    }
    
    .btn-primary::after {
        content: "⚡";
    }
    
    .btn-danger::after {
        content: "✕";
    }
    
    .btn-success::after {
        content: "↓";
    }
    
    /* Progress Bar */
    .progress-section {
        display: flex;
        align-items: center;
        margin-bottom: 25px;
        gap: 15px;
        background-color: var(--card-bg);
        padding: 15px;
        border-radius: 8px;
        border: 1px solid var(--border-color);
    }
    
    .progress-label {
        flex: 0 0 auto;
        font-weight: bold;
        color: var(--highlight-color);
    }
    
    .progress {
        flex: 1;
        height: 10px;
        background-color: rgba(0, 0, 0, 0.3);
        border-radius: 10px;
        overflow: hidden;
        position: relative;
    }
    
    .progress-bar {
        height: 100%;
        background: linear-gradient(90deg, var(--highlight-color), var(--info-color));
        transition: width 0.3s ease;
        border-radius: 10px;
        position: relative;
    }
    
    .progress-bar::after {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(
            90deg,
            transparent,
            rgba(255, 255, 255, 0.3),
            transparent
        );
        animation: progress-shine 2s infinite;
    }
    
    @keyframes progress-shine {
        0% {
            transform: translateX(-100%);
        }
        100% {
            transform: translateX(100%);
        }
    }
    
    .status-label {
        flex: 0 0 auto;
        font-weight: bold;
        padding: 5px 10px;
        border-radius: 20px;
        background-color: rgba(0, 0, 0, 0.2);
        font-size: 0.8rem;
        min-width: 100px;
        text-align: center;
    }
    
    /* Tabs */
    .tab-navigation {
        display: flex;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 20px;
        gap: 5px;
    }
    
    .tab-button {
        padding: 10px 20px;
        background: none;
        border: none;
        cursor: pointer;
        opacity: 0.7;
        border-bottom: 2px solid transparent;
        color: var(--text-color);
        transition: all 0.3s;
        position: relative;
        font-weight: bold;
    }
    
    .tab-button:hover {
        opacity: 0.9;
        background-color: rgba(255, 255, 255, 0.05);
    }
    
    .tab-button.active {
        opacity: 1;
        border-bottom: 2px solid var(--highlight-color);
        color: var(--highlight-color);
    }
    
    .tab-button.active::before {
        content: "";
        position: absolute;
        bottom: -2px;
        left: 0;
        width: 100%;
        height: 2px;
        background: var(--highlight-color);
        box-shadow: 0 0 10px var(--highlight-color);
    }
    
    .tab-content {
        display: none;
        animation: fadeIn 0.5s ease;
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .tab-content.active {
        display: block;
    }
    
    /* Table */
    .table-container {
        overflow-x: auto;
        border-radius: 6px;
        border: 1px solid var(--border-color);
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
    }
    
    th, td {
        padding: 12px 15px;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
    }
    
    th {
        background-color: rgba(0, 0, 0, 0.2);
        font-weight: bold;
        color: var(--highlight-color);
        position: sticky;
        top: 0;
    }
    
    tbody tr {
        transition: background-color 0.2s;
    }
    
    tbody tr:hover {
        background-color: rgba(255, 255, 255, 0.05);
    }
    
    /* Alternating row colors */
    tbody tr:nth-child(even) {
        background-color: rgba(0, 0, 0, 0.1);
    }
    
    /* Log Container */
    .log-container {
        height: 350px;
        overflow-y: auto;
        padding: 15px;
        background-color: rgba(0, 0, 0, 0.3);
        border-radius: 6px;
        font-size: 0.9rem;
        font-family: 'JetBrains Mono', monospace;
        border: 1px solid var(--border-color);
    }
    
    .log-entry {
        margin-bottom: 8px;
        padding: 8px;
        border-radius: 4px;
        position: relative;
        animation: logFadeIn 0.3s ease;
    }
    
    @keyframes logFadeIn {
        from {
            opacity: 0;
            transform: translateX(-10px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    .log-info {
        color: var(--info-color);
        border-left: 2px solid var(--info-color);
        padding-left: 8px;
        background-color: rgba(52, 152, 219, 0.1);
    }
    
    .log-success {
        color: var(--success-color);
        border-left: 2px solid var(--success-color);
        padding-left: 8px;
        background-color: rgba(39, 174, 96, 0.1);
    }
    
    .log-warning {
        color: var(--warning-color);
        border-left: 2px solid var(--warning-color);
        padding-left: 8px;
        background-color: rgba(243, 156, 18, 0.1);
    }
    
    .log-error {
        color: var(--secondary-color);
        border-left: 2px solid var(--secondary-color);
        padding-left: 8px;
        background-color: rgba(231, 76, 60, 0.1);
    }
    
    /* Modal */
    .modal {
        display: none;
        position: fixed;
        z-index: 1000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.7);
        backdrop-filter: blur(5px);
        animation: fadeIn 0.3s ease;
    }
    
    .modal-content {
        background-color: var(--card-bg);
        margin: 10% auto;
        padding: 25px;
        border-radius: 8px;
        width: 400px;
        max-width: 90%;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
        border: 1px solid var(--border-color);
        position: relative;
        animation: modalSlideIn 0.4s ease;
    }
    
    @keyframes modalSlideIn {
        from {
            opacity: 0;
            transform: translateY(-50px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .close-button {
        position: absolute;
        top: 15px;
        right: 15px;
        font-size: 24px;
        cursor: pointer;
        width: 30px;
        height: 30px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        background-color: rgba(0, 0, 0, 0.2);
        transition: all 0.3s;
    }
    
    .close-button:hover {
        background-color: var(--secondary-color);
        color: white;
        transform: rotate(90deg);
    }
    
    .export-options {
        display: flex;
        flex-direction: column;
        gap: 15px;
        margin-top: 25px;
    }
    
    /* Footer */
    footer {
        text-align: center;
        margin-top: 40px;
        color: #718096;
        font-size: 0.9rem;
        padding: 20px 0;
        position: relative;
    }
    
    footer::before {
        content: "";
        position: absolute;
        top: 0;
        left: 50%;
        transform: translateX(-50%);
        width: 50px;
        height: 2px;
        background: linear-gradient(90deg, transparent, var(--highlight-color), transparent);
    }
    
    /* Matrix-like background animation */
    @keyframes matrix-effect {
        0% {
            background-position: 0% 0%;
        }
        100% {
            background-position: 0% 100%;
        }
    }
    
    /* Typing effect */
    .typing-effect {
        overflow: hidden;
        border-right: 2px solid var(--highlight-color);
        white-space: nowrap;
        margin: 0 auto;
        letter-spacing: 0.1em;
        animation: 
            typing 3.5s steps(30, end),
            blink-caret 0.75s step-end infinite;
    }
    
    @keyframes typing {
        from { width: 0 }
        to { width: 100% }
    }
    
    @keyframes blink-caret {
        from, to { border-color: transparent }
        50% { border-color: var(--highlight-color) }
    }
    
    /* Responsive Design */
    @media (max-width: 768px) {
        .input-group {
            flex-direction: column;
        }
        
        .button-group {
            flex-wrap: wrap;
        }
        
        .advanced {
            flex-direction: column;
            align-items: flex-start;
        }
        
        .progress-section {
            flex-direction: column;
            align-items: stretch;
        }
        
        .status-label {
            align-self: flex-end;
        }
    }
    
    /* Custom Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: rgba(0, 0, 0, 0.2);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: var(--highlight-color);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: var(--secondary-color);
    }
    """
    
    if not os.path.exists('scanner_tool/static/css/styles.css'):
        with open('scanner_tool/static/css/styles.css', 'w') as f:
            f.write(css)

# Generate JavaScript
def create_js():
    """Create JavaScript code if it doesn't exist."""
    js = """
    // Global variables
    let scanActive = false;
    let scanId = null;
    let updateInterval = null;
    let resultCount = 0;
    let typingEffect = false;
    
    // DOM Elements
    const targetInput = document.getElementById('target');
    const portRangeInput = document.getElementById('port-range');
    const threadsInput = document.getElementById('threads');
    const timeoutInput = document.getElementById('timeout');
    const usePredefinedCheck = document.getElementById('use-predefined');
    const scanButton = document.getElementById('scan-button');
    const stopButton = document.getElementById('stop-button');
    const exportButton = document.getElementById('export-button');
    const progressBar = document.getElementById('progress-bar');
    const statusLabel = document.getElementById('status-label');
    const resultsBody = document.getElementById('results-body');
    const logContainer = document.getElementById('log-container');
    const exportModal = document.getElementById('export-modal');
    const currentTimeElem = document.getElementById('current-time');
    
    // Update current time
    function updateTime() {
        const now = new Date();
        currentTimeElem.textContent = now.toLocaleString();
    }
    
    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
        updateTime();
        setInterval(updateTime, 1000);
        
        // Event listeners
        usePredefinedCheck.addEventListener('change', togglePortInput);
        
        // Add terminal typing effect to the header
        const header = document.querySelector('h1');
        applyTypingEffect(header);
        
        // Add some initial tech logs
        setTimeout(() => {
            addLogEntry('System initialized', 'info');
            addLogEntry('Scanner engine loaded', 'info');
            addLogEntry('Multithreading enabled', 'success');
            addLogEntry('Ready to scan network targets', 'info');
        }, 500);
        
        // Add input event listeners for "tech feeling"
        targetInput.addEventListener('focus', () => {
            addLogEntry(`Target input focused`, 'info');
        });
        
        // Add port range visual feedback
        portRangeInput.addEventListener('input', () => {
            validatePortsVisually();
        });
        
        // Add thread count visual feedback
        threadsInput.addEventListener('input', () => {
            const threads = parseInt(threadsInput.value);
            if (!isNaN(threads)) {
                if (threads > 20) {
                    addLogEntry(`Warning: High thread count may impact system performance`, 'warning');
                }
            }
        });
    });
    
    // Apply typing effect to an element
    function applyTypingEffect(element) {
        if (!element || typingEffect) return;
        
        typingEffect = true;
        const text = element.textContent;
        element.textContent = '';
        element.classList.add('typing-effect');
        
        let i = 0;
        const typeInterval = setInterval(() => {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
            } else {
                clearInterval(typeInterval);
                setTimeout(() => {
                    element.classList.remove('typing-effect');
                }, 1000);
            }
        }, 80);
    }
    
    // Validate ports visually
    function validatePortsVisually() {
        try {
            const portRangeText = portRangeInput.value.trim();
            if (!portRangeText) return;
            
            // Count total ports
            let portCount = 0;
            const sections = portRangeText.split(',');
            
            for (const section of sections) {
                if (section.includes('-')) {
                    const [start, end] = section.split('-').map(p => parseInt(p.trim()));
                    if (!isNaN(start) && !isNaN(end) && start <= end) {
                        portCount += (end - start + 1);
                    }
                } else {
                    if (!isNaN(parseInt(section.trim()))) {
                        portCount++;
                    }
                }
            }
            
            if (portCount > 100) {
                addLogEntry(`Scan configuration: ${portCount} ports selected`, 'warning');
            } else if (portCount > 0) {
                addLogEntry(`Scan configuration: ${portCount} ports selected`, 'info');
            }
        } catch (e) {
            // Silently fail
        }
    }
    
    // Tab navigation
    function showTab(tabId) {
        // Add tech sound effect
        playTechSound('switch');
        
        // Hide all tab content
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Remove active class from all tab buttons
        document.querySelectorAll('.tab-button').forEach(button => {
            button.classList.remove('active');
        });
        
        // Show selected tab
        document.getElementById(tabId).classList.add('active');
        
        // Set active class on clicked button
        event.currentTarget.classList.add('active');
        
        addLogEntry(`View switched to ${tabId.replace('-', ' ')}`, 'info');
    }
    
    // Toggle port input based on checkbox
    function togglePortInput() {
        if (usePredefinedCheck.checked) {
            portRangeInput.value = '21,22,23,25,80,443,3306,8080';
            addLogEntry('Using predefined ports', 'info');
        } else {
            portRangeInput.value = '';
            addLogEntry('Custom port configuration enabled', 'info');
        }
        
        // Add tech sound effect
        playTechSound('toggle');
    }
    
    // Get local IP address
    function useLocalIP() {
        // Add tech sound effect
        playTechSound('process');
        
        addLogEntry('Detecting local IP address...', 'info');
        
        fetch('/api/local-ip')
            .then(response => response.json())
            .then(data => {
                if (data.ip) {
                    targetInput.value = data.ip;
                    addLogEntry(`Local IP detected: ${data.ip}`, 'success');
                    
                    // Visual feedback
                    targetInput.classList.add('highlight-success');
                    setTimeout(() => {
                        targetInput.classList.remove('highlight-success');
                    }, 1000);
                }
            })
            .catch(error => {
                addLogEntry(`Error detecting local IP: ${error}`, 'error');
            });
    }
    
    // Play tech sound effect
    function playTechSound(type) {
        // This could be implemented with actual sounds if desired
        // For now we'll just add a visual effect
        const body = document.body;
        
        switch(type) {
            case 'process':
                body.classList.add('processing');
                setTimeout(() => body.classList.remove('processing'), 300);
                break;
            case 'success':
                body.classList.add('success-flash');
                setTimeout(() => body.classList.remove('success-flash'), 300);
                break;
            case 'error':
                body.classList.add('error-flash');
                setTimeout(() => body.classList.remove('error-flash'), 300);
                break;
            case 'switch':
            case 'toggle':
                // Just visual feedback in the log
                break;
        }
    }
    
    // Validate input before starting scan
    function validateInput() {
        const target = targetInput.value.trim();
        const portRange = portRangeInput.value.trim();
        const threads = parseInt(threadsInput.value);
        const timeout = parseFloat(timeoutInput.value);
        
        if (!target) {
            addLogEntry('Error: Target host required', 'error');
            playTechSound('error');
            targetInput.classList.add('highlight-error');
            setTimeout(() => targetInput.classList.remove('highlight-error'), 1000);
            return false;
        }
        
        if (!portRange) {
            addLogEntry('Error: Port range required', 'error');
            playTechSound('error');
            portRangeInput.classList.add('highlight-error');
            setTimeout(() => portRangeInput.classList.remove('highlight-error'), 1000);
            return false;
        }
        
        if (isNaN(threads) || threads < 1) {
            addLogEntry('Error: Thread count must be at least 1', 'error');
            playTechSound('error');
            threadsInput.classList.add('highlight-error');
            setTimeout(() => threadsInput.classList.remove('highlight-error'), 1000);
            return false;
        }
        
        if (isNaN(timeout) || timeout <= 0) {
            addLogEntry('Error: Timeout must be greater than 0', 'error');
            playTechSound('error');
            timeoutInput.classList.add('highlight-error');
            setTimeout(() => timeoutInput.classList.remove('highlight-error'), 1000);
            return false;
        }
        
        return true;
    }
    
    // Start scan
    function startScan() {
        if (!validateInput()) return;
        
        // Add tech sound effect
        playTechSound('process');
        
        const scanData = {
            target: targetInput.value.trim(),
            port_range: portRangeInput.value.trim(),
            threads: parseInt(threadsInput.value),
            timeout: parseFloat(timeoutInput.value)
        };
        
        // Update UI
        scanButton.disabled = true;
        stopButton.disabled = false;
        exportButton.disabled = true;
        statusLabel.textContent = 'Scanning...';
        progressBar.style.width = '0%';
        
        // Clear previous results
        clearResults(false);
        
        // Matrix-like visual effect during scan
        document.body.classList.add('scanning-mode');
        
        // Log scan start
        addLogEntry(`Initializing scan engine...`, 'info');
        addLogEntry(`Target: ${scanData.target}`, 'info');
        addLogEntry(`Preparing ${scanData.threads} scanner threads`, 'info');
        addLogEntry(`Timeout set to ${scanData.timeout} seconds`, 'info');
        addLogEntry(`Scan initiated - connecting to target system`, 'success');
        
        // Start scan
        fetch('/api/scan/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(scanData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                addLogEntry(`Error: ${data.error}`, 'error');
                playTechSound('error');
                resetScanUI();
                return;
            }
            
            scanId = data.scan_id;
            scanActive = true;
            
            // Add scanning indicator to status
            statusLabel.innerHTML = 'Scanning <span class="scan-pulse">⚡</span>';
            
            // Start polling for updates
            updateInterval = setInterval(updateScanProgress, 500);
        })
        .catch(error => {
            addLogEntry(`Connection error: ${error}`, 'error');
            playTechSound('error');
            resetScanUI();
        });
    }
    
    // Stop scan
    function stopScan() {
        if (!scanActive || !scanId) return;
        
        // Add tech sound effect
        playTechSound('process');
        
        addLogEntry('User interrupt signal received', 'warning');
        addLogEntry('Terminating scanner threads...', 'warning');
        
        fetch(`/api/scan/${scanId}/stop`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            addLogEntry('Scan process terminated by user', 'warning');
            document.body.classList.remove('scanning-mode');
            resetScanUI();
        })
        .catch(error => {
            addLogEntry(`Error stopping scan: ${error}`, 'error');
        });
        
        clearInterval(updateInterval);
        scanActive = false;
    }
    
    // Update scan progress
    function updateScanProgress() {
        if (!scanActive || !scanId) return;
        
        fetch(`/api/scan/${scanId}/status`)
            .then(response => response.json())
            .then(data => {
                // Update progress bar
                progressBar.style.width = `${data.progress}%`;
                
                // Add new log entries
                if (data.logs && data.logs.length > 0) {
                    data.logs.forEach(log => {
                        addLogEntry(log.message, log.level);
                    });
                }
                
                // Update results table
                if (data.results) {
                    updateResultsTable(data.results);
                }
                
                // Check if scan is complete
                if (data.status === 'completed' || data.status === 'failed' || data.status === 'stopped') {
                    clearInterval(updateInterval);
                    scanActive = false;
                    document.body.classList.remove('scanning-mode');
                    
                    if (data.status === 'completed') {
                        statusLabel.textContent = `Completed in ${data.duration.toFixed(2)}s`;
                        progressBar.style.width = '100%';
                        
                        // Play success sound
                        playTechSound('success');
                        
                        addLogEntry(`Scan completed in ${data.duration.toFixed(2)} seconds`, 'success');
                        addLogEntry(`Found ${resultCount} open ports`, 'success');
                        
                        // Enable export button if we have results
                        if (data.results && Object.keys(data.results).length > 0) {
                            exportButton.disabled = false;
                            addLogEntry('Export functionality enabled', 'info');
                        }
                    } else if (data.status === 'failed') {
                        statusLabel.textContent = 'Scan Failed';
                        addLogEntry('Scan process failed', 'error');
                        playTechSound('error');
                    } else {
                        statusLabel.textContent = 'Stopped';
                    }
                    
                    scanButton.disabled = false;
                    stopButton.disabled = true;
                }
            })
            .catch(error => {
                addLogEntry(`Connection error: ${error}`, 'error');
                clearInterval(updateInterval);
                document.body.classList.remove('scanning-mode');
                resetScanUI();
            });
    }
    
    // Update results table
    function updateResultsTable(results) {
        const host = targetInput.value.trim();
        const currentPortCount = Object.keys(results).length;
        
        // Only update if we have new results
        if (currentPortCount > resultCount) {
            const newPorts = currentPortCount - resultCount;
            playTechSound('success');
            addLogEntry(`Discovered ${newPorts} new open port${newPorts > 1 ? 's' : ''}`, 'success');
            
            // Clear and rebuild the table for animation effect
            resultsBody.innerHTML = '';
            
            // Update with new result count
            resultCount = currentPortCount;
            
            // Populate table with animation delay
            let delay = 0;
            for (const port in results) {
                const service = results[port];
                
                const row = document.createElement('tr');
                row.style.animation = `fadeIn 0.3s ease ${delay}s both`;
                row.innerHTML = `
                    <td>${host}</td>
                    <td>${port}</td>
                    <td><span class="status-badge">Open</span></td>
                    <td>${service}</td>
                `;
                
                resultsBody.appendChild(row);
                delay += 0.05;
            }
        }
    }
    
    // Add log entry
    function addLogEntry(message, level) {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry log-${level}`;
        
        // Add console-like prefix based on log level
        let prefix = '>';
        switch(level) {
            case 'info': prefix = 'ℹ'; break;
            case 'success': prefix = '✓'; break;
            case 'warning': prefix = '⚠'; break;
            case 'error': prefix = '✗'; break;
        }
        
        logEntry.innerHTML = `<span class="log-time">[${timestamp}]</span> <span class="log-prefix">${prefix}</span> ${message}`;
        
        logContainer.appendChild(logEntry);
        logContainer.scrollTop = logContainer.scrollHeight; // Auto-scroll to bottom
    }
    
    // Reset scan UI
    function resetScanUI() {
        scanButton.disabled = false;
        stopButton.disabled = true;
        scanActive = false;
        clearInterval(updateInterval);
        document.body.classList.remove('scanning-mode');
    }
    
    // Clear results
    function clearResults(clearLogs = true) {
        // Add tech sound effect
        playTechSound('process');
        
        // Clear table
        resultsBody.innerHTML = '';
        resultCount = 0;
        
        // Reset progress
        progressBar.style.width = '0%';
        
        // Disable export button
        exportButton.disabled = true;
        
        // Clear logs if requested
        if (clearLogs) {
            logContainer.innerHTML = '';
            addLogEntry('System reset: Results and logs cleared', 'info');
        }
        
        // Update status
        statusLabel.textContent = 'Ready';
    }
    
    // Show export options modal
    function showExportOptions() {
        if (resultsBody.innerHTML === '') {
            addLogEntry('Error: No results to export', 'error');
            playTechSound('error');
            return;
        }
        
        // Add tech sound effect
        playTechSound('process');
        addLogEntry('Preparing export options...', 'info');
        
        exportModal.style.display = 'block';
    }
    
    // Close export modal
    function closeExportModal() {
        // Add tech sound effect
        playTechSound('toggle');
        exportModal.style.display = 'none';
    }
    
    // Export results
    function exportResults(format) {
        // Add tech sound effect
        playTechSound('process');
        
        addLogEntry(`Preparing ${format.toUpperCase()} export...`, 'info');
        
        fetch(`/api/export/${format}?scan_id=${scanId}`)
            .then(response => {
                if (response.ok) {
                    return response.blob();
                }
                throw new Error('Export failed');
            })
            .then(blob => {
                // Create file name
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const host = targetInput.value.trim();
                const fileName = `${host}_scan_${timestamp}.${format}`;
                
                // Create download link
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileName;
                document.body.appendChild(a);
                a.click();
                
                // Clean up
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
                
                playTechSound('success');
                addLogEntry(`Export successful: ${fileName}`, 'success');
                closeExportModal();
            })
            .catch(error => {
                addLogEntry(`Export error: ${error}`, 'error');
                playTechSound('error');
            });
    }
    
    // Add some CSS classes for the tech effects
    document.head.insertAdjacentHTML('beforeend', `
        <style>
            .scanning-mode {
                animation: scanner-pulse 2s infinite;
            }
            
            @keyframes scanner-pulse {
                0% { background-color: var(--background-color); }
                50% { background-color: #111827; }
                100% { background-color: var(--background-color); }
            }
            
            .processing {
                animation: processing-flash 0.3s;
            }
            
            @keyframes processing-flash {
                0% { background-color: var(--background-color); }
                50% { background-color: rgba(2, 179, 228, 0.1); }
                100% { background-color: var(--background-color); }
            }
            
            .success-flash {
                animation: success-flash 0.3s;
            }
            
            @keyframes success-flash {
                0% { background-color: var(--background-color); }
                50% { background-color: rgba(39, 174, 96, 0.1); }
                100% { background-color: var(--background-color); }
            }
            
            .error-flash {
                animation: error-flash 0.3s;
            }
            
            @keyframes error-flash {
                0% { background-color: var(--background-color); }
                50% { background-color: rgba(231, 76, 60, 0.1); }
                100% { background-color: var(--background-color); }
            }
            
            .highlight-error {
                animation: highlight-error 1s;
            }
            
            @keyframes highlight-error {
                0% { border-color: var(--border-color); }
                50% { border-color: var(--secondary-color); box-shadow: 0 0 10px rgba(231, 76, 60, 0.5); }
                100% { border-color: var(--border-color); }
            }
            
            .highlight-success {
                animation: highlight-success 1s;
            }
            
            @keyframes highlight-success {
                0% { border-color: var(--border-color); }
                50% { border-color: var(--success-color); box-shadow: 0 0 10px rgba(39, 174, 96, 0.5); }
                100% { border-color: var(--border-color); }
            }
            
            .scan-pulse {
                display: inline-block;
                animation: scan-pulse 1s infinite;
            }
            
            @keyframes scan-pulse {
                0% { opacity: 0.5; transform: scale(1); }
                50% { opacity: 1; transform: scale(1.2); }
                100% { opacity: 0.5; transform: scale(1); }
            }
            
            .status-badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 12px;
                background-color: var(--success-color);
                color: white;
                font-size: 0.8rem;
                font-weight: bold;
            }
            
            .log-time {
                color: #718096;
            }
            
            .log-prefix {
                display: inline-block;
                width: 20px;
                text-align: center;
                margin-right: 5px;
            }
        </style>
    `);
    
    // Close modal when clicking outside of it
    window.onclick = function(event) {
        if (event.target === exportModal) {
            closeExportModal();
        }
    };
    """
    
    if not os.path.exists('scanner_tool/static/js/script.js'):
        with open('scanner_tool/static/js/script.js', 'w') as f:
            f.write(js)

# Step 9: Define helper functions
def get_local_ip():
    """
    Step 9.1: Get the local IP address of the machine.
    This helps users scan their own machine easily.
    """
    try:
        # Create a dummy socket to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect to Google's DNS (doesn't actually send data)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        # Return localhost if unable to determine IP
        return "127.0.0.1"

def parse_port_range(port_range: str) -> List[int]:
    """
    Step 10: Parse port range string into a list of port numbers.
    This converts user input like "80,443,8000-8100" into a list of ports to scan.
    
    Args:
        port_range: String representing port range (e.g., "80,443,8000-8100")
        
    Returns:
        List[int]: List of port numbers to scan
    """
    ports = []
    # Step 10.1: Return default ports if no input provided
    if not port_range:
        return DEFAULT_PORTS
    
    # Step 10.2: Parse the port range string    
    sections = port_range.split(',')
    for section in sections:
        section = section.strip()
        if '-' in section:
            # Handle ranges like "8000-8100"
            start, end = map(int, section.split('-'))
            ports.extend(range(start, end + 1))
        else:
            # Handle individual ports like "80"
            ports.append(int(section))
    
    # Step 10.3: Remove duplicates and sort
    return sorted(list(set(ports)))

def scan_worker(scan_id: str, target: str, ports: List[int], thread_count: int, timeout: float):
    """
    Step 11: Worker function to execute a scan in a separate thread.
    This function runs in the background and performs the actual port scanning.
    
    Args:
        scan_id: Unique ID for this scan
        target: Target host to scan
        ports: List of ports to scan
        thread_count: Number of threads to use
        timeout: Socket timeout in seconds
    """
    try:
        # Step 11.1: Initialize scan state
        active_scans[scan_id] = {
            'status': 'running',     # Scan is now running
            'progress': 0,           # 0% progress initially
            'start_time': datetime.now(),  # Record start time
            'logs': [],              # Empty log list
            'results': {}            # Empty results dict
        }
        
        # Step 11.2: Resolve target hostname to IP address
        try:
            ip_address = socket.gethostbyname(target)
            if ip_address != target:
                # Log hostname resolution if successful
                add_log(scan_id, f"Resolved {target} to {ip_address}", "info")
        except Exception as e:
            # Log and exit if hostname resolution fails
            add_log(scan_id, f"Failed to resolve {target}: {e}", "error")
            complete_scan(scan_id, 'failed')
            return
        
        # Step 11.3: Configure scanner timeout
        scanner_engine.timeout = timeout
        
        # Step 11.4: Set up progress tracking
        total_ports = len(ports)
        completed_ports = 0
        
        # Step 11.5: Define progress callback function
        def update_progress(port_number, status):
            nonlocal completed_ports
            completed_ports += 1
            # Calculate percentage progress
            progress = int((completed_ports / total_ports) * 100)
            
            # Update progress in scan state
            active_scans[scan_id]['progress'] = progress
            
            # Log status for open ports
            if status:
                service = scanner_engine.fetch_service_info(port_number)
                add_log(scan_id, f"Port {port_number} is open: {service}", "success")
        
        # Step 11.6: Execute the scan using the scanner engine
        # This is where the ScannerEngine and ThreadingModule work together
        scan_results = scanner_engine.scan_ports(
            target,                     # Target host
            ports,                      # Ports to scan
            threading_module,           # Threading module for parallel scanning
            thread_count,               # Number of threads to use
            progress_callback=update_progress  # Callback for progress updates
        )
        
        # Step 11.7: Store scan results
        active_scans[scan_id]['results'] = scan_results
        
        # Step 11.8: Log completion status
        if scan_results:
            add_log(scan_id, f"Scan completed. Found {len(scan_results)} open ports.", "info")
        else:
            add_log(scan_id, "Scan completed. No open ports found.", "warning")
        
        # Step 11.9: Mark scan as completed
        complete_scan(scan_id, 'completed')
        
    except Exception as e:
        # Step 11.10: Handle any unexpected errors
        add_log(scan_id, f"Error during scan: {e}", "error")
        complete_scan(scan_id, 'failed')

def add_log(scan_id: str, message: str, level: str = "info"):
    """
    Step 12: Add a log message to the scan state.
    This function is used to track progress and provide feedback to the user.
    
    Args:
        scan_id: Unique ID for the scan
        message: Log message
        level: Log level (info, success, warning, error)
    """
    if scan_id in active_scans:
        # Create log entry with timestamp
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'level': level
        }
        # Add to scan's log list
        active_scans[scan_id]['logs'].append(log_entry)

def complete_scan(scan_id: str, status: str):
    """
    Step 13: Mark a scan as completed.
    This updates the scan status and stores results for later retrieval.
    
    Args:
        scan_id: Unique ID for the scan
        status: Final status (completed, failed, stopped)
    """
    if scan_id in active_scans:
        # Update scan status
        active_scans[scan_id]['status'] = status
        # Record end time
        active_scans[scan_id]['end_time'] = datetime.now()
        
        # Store results in the global results dictionary for later access
        scan_results[scan_id] = active_scans[scan_id]['results']

# Step 14: Define Flask routes
@app.route('/')
def index():
    """
    Step 11.1: Render the main landing page.
    This page shows a list of approved feedback items.
    """
    try:
        # Fetch approved feedback from Supabase
        supabase = get_supabase()
        response = supabase.table('feedback').select('*').eq('is_approved', True).order('created_at', desc=True).limit(6).execute()
        
        approved_feedback = response.data if response.data else []
    except Exception as e:
        app.logger.error(f"Error fetching approved feedback: {e}")
        approved_feedback = []
        
    return render_template('landing.html', feedback=approved_feedback)

@app.route('/api/feedback/submit', methods=['POST'])
def submit_feedback():
    """API endpoint to submit user feedback."""
    try:
        # Get form data
        name = request.form.get('name', '')
        message = request.form.get('message', '')
        rating = request.form.get('rating', 5)
        
        # Validate input
        if not name or not message:
            return jsonify({'status': 'error', 'message': 'Name and message are required'}), 400
            
        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                rating = 5
        except ValueError:
            rating = 5
            
        # Get user ID if logged in
        user_id = session.get('user_id')
        
        # Create feedback data
        feedback_data = {
            "name": name,
            "message": message,
            "rating": rating,
            "is_approved": False
        }
        
        # Add user_id if available
        if user_id:
            feedback_data["user_id"] = user_id
            
        # Store in Supabase
        supabase = get_supabase()
        result = supabase.table('feedback').insert(feedback_data).execute()
        
        if result.data and len(result.data) > 0:
            return jsonify({
                'status': 'success',
                'message': 'Thank you for your feedback! It will be reviewed by our team.'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to submit feedback. Please try again.'
            }), 500
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error submitting feedback: {str(e)}'
        }), 500

@app.route('/admin/feedback')
@admin_required
def admin_feedback():
    """Admin page for managing user feedback."""
    try:
        # Fetch feedback from Supabase
        supabase = get_supabase()
        feedback = supabase.table('feedback').select('*').order('created_at', desc=True).execute()
        
        return render_template('admin/feedback.html', feedback=feedback.data)
    except Exception as e:
        flash(f'Error retrieving feedback: {str(e)}', 'error')
        return render_template('admin/feedback.html', feedback=[])

@app.route('/api/feedback/approve/<feedback_id>', methods=['POST'])
@admin_required
def approve_feedback(feedback_id):
    """API endpoint to approve user feedback."""
    try:
        # Update feedback approval status in Supabase
        supabase = get_supabase()
        result = supabase.table('feedback').update({"is_approved": True}).eq('id', feedback_id).execute()
        
        if result.data and len(result.data) > 0:
            return jsonify({'status': 'success', 'message': 'Feedback approved'})
        else:
            return jsonify({'status': 'error', 'message': 'Feedback not found'}), 404
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error approving feedback: {str(e)}'}), 500

@app.route('/api/feedback/delete/<feedback_id>', methods=['POST'])
@admin_required
def delete_feedback(feedback_id):
    """API endpoint to delete user feedback."""
    try:
        # Delete feedback from Supabase
        supabase = get_supabase()
        result = supabase.table('feedback').delete().eq('id', feedback_id).execute()
        
        if result.data and len(result.data) > 0:
            return jsonify({'status': 'success', 'message': 'Feedback deleted'})
        else:
            return jsonify({'status': 'error', 'message': 'Feedback not found'}), 404
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error deleting feedback: {str(e)}'}), 500

@app.route('/api/feedback/approved', methods=['GET'])
def get_approved_feedback():
    """API endpoint to get approved feedback for public display."""
    try:
        # Fetch approved feedback from Supabase
        supabase = get_supabase()
        feedback = supabase.table('feedback').select('*').eq('is_approved', True).order('created_at', desc=True).execute()
        
        return jsonify({'status': 'success', 'feedback': feedback.data})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error retrieving feedback: {str(e)}'}), 500

@app.route('/export-history')
@login_required
def export_history():
    """
    Display the export history page.
    This page shows a list of previous exports for the logged-in user.
    """
    try:
        # Get user_id from session
        user_id = session.get('user_id')
        
        # Fetch export history from Supabase
        supabase = get_supabase()
        exports = supabase.table('scan_exports').select('*').eq('user_id', user_id).order('export_date', desc=True).execute()
        
        return render_template('export_history.html', exports=exports.data)
    except Exception as e:
        flash(f'Error retrieving export history: {str(e)}', 'error')
        return render_template('export_history.html', exports=[])

@app.route('/api/exports', methods=['GET'])
@login_required
def api_export_history():
    """
    API endpoint for getting export history data for the current user.
    """
    try:
        # Get user_id from session
        user_id = session.get('user_id')
        
        # Fetch export history from Supabase
        supabase = get_supabase()
        exports = supabase.table('scan_exports').select('*').eq('user_id', user_id).order('export_date', desc=True).execute()
        
        # Format export data for display
        formatted_exports = []
        for export in exports.data:
            formatted_exports.append({
                'id': export['id'],
                'scan_id': export['scan_id'],
                'target_host': export['target_host'],
                'export_format': export['export_format'].upper(),
                'file_path': export['file_path'],
                'file_size': export['file_size'],
                'export_date': export['export_date'],
                'port_count': export['port_count'],
                'open_port_count': export['open_port_count'],
                'summary': export['summary']
            })
            
        return jsonify({
            'status': 'success',
            'exports': formatted_exports
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error retrieving export history: {str(e)}'
        }), 500

@app.route('/api/export/<int:export_id>/download', methods=['GET'])
@login_required
def download_export(export_id):
    """Download a previously exported file."""
    try:
        with sqlite3.connect(os.path.join(os.path.dirname(__file__), 'users.db')) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_exports WHERE id = ?", (export_id,))
            export = cursor.fetchone()
            
            if not export:
                return jsonify({'error': 'Export not found'}), 404
            
            # Check if user has permission (is the owner)
            user_id = session.get('user_id')
            if export['user_id'] and export['user_id'] != user_id:
                return jsonify({'error': 'Permission denied'}), 403
            
            filepath = export['file_path']
            
            # Check if file exists
            if not os.path.exists(filepath):
                return jsonify({'error': 'Export file not found'}), 404
            
            # Send file as download attachment
            return send_from_directory(
                os.path.dirname(os.path.abspath(filepath)),
                os.path.basename(filepath),
                as_attachment=True
            )
            
    except Exception as e:
        app.logger.error(f"Error downloading export: {e}")
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

@app.route('/scanner')
@login_required
def scanner_page():
    """Render the scanner page."""
    return render_template('scanner.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Render the dashboard page."""
    return render_template('index_dash.html')

@app.route('/api/local-ip', methods=['GET'])
def api_local_ip():
    """
    Step 14.2: API endpoint to get local IP address.
    This helps users quickly scan their own machine.
    """
    return jsonify({'ip': get_local_ip()})

@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    """
    Step 14.3: API endpoint to start a scan.
    This is the main entry point for initiating a scan from the web interface.
    """
    # Step 14.3.1: Get JSON data from request
    data = request.json
    import multiprocessing
    
    # Step 14.3.2: Validate input
    if not data or 'target' not in data:
        return jsonify({'error': 'Missing target host'}), 400
    
    # Step 14.3.3: Extract scan parameters
    target = data.get('target', '').strip()
    port_range = data.get('port_range', '').strip()
    thread_count = int(data.get('threads', 10))
    timeout = float(data.get('timeout', 1.0))
    
    # Step 14.3.4: Validate and limit thread count based on CPU resources
    # This prevents excessive resource usage
    cpu_count = multiprocessing.cpu_count()
    max_recommended_threads = cpu_count * 2
    
    # Define the warning function outside the condition to ensure it's always available
    def add_thread_warning(scan_id, original_count, max_count):
        warning_msg = f"Thread count {original_count} exceeds recommended maximum of {max_count}"
        add_log(
            scan_id=scan_id,
            message=f"WARNING: {warning_msg}. Using {max_count} threads for optimal performance.",
            level="warning"
        )
    
    # Store original thread count for warning message
    original_thread_count = thread_count
    should_warn = thread_count > max_recommended_threads
    
    if should_warn:
        # Log warning about thread count being capped
        warning_msg = f"Thread count {thread_count} exceeds recommended maximum of {max_recommended_threads}"
        app.logger.warning(warning_msg)
        
        # Limit thread count to the recommended maximum
        thread_count = max_recommended_threads
    
    # Step 14.3.5: Parse and validate ports
    try:
        ports = parse_port_range(port_range)
        if not ports:
            return jsonify({'error': 'No valid ports specified'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid port range'}), 400
    
    # Step 14.3.6: Generate unique scan ID using timestamp and target
    scan_id = f"{int(time.time())}_{target}"
    
    # Step 14.3.7: Show thread warning if needed
    if should_warn:
        add_thread_warning(scan_id, original_thread_count, max_recommended_threads)
    
    # Step 14.3.8: Start scan in a separate thread
    # This allows the web interface to remain responsive during scanning
    scan_thread = threading.Thread(
        target=scan_worker,
        args=(scan_id, target, ports, thread_count, timeout),
        daemon=True  # Daemon thread will be terminated when main thread exits
    )
    scan_thread.start()
    
    # Step 14.3.9: Return scan ID to client for status tracking
    return jsonify({'scan_id': scan_id})

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def api_scan_status(scan_id):
    """
    Step 14.4: API endpoint to get scan status.
    This allows the client to poll for updates on an ongoing scan.
    """
    # Step 14.4.1: Check if scan exists
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Step 14.4.2: Get scan data
    scan_data = active_scans[scan_id]
    
    # Step 14.4.3: Add CPU core information if not already present
    if 'cpu_cores' not in scan_data:
        import multiprocessing
        scan_data['cpu_cores'] = multiprocessing.cpu_count()
        scan_data['max_recommended_threads'] = scan_data['cpu_cores'] * 2
    
    # Step 14.4.4: Calculate scan duration if scan is complete
    duration = 0
    if 'end_time' in scan_data and scan_data['start_time']:
        duration = (scan_data['end_time'] - scan_data['start_time']).total_seconds()
    
    # Step 14.4.5: Get new logs since last fetch (for incremental updates)
    logs_index = int(request.args.get('logs_index', 0))
    new_logs = scan_data['logs'][logs_index:] if logs_index < len(scan_data['logs']) else []
    
    # Calculate real-time statistics for open ports and vulnerabilities
    current_results = scan_data.get('results', [])
    open_ports_count = 0
    vulnerabilities_count = 0
    
    # Process current results for statistics
    if isinstance(current_results, list):
        if all(isinstance(r, dict) for r in current_results):
            open_ports_count = len([r for r in current_results if r.get('status') == 'open'])
            # Check for vulnerable services
            vulnerabilities_count = len([r for r in current_results if r.get('service', '').lower() in ['telnet', 'ftp']])
        else:
            open_ports_count = len(current_results)  # If it's a list of port numbers
            # Check for vulnerable ports
            vulnerabilities_count = len([p for p in current_results if p in [21, 23]])  # FTP and Telnet ports
    
    # Step 14.4.6: Prepare response with current status
    response = {
        'status': scan_data['status'],       # running, completed, failed, or stopped
        'progress': scan_data['progress'],   # percentage complete (0-100)
        'logs': new_logs,                    # new log entries since last fetch
        'logs_index': len(scan_data['logs']), # current log index for next update
        'duration': duration,                # scan duration in seconds
        'real_time_stats': {
            'open_ports': open_ports_count,
            'vulnerabilities': vulnerabilities_count
        }
    }
    
    # Step 14.4.7: Include results if scan is complete
    if scan_data['status'] in ['completed', 'failed', 'stopped']:
        response['results'] = scan_data['results']
    
    # Step 14.4.8: Return JSON response to client
    return jsonify(response)

@app.route('/api/scan/<scan_id>/stop', methods=['POST'])
def api_stop_scan(scan_id):
    """
    Step 14.5: API endpoint to stop a scan.
    This allows users to cancel an ongoing scan.
    """
    # Step 14.5.1: Check if scan exists
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Step 14.5.2: Mark the scan as stopped
    complete_scan(scan_id, 'stopped')
    
    # Step 14.5.3: Return stopped status to client
    return jsonify({'status': 'stopped'})

@app.route('/api/export/<format_type>', methods=['GET'])
def api_export_results(format_type):
    """
    API endpoint for exporting scan results to a file.
    
    Args:
        format_type: The format to export to (csv, excel, pdf, json)
    """
    scan_id = request.args.get('scan_id')
    
    if not scan_id or scan_id not in scan_results:
        return jsonify({
            'status': 'error',
            'message': 'Invalid or missing scan ID'
        }), 400
    
    # Get target host and results
    results = scan_results.get(scan_id, {})
    target_host = active_scans.get(scan_id, {}).get('target', 'unknown')
    
    # Check if we have open ports to export
    open_ports = {}
    for port, data in results.items():
        if data.get('status') == 'open':
            open_ports[int(port)] = data
    
    if not open_ports:
        return jsonify({
            'status': 'error',
            'message': 'No open ports found to export'
        }), 404
    
    try:
        # Export the results based on the requested format
        filepath = ""
        if format_type.lower() == 'csv':
            filepath = data_export.export_to_csv(open_ports, target_host)
        elif format_type.lower() == 'excel':
            filepath = data_export.export_to_excel(open_ports, target_host)
        elif format_type.lower() == 'pdf':
            filepath = data_export.export_to_pdf(open_ports, target_host)
        elif format_type.lower() == 'json':
            filepath = data_export.export_to_json(open_ports, target_host)
        else:
            return jsonify({
                'status': 'error',
                'message': f'Unsupported export format: {format_type}'
            }), 400
        
        if not filepath:
            return jsonify({
                'status': 'error',
                'message': 'Failed to export scan results'
            }), 500
        
        # Get the filename from the filepath
        filename = os.path.basename(filepath)
        
        # Store export in history - always store even if user is not logged in
        user_id = session.get('user_id')
        try:
            # Attempt to store the export history in Supabase
            data_export.store_export_history(
                scan_id=scan_id,
                target_host=target_host,
                export_format=format_type.lower(),
                file_path=filepath,
                user_id=user_id,  # May be None if user is not logged in
                scan_results=open_ports
            )
            app.logger.info(f"Export history stored in Supabase: {scan_id}, {format_type}")
        except Exception as export_error:
            app.logger.error(f"Failed to store export history in Supabase: {str(export_error)}")
            # Continue with the export even if Supabase storage fails
        
        # Return the download link
        download_url = url_for(
            'static',
            filename=os.path.relpath(filepath, app.static_folder)
            if filepath.startswith(app.static_folder)
            else f'../scan_results/{filename}'
        )
        
        return jsonify({
            'status': 'success',
            'message': f'Scan results exported to {format_type.upper()}',
            'download_url': download_url,
            'filename': filename
        })
        
    except Exception as e:
        app.logger.error(f"Export error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Export error: {str(e)}'
        }), 500

@app.route('/api/dashboard/scans')
@login_required
def api_dashboard_data():
    """
    API endpoint to get dashboard data including all scans, statistics, and security issues.
    This provides data for the real-time dashboard.
    """
    # Collect all completed scans (from both active_scans and scan_results)
    all_scans = []
    
    # Add completed scans from scan_results
    for scan_id, results in scan_results.items():
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
            
            # Extract target from scan_id (format: timestamp_target)
            target = scan_id.split('_', 1)[1] if '_' in scan_id else 'unknown'
            
            # Count open ports - safely handle different result formats
            try:
                # Check if results is a list of dictionaries with 'status' key
                if isinstance(results, list) and all(isinstance(r, dict) for r in results):
                    open_ports_count = len([r for r in results if r.get('status') == 'open'])
                # If results is a simple list of port numbers
                elif isinstance(results, list) and all(isinstance(r, int) for r in results):
                    open_ports_count = len(results)  # All ports in this list are considered open
                else:
                    # For any other format, default to 0
                    app.logger.warning(f"Unexpected scan results format for scan_id {scan_id}: {type(results)}")
                    open_ports_count = 0
            except Exception as e:
                app.logger.error(f"Error processing scan results for {scan_id}: {str(e)}")
                open_ports_count = 0
            
            # Extract services - safely handle different result formats
            services = []
            try:
                if isinstance(results, list) and all(isinstance(r, dict) for r in results):
                    for result in results:
                        if result.get('service') and result.get('service') not in services:
                            services.append(result.get('service'))
                # If we have a custom service mapping based on port numbers
                elif isinstance(results, list) and all(isinstance(r, int) for r in results):
                    # Common port to service mappings
                    port_services = {
                        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
                        53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
                        3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Proxy'
                    }
                    for port in results:
                        if port in port_services and port_services[port] not in services:
                            services.append(port_services[port])
            except Exception as e:
                app.logger.error(f"Error extracting services for {scan_id}: {str(e)}")
            
            # Identify potential vulnerabilities - safely handle different result formats
            vulnerabilities = []
            try:
                common_vulnerable_services = ['telnet', 'ftp']
                common_vulnerable_ports = {23: 'telnet', 21: 'ftp'}
                
                if isinstance(results, list) and all(isinstance(r, dict) for r in results):
                    # Process dictionary-based results
                    for result in results:
                        service = result.get('service', '').lower()
                        if service in common_vulnerable_services:
                            vulnerabilities.append({
                                'port': result.get('port'),
                                'service': service,
                                'severity': 'high'
                            })
                elif isinstance(results, list) and all(isinstance(r, int) for r in results):
                    # Process port number list results
                    for port in results:
                        if port in common_vulnerable_ports:
                            vulnerabilities.append({
                                'port': port,
                                'service': common_vulnerable_ports[port],
                                'severity': 'high'
                            })
            except Exception as e:
                app.logger.error(f"Error identifying vulnerabilities for {scan_id}: {str(e)}")
            
            # Create scan entry
            scan_info = {
                'scan_id': scan_id,
                'target': target,
                'timestamp': scan_data.get('start_time').isoformat() if scan_data.get('start_time') else None,
                'status': scan_data.get('status', 'unknown'),
                'open_ports_count': open_ports_count,
                'services': services[:3],  # Limit to 3 services for display
                'vulnerabilities': vulnerabilities
            }
            
            all_scans.append(scan_info)
    
    # Also include running scans that might not have results yet
    for scan_id, scan_data in active_scans.items():
        if scan_id not in scan_results and scan_data.get('status') == 'running':
            # Extract target from scan_id
            target = scan_id.split('_', 1)[1] if '_' in scan_id else 'unknown'
            
            # Create scan entry for running scan
            scan_info = {
                'scan_id': scan_id,
                'target': target,
                'timestamp': scan_data.get('start_time').isoformat() if scan_data.get('start_time') else None,
                'status': 'running',
                'open_ports_count': 0,
                'services': [],
                'vulnerabilities': []
            }
            
            all_scans.append(scan_info)
    
    # Calculate statistics
    total_scans = len(all_scans)
    active_hosts = len(set([scan['target'] for scan in all_scans]))
    
    # Count total open ports across all scans
    open_ports = sum([scan['open_ports_count'] for scan in all_scans])
    
    # Count total vulnerabilities
    vulnerabilities = sum([len(scan.get('vulnerabilities', [])) for scan in all_scans])
    
    # Generate security recommendations based on scan results
    security_issues = []
    
    # Add default recommendations if there are no scans
    if not all_scans:
        security_issues = [
            {
                'title': 'Welcome to PortSentinel',
                'description': 'Start by running a scan on your local network to identify open ports and potential vulnerabilities.'
            },
            {
                'title': 'Security Best Practice',
                'description': 'Regular scanning helps maintain network security. Use the "New Scan" button to begin.'
            }
        ]
    else:
        # Check for hosts with many open ports
        for scan in all_scans:
            if scan['open_ports_count'] > 10:
                security_issues.append({
                    'title': f'Open Port Alert for {scan["target"]}',
                    'description': f'Host {scan["target"]} has {scan["open_ports_count"]} open ports. Consider closing unnecessary services and implementing firewall rules.'
                })
        
        # Check for common vulnerable services
        vulnerable_services = {}
        for scan in all_scans:
            for vuln in scan.get('vulnerabilities', []):
                service = vuln.get('service')
                if service:
                    if service not in vulnerable_services:
                        vulnerable_services[service] = []
                    vulnerable_services[service].append(scan['target'])
        
        for service, hosts in vulnerable_services.items():
            if service == 'telnet':
                security_issues.append({
                    'title': 'Telnet Security Risk',
                    'description': f'Telnet (unencrypted protocol) found on {len(hosts)} host(s). Consider replacing with SSH for secure remote access.'
                })
            elif service == 'ftp':
                security_issues.append({
                    'title': 'FTP Security Risk',
                    'description': f'FTP (unencrypted protocol) found on {len(hosts)} host(s). Consider using SFTP or FTPS for secure file transfers.'
                })
        
        # Check for hosts with SSH
        ssh_hosts = []
        for scan in all_scans:
            if 'SSH' in scan.get('services', []):
                ssh_hosts.append(scan['target'])
        
        if ssh_hosts:
            security_issues.append({
                'title': 'SSH Security',
                'description': f'{len(ssh_hosts)} host(s) have SSH (port 22) open. Ensure key-based authentication is enabled and password auth is disabled.'
            })
    
    response = {
        'scans': all_scans,
        'statistics': {
            'total_scans': total_scans,
            'active_hosts': active_hosts,
            'open_ports': open_ports,
            'vulnerabilities': vulnerabilities
        },
        'security_issues': security_issues
    }
    
    return jsonify(response)

@app.route('/api/scan/<scan_id>/details')
@login_required
def api_scan_details(scan_id):
    """
    API endpoint to get detailed information about a specific scan.
    This provides data for the scan details modal.
    """
    # Check if scan exists
    if scan_id not in active_scans:
        # Return a helpful error message instead of just "Scan not found"
        return jsonify({
            'error': 'Scan not found. The scan may have been deleted or has not been started.',
            'scan_id': scan_id
        }), 404
    
    scan_data = active_scans[scan_id]
    
    # Calculate scan duration
    duration = 0
    if 'end_time' in scan_data and scan_data['start_time']:
        try:
            duration = (scan_data['end_time'] - scan_data['start_time']).total_seconds()
        except Exception as e:
            app.logger.error(f"Error calculating duration: {str(e)}")
    
    # Extract target from scan_id
    target = scan_id.split('_', 1)[1] if '_' in scan_id else 'unknown'
    
    # Get results, defaulting to empty list if not available
    raw_results = scan_data.get('results', [])
    
    # Process results to ensure they're in a consistent format for the client
    processed_results = []
    try:
        # Common port to service mappings
        port_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
            53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
            3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Proxy'
        }
        
        # Check if results is a list of dictionaries
        if isinstance(raw_results, list) and all(isinstance(r, dict) for r in raw_results):
            processed_results = raw_results
        
        # Check if results is a list of port numbers
        elif isinstance(raw_results, list) and all(isinstance(r, int) for r in raw_results):
            for port in raw_results:
                result = {
                    'port': port,
                    'status': 'open',
                    'service': port_services.get(port, 'Unknown'),
                    'banner': None
                }
                processed_results.append(result)
        
        # Handle any other format
        else:
            app.logger.warning(f"Unexpected results format for scan_id {scan_id}: {type(raw_results)}")
    except Exception as e:
        app.logger.error(f"Error processing scan details for {scan_id}: {str(e)}")
    
    # Create response with detailed scan information
    response = {
        'scan_id': scan_id,
        'target': target,
        'timestamp': scan_data.get('start_time').isoformat() if scan_data.get('start_time') else None,
        'duration': duration,
        'status': scan_data.get('status', 'unknown'),
        'results': processed_results
    }
    
    return jsonify(response)

# Step 15: Run setup on import
# These functions create necessary directories and files when the module is imported
ensure_directories()   # Create required directories
create_templates()     # Generate HTML templates
create_css()           # Generate CSS styles
create_js()            # Generate JavaScript code

def run():
    """
    Step 16: Run the Flask web application.
    This function is called when the module is run directly.
    """
    # Step 16.1: Run the Flask app with specified host and port
    # host='0.0.0.0' makes the app accessible from any network interface
    app.run(host='0.0.0.0', port=5000, debug=True)

# Step 17: Module execution check
if __name__ == "__main__":
    # This block only runs when the module is executed directly
    run()