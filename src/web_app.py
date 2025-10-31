"""
Web Application for Security Scanner
Flask-based interface with dashboard
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import sys
import json
from datetime import datetime
import logging

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import VulnerabilityScanner
from report_generator import ReportGenerator
from utils.analysis import calculate_risk_score, prioritize_vulnerabilities, get_mitigation_recommendation, generate_executive_summary
from utils.logger import setup_logger

logger = setup_logger('WebApp')

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'  # Change this in production!

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple user database (in production, use a real database)
users = {
    'admin': {'password': 'admin123', 'name': 'Administrator'},
    'demo': {'password': 'demo123', 'name': 'Demo User'}
}

# Scan history (in production, use a database)
scan_history = []


class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.name = users[username]['name']


@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username)
    return None


@app.route('/')
def index():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and users[username]['password'] == password:
            user = User(username)
            login_user(user)
            flash(f'Welcome, {user.name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Logout"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    # Get statistics from scan history
    total_scans = len(scan_history)
    total_vulnerabilities = sum(len(scan['vulnerabilities']) for scan in scan_history)
    
    # Get recent scans (last 5)
    recent_scans = sorted(scan_history, key=lambda x: x['timestamp'], reverse=True)[:5]
    
    return render_template('dashboard.html', 
                         total_scans=total_scans,
                         total_vulnerabilities=total_vulnerabilities,
                         recent_scans=recent_scans)


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    """Scan page"""
    if request.method == 'POST':
        target_url = request.form.get('url')
        
        if not target_url:
            flash('Please provide a URL to scan', 'warning')
            return redirect(url_for('scan'))
        
        try:
            # Perform scan
            scanner = VulnerabilityScanner(target_url)
            vulnerabilities = scanner.scan()
            
            # Calculate risk
            risk_analysis = calculate_risk_score(vulnerabilities)
            prioritized_vulns = prioritize_vulnerabilities(vulnerabilities)
            executive_summary = generate_executive_summary(vulnerabilities)
            
            # Store in history
            scan_result = {
                'id': len(scan_history) + 1,
                'url': target_url,
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': vulnerabilities,
                'risk_score': risk_analysis['score'],
                'risk_level': risk_analysis['level'],
                'total_vulnerabilities': len(vulnerabilities),
                'user': current_user.id,
                'executive_summary': executive_summary
            }
            scan_history.append(scan_result)
            
            flash(f'Scan completed! Found {len(vulnerabilities)} vulnerabilities.', 'success' if len(vulnerabilities) == 0 else 'warning')
            return redirect(url_for('results', scan_id=scan_result['id']))
            
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            flash(f'Scan failed: {str(e)}', 'danger')
            return redirect(url_for('scan'))
    
    return render_template('scan.html')


@app.route('/results/<int:scan_id>')
@login_required
def results(scan_id):
    """Results page"""
    # Find scan by ID
    scan_result = next((s for s in scan_history if s['id'] == scan_id), None)
    
    if not scan_result:
        flash('Scan not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Prioritize vulnerabilities
    prioritized_vulns = prioritize_vulnerabilities(scan_result['vulnerabilities'])
    
    # Add mitigation recommendations
    for vuln in prioritized_vulns:
        vuln['mitigation'] = get_mitigation_recommendation(vuln.get('type', ''))
    
    return render_template('results.html', scan=scan_result, vulnerabilities=prioritized_vulns)


@app.route('/history')
@login_required
def history():
    """Scan history page"""
    # Get all scans for current user
    user_scans = [s for s in scan_history if s.get('user') == current_user.id]
    user_scans = sorted(user_scans, key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('history.html', scans=user_scans)


@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    """API endpoint for scanning"""
    data = request.get_json()
    target_url = data.get('url')
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        scanner = VulnerabilityScanner(target_url)
        vulnerabilities = scanner.scan()
        risk_analysis = calculate_risk_score(vulnerabilities)
        
        return jsonify({
            'success': True,
            'url': target_url,
            'vulnerabilities': vulnerabilities,
            'risk_score': risk_analysis['score'],
            'risk_level': risk_analysis['level'],
            'total_vulnerabilities': len(vulnerabilities)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/download/<int:scan_id>/<format>')
@login_required
def api_download(scan_id, format):
    """Download scan report in various formats"""
    scan_result = next((s for s in scan_history if s['id'] == scan_id), None)
    
    if not scan_result:
        return jsonify({'error': 'Scan not found'}), 404
    
    report_gen = ReportGenerator(scan_result['vulnerabilities'], scan_result['url'])
    
    filename = f"scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    if format == 'json':
        filepath = f"/tmp/{filename}.json"
        report_gen.generate_json_report(filepath)
    elif format == 'csv':
        filepath = f"/tmp/{filename}.csv"
        report_gen.generate_csv_report(filepath)
    elif format == 'markdown':
        filepath = f"/tmp/{filename}.md"
        report_gen.generate_markdown_report(filepath)
    else:
        return jsonify({'error': 'Invalid format'}), 400
    
    return jsonify({'success': True, 'file': filepath})


if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    print("=" * 80)
    print("Web Security Scanner - Web Interface")
    print("=" * 80)
    print("Starting server...")
    print("Access the application at: http://localhost:8080")
    print("\nDefault credentials:")
    print("  Username: admin")
    print("  Password: admin123")
    print("\n  Username: demo")
    print("  Password: demo123")
    print("=" * 80)
    
    app.run(debug=True, host='0.0.0.0', port=8080)
