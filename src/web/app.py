from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from src.scanner import WebSecurityScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///webscanner.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    company = db.Column(db.String(120))
    scans = db.relationship('Scan', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    risk_score = db.Column(db.Float)
    findings = db.relationship('Finding', backref='scan', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vulnerability_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    evidence = db.Column(db.Text)
    mitigation = db.Column(db.Text)
    cvss_score = db.Column(db.Float)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User(
            username=request.form['username'],
            email=request.form['email'],
            company=request.form['company']
        )
        user.set_password(request.form['password'])
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_scans = current_user.scans
    return render_template('dashboard.html', scans=user_scans)

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        url = request.form['url']
        scanner = WebSecurityScanner(url)
        results = scanner.run_full_scan()
        
        # Create new scan record
        scan = Scan(target_url=url, user_id=current_user.id)
        db.session.add(scan)
        
        # Process and store findings
        total_score = 0
        num_findings = 0
        
        for vuln_type, findings in results.items():
            for finding in findings:
                severity_scores = {
                    'Critical': 10.0,
                    'High': 8.0,
                    'Medium': 5.0,
                    'Low': 2.0
                }
                
                cvss_score = severity_scores.get(finding.get('severity', 'Low'), 2.0)
                total_score += cvss_score
                num_findings += 1
                
                new_finding = Finding(
                    vulnerability_type=vuln_type,
                    severity=finding.get('severity', 'Low'),
                    description=finding.get('description', ''),
                    evidence=str(finding),
                    cvss_score=cvss_score,
                    mitigation=get_mitigation_recommendation(vuln_type),
                    scan_id=scan.id
                )
                db.session.add(new_finding)
        
        if num_findings > 0:
            scan.risk_score = total_score / num_findings
        scan.status = 'completed'
        db.session.commit()
        
        return redirect(url_for('scan_results', scan_id=scan.id))
    
    return render_template('scan.html')

@app.route('/scan/<int:scan_id>')
@login_required
def scan_results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return redirect(url_for('dashboard'))
    return render_template('scan_results.html', scan=scan)

def get_mitigation_recommendation(vuln_type):
    recommendations = {
        'xss': '''
            To prevent XSS vulnerabilities:
            1. Implement input validation
            2. Use content security policy (CSP)
            3. Encode/escape output
            4. Use modern frameworks that automatically escape data
        ''',
        'sqli': '''
            To prevent SQL Injection:
            1. Use parameterized queries
            2. Implement input validation
            3. Use ORM frameworks
            4. Apply principle of least privilege
        ''',
        'csrf': '''
            To prevent CSRF:
            1. Implement anti-CSRF tokens
            2. Use SameSite cookie attribute
            3. Verify origin headers
            4. Implement proper session management
        ''',
        'directory_traversal': '''
            To prevent Directory Traversal:
            1. Validate and sanitize file paths
            2. Use whitelist of allowed paths
            3. Implement proper access controls
            4. Use safe file handling libraries
        '''
    }
    return recommendations.get(vuln_type.lower(), 'Contact security team for mitigation steps.')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)