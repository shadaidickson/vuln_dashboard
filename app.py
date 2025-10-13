from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import random, os

app = Flask(__name__)
app.secret_key = 'vuln_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vuln_data.db'
db = SQLAlchemy(app)

# Database Model
class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_detected = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def index():
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.date_detected.desc()).all()
    severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
    for v in vulnerabilities:
        severity_counts[v.severity] += 1
    return render_template('index.html', vulnerabilities=vulnerabilities, severity_counts=severity_counts)

@app.route('/scan', methods=['POST'])
def scan():
    simulated_vulns = [
        ("SQL Injection", "High", "Unsanitized input in login form."),
        ("Cross-Site Scripting (XSS)", "Medium", "Reflected XSS detected in user comments."),
        ("Insecure HTTP Headers", "Low", "Missing Content-Security-Policy header."),
        ("Server Misconfiguration", "Medium", "Directory listing is enabled."),
        ("Open Port 22 (SSH)", "Low", "SSH service exposed on public IP.")
    ]
    vuln = random.choice(simulated_vulns)
    new_vuln = Vulnerability(name=vuln[0], severity=vuln[1], description=vuln[2])
    db.session.add(new_vuln)
    db.session.commit()
    flash(f"Vulnerability '{vuln[0]}' detected successfully!", "success")
    return redirect(url_for('index'))

@app.route('/delete/<int:id>')
def delete(id):
    vuln = Vulnerability.query.get_or_404(id)
    db.session.delete(vuln)
    db.session.commit()
    flash("Vulnerability deleted successfully!", "info")
    return redirect(url_for('index'))

@app.route('/download_report')
def download_report():
    vulns = Vulnerability.query.all()
    filename = "vulnerability_report.pdf"
    filepath = os.path.join(os.getcwd(), filename)

    pdf = canvas.Canvas(filepath, pagesize=A4)
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(180, 800, "Vulnerability Scan Report")

    pdf.setFont("Helvetica", 12)
    y = 770
    for vuln in vulns:
        pdf.drawString(50, y, f"ID: {vuln.id}")
        pdf.drawString(100, y, f"Name: {vuln.name}")
        pdf.drawString(100, y - 15, f"Severity: {vuln.severity}")
        pdf.drawString(100, y - 30, f"Description: {vuln.description}")
        pdf.drawString(100, y - 45, f"Date: {vuln.date_detected.strftime('%Y-%m-%d %H:%M:%S')}")
        y -= 70
        if y < 100:
            pdf.showPage()
            y = 800
            pdf.setFont("Helvetica", 12)
    pdf.save()
    return send_file(filepath, as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
