import os
import re
import time
import joblib
import requests
import io
from flask import Flask, render_template, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime
from fpdf import FPDF

app = Flask(__name__)
CORS(app)

# --- 1. CONFIGURATION & DATABASE ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

SAFE_BROWSING_API_KEY = "AIzaSyB-sV2_XCYLI3BRdWJt7u1mG-K1_0MWWZU"
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, '..', 'models', 'phishing_model.pkl')
VECT_PATH = os.path.join(BASE_DIR, '..', 'models', 'vectorizer.pkl')
WHITELIST_PATH = os.path.join(BASE_DIR, 'whitelist.txt')

# Keywords for forensic analysis
PHISH_WORDS = ["urgent", "verify", "suspended", "password", "login", "bank", "account", "security", "update", "action required", "official"]

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    verdict = db.Column(db.String(20))
    score = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

try:
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECT_PATH)
except Exception as e:
    print(f"ERROR: Could not load models: {e}")

def load_whitelist():
    try:
        with open(WHITELIST_PATH, 'r', encoding='utf-8') as f:
            return set(line.strip().lower() for line in f if line.strip())
    except:
        return {"google.com", "paypal.com", "microsoft.com", "amazon.com", "apple.com"}

whitelist_set = load_whitelist()

# --- 2. DETECTION LAYERS ---

def get_google_reputation(url):
    if "testsafebrowsing" in url: return "DANGEROUS"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(SAFE_BROWSING_URL, json=payload, timeout=2)
        return "DANGEROUS" if "matches" in res.json() else "CLEAN"
    except: return "CLEAN"

def analyze_full_email(email_text):
    text_cleaned = str(email_text).lower()
    vec = vectorizer.transform([text_cleaned])
    ml_score = model.predict_proba(vec)[0][1] * 100
    
    # NEW: Extract Identified Phishing Content (Keywords)
    identified_words = [word for word in PHISH_WORDS if word in text_cleaned]
    
    links = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', email_text)
    all_flags, is_trusted, google_status, mal_count = [], False, "CLEAN", 0

    for link in links:
        target = link.split('@')[-1] if '@' in link else link
        if '@' in link: all_flags.append("Obfuscation: '@' symbol used")

        host_match = re.search(r'https?://(?:www\.)?([^/]+)', target.lower())
        if not host_match: continue
        hostname = host_match.group(1)

        if len(hostname.split('.')) >= 2 and '.'.join(hostname.split('.')[-2:]) in whitelist_set:
            is_trusted = True
            continue

        link_bad = False
        for brand in ["google", "paypal", "microsoft", "amazon", "apple"]:
            if brand in hostname:
                all_flags.append(f"Identity Spoof: {hostname} mimics {brand}")
                ml_score += 45
                link_bad = True

        if hostname.count('.') > 3:
            all_flags.append("Excessive Subdomains")
            ml_score += 20
            link_bad = True

        if get_google_reputation(link) == "DANGEROUS":
            return "PHISHING", 100.0, ["Google API Blacklist"], "DANGEROUS", len(links), False, 1, ["MALICIOUS_LINK"]

        if link_bad: mal_count += 1

    if is_trusted and not all_flags:
        return "LEGITIMATE", 0.0, ["Identity Verified"], "CLEAN", len(links), True, 0, []

    final_score = max(0, min(100, round(ml_score, 2)))
    verdict = "PHISHING" if final_score >= 60 else "LEGITIMATE"
    
# NEW: Logic for the Reputation Status override
    display_reputation = google_status
    if verdict == "PHISHING":
        display_reputation = "DANGEROUS"
    elif google_status == "CLEAN" and verdict == "LEGITIMATE":
        display_reputation = "CLEAN"

    return verdict, final_score, list(set(all_flags)), display_reputation, len(links), is_trusted, mal_count, identified_words

# --- 3. ROUTES ---

@app.route('/')
def index():
    history = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(5).all()
    total = ScanHistory.query.count()
    phish = ScanHistory.query.filter_by(verdict='PHISHING').count()
    return render_template('index.html', history=history, total_scans=total, total_phishing=phish)

@app.route('/predict', methods=['POST'])
def predict():
    content = request.form.get('email_content', '')
    # Unpack the new 8th variable (identified_words)
    v, s, f, g, c, t, m, identified_words = analyze_full_email(content)
    
    db.session.add(ScanHistory(verdict=v, score=s))
    db.session.commit()
    
    history = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(5).all()
    total = ScanHistory.query.count()
    phish = ScanHistory.query.filter_by(verdict='PHISHING').count()
    
    return render_template('index.html', prediction=v, risk_score=s, flags=f, 
                           google_status=g, link_count=c, is_trusted=t, 
                           mal_count=m, identified_words=identified_words, 
                           original_text=content, history=history, total_scans=total, total_phishing=phish)

@app.route('/predict_api', methods=['POST'])
def predict_api():
    data = request.get_json()
    content = data.get('email_content', '')
    v, s, f, g, c, t, m, identified_words = analyze_full_email(content)
    
    db.session.add(ScanHistory(verdict=v, score=s))
    db.session.commit()
    
    return jsonify({
        "prediction": v,
        "score": s,
        "flags": f,
        "malicious_links": m,
        "identified_words": identified_words
    })

@app.route('/api/history', methods=['GET'])
def get_api_history():
    history = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(10).all()
    results = [{"verdict": h.verdict, "score": h.score, "time": h.timestamp.strftime('%H:%M:%S')} for h in history]
    return jsonify(results)

@app.route('/download_report', methods=['POST'])
def download_report():
    pdf = FPDF()
    pdf.add_page()
    
    # Header
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(30, 41, 59) # Slate 800
    pdf.cell(0, 15, "PHISHGUARD FORENSIC AUDIT REPORT", ln=True, align='C')
    pdf.set_draw_color(59, 130, 246) # Blue Border
    pdf.line(10, 25, 200, 25)
    pdf.ln(10)
    
    # Summary Table
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_fill_color(241, 245, 249)
    pdf.cell(95, 10, " METRIC", border=1, fill=True)
    pdf.cell(95, 10, " VALUE", border=1, fill=True, ln=True)
    
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(95, 10, " Security Verdict", border=1)
    pdf.set_text_color(220, 38, 38) if request.form.get('prediction') == "PHISHING" else pdf.set_text_color(22, 163, 74)
    pdf.cell(95, 10, f" {request.form.get('prediction')}", border=1, ln=True)
    
    pdf.set_text_color(0, 0, 0)
    pdf.cell(95, 10, " Risk Probability", border=1)
    pdf.cell(95, 10, f" {request.form.get('score')}%", border=1, ln=True)
    
    pdf.cell(95, 10, " Infrastructure Reputation", border=1)
    pdf.cell(95, 10, f" {request.form.get('google_status')}", border=1, ln=True)
    pdf.ln(10)
    
    # NEW: Identified Phishing Keywords Section
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 10, "IDENTIFIED PHISHING KEYWORDS (FORENSIC MARKERS):", ln=True)
    pdf.set_font("Helvetica", "", 10)
    
    # Get the list of words from the hidden form input
    words = request.form.getlist('identified_words')
    if words:
        pdf.set_text_color(185, 28, 28) # Dark Red
        word_string = ", ".join([w.upper() for w in words])
        pdf.multi_cell(0, 8, f"The AI detected the following high-risk linguistic markers: {word_string}")
    else:
        pdf.cell(0, 10, "No specific keyword-based markers detected.", ln=True)
    
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)
    
    # Original Content
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "ANALYZED CONTENT STREAM:", ln=True)
    pdf.set_font("Courier", "", 9)
    pdf.set_fill_color(250, 250, 250)
    pdf.multi_cell(0, 5, request.form.get('original_text'), border=1, fill=True)
    
    # Footer
    pdf.set_y(-25)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 10, f"Report generated by PhishGuard 5.0 on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align='C')

    out = io.BytesIO()
    pdf.output(out)
    out.seek(0)
    return send_file(out, as_attachment=True, download_name=f"PhishGuard_Report_{datetime.now().strftime('%H%M%S')}.pdf")

if __name__ == "__main__":
    app.run(debug=True, port=5000)