#!/bin/bash

# --- PhishGuard Pro v5.0 Automation Script ---
echo "------------------------------------------------"
echo "🚀 Initializing PhishGuard Pro Setup..."
echo "------------------------------------------------"

# 1. Create Virtual Environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating Virtual Environment..."
    python3 -m venv venv
fi

# 2. Activate Environment
source venv/bin/activate

# 3. Upgrade Pip and Install Dependencies
echo "📥 Installing Required Libraries (Flask, SQLAlchemy, FPDF2, Requests)..."
pip install --upgrade pip
pip install flask flask-sqlalchemy fpdf2 requests joblib scikit-learn

# 4. Clean Whitelist File (Remove Windows hidden characters)
if [ -f "app/whitelist.txt" ]; then
    echo "🧹 Cleaning whitelist.txt..."
    sed -i 's/\r//' app/whitelist.txt
fi

# 5. Check for Model Files
if [ ! -f "models/phishing_model.pkl" ]; then
    echo "⚠️ WARNING: ML model files not found in /models/ folder!"
fi

# 6. Launch Application
echo "------------------------------------------------"
echo "✅ Setup Complete. Launching PhishGuard Dashboard..."
echo "------------------------------------------------"
python3 app/app.py