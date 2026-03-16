import pandas as pd
import joblib
import os
import sys
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Add current directory to path to import utils
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils import clean_text

# Define Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, 'data', 'phishing_email.csv')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

# 1. Load Dataset
print(f"Loading dataset from: {DATA_PATH}")
df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()

# 2. Handle NaNs
df = df.dropna(subset=['text_combined', 'label'])

# 3. Cleaning
print("Cleaning data...")
df['clean_content'] = df['text_combined'].apply(clean_text)

# 4. Vectorization
print("Vectorizing text...")
tfidf = TfidfVectorizer(max_features=5000, stop_words='english')
X = tfidf.fit_transform(df['clean_content'])
y = df['label'] 

# 5. Split and Train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print("Training Random Forest...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# 6. Evaluate
y_pred = model.predict(X_test)
print("\n--- PERFORMANCE REPORT ---")
print(f"Accuracy: {accuracy_score(y_test, y_pred):.2%}")
print(classification_report(y_test, y_pred))

# 7. Save
joblib.dump(model, os.path.join(MODEL_DIR, 'phishing_model.pkl'))
joblib.dump(tfidf, os.path.join(MODEL_DIR, 'vectorizer.pkl'))
print(f"\nSuccess! Files saved in: {MODEL_DIR}")