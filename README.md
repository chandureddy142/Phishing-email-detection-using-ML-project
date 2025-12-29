## 🧠 Technical Implementation (NLP & Machine Learning)

This project utilizes a full **Natural Language Processing (NLP)** pipeline to facilitate high-accuracy classification:

### 1. NLP Preprocessing Pipeline
- **Case Folding:** Normalizing text to lowercase to ensure uniform feature extraction.
- **Regex-based Noise Reduction:** Systematically removing punctuation, special characters, and digits to focus on linguistic intent.
- **Stop-Word Elimination:** Filtering out non-informative English words (e.g., 'the', 'is', 'at') to reduce feature noise.
- **Tokenization:** Breaking down raw email strings into individual word-level tokens for analysis.

### 2. Feature Engineering
- **TF-IDF Vectorization:** Implementing *Term Frequency-Inverse Document Frequency* to transform text into numerical vectors. This ensures that words unique to phishing (like 'suspended' or 'verify') are given higher mathematical weight than common words.
- **Feature Limiting:** Restricted to the top 5,000 features to maintain a low memory footprint and ensure <200ms inference latency.

### 3. Machine Learning Architecture
- **Algorithm:** Random Forest Classifier (Ensemble Learning).
- **Consensus Voting:** Utilizing 100 individual decision trees to determine the final class, significantly reducing the risk of overfitting.
- **Performance Metrics:** Achieved a **98.27% Accuracy** and a **0.98 F1-Score**, meeting all project safety and reliability benchmarks.