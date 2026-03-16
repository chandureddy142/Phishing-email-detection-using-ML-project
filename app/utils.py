import re
import string

def clean_text(text):
    """
    Standardized cleaning function used for both 
    Training and Real-time Prediction.
    """
    # Convert to lowercase
    text = str(text).lower()
    # Remove punctuation
    text = re.sub(f"[{re.escape(string.punctuation)}]", "", text)
    # Remove numbers
    text = re.sub(r'\d+', '', text)
    # Remove extra whitespace
    text = " ".join(text.split())
    return text