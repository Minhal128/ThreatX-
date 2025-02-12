import os
import pandas as pd
import numpy as np
import pickle
import sys
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from scipy.sparse import csr_matrix

def sanitization(web):
    """
    Sanitizes the given URL by breaking it into meaningful tokens.
    """
    web = web.lower()
    tokens = set()
    
    raw_slash = web.split('/')
    for part in raw_slash:
        raw_hyphen = part.split('-')
        for subpart in raw_hyphen:
            tokens.update(subpart.split('.'))

    tokens.discard('com')  # Remove 'com' if present
    return list(tokens)

# Get user input
url_input = input("🔍 Enter the URL to check (e.g., google.com): ").strip()
urls = [url_input]

# Whitelist filter
whitelist = {'hackthebox.eu', 'root-me.org', 'gmail.com'}
s_url = [i for i in urls if i not in whitelist]

try:
    # Ensure Classifier directory exists
    os.makedirs("Classifier", exist_ok=True)

    # Load the model
    with open("Classifier/pickel_model.pkl", 'rb') as f1:
        lgr = pickle.load(f1)

    with open("Classifier/pickel_vector.pkl", 'rb') as f2:
        vectorizer = pickle.load(f2)

    # Ensure vectorizer is fitted
    if not hasattr(vectorizer, 'vocabulary_'):
        raise ValueError("⚠️ Error: Vectorizer is not fitted. Retrain the model.")

    # Transform input URLs
    x = vectorizer.transform(s_url)
    y_predict = lgr.predict(x)

    # Append whitelist sites as 'good'
    predictions = list(y_predict) + ['good'] * len(whitelist)

    print(f"\n✅ The entered domain ({url_input}) is classified as: {predictions[0]}")

except FileNotFoundError:
    print("❌ Error: Model files not found. Running model training...")

    # Training new model since files are missing
    urls = ["example.com", "malicious-site.com", "safe-site.org"]
    labels = ["good", "bad", "good"]

    # Train new model
    vectorizer = TfidfVectorizer()
    X_train = vectorizer.fit_transform(urls)
    model = LogisticRegression()
    model.fit(X_train, labels)

    # Save the new model & vectorizer
    with open("Classifier/pickel_model.pkl", 'wb') as f:
        pickle.dump(model, f)

    with open("Classifier/pickel_vector.pkl", 'wb') as f:
        pickle.dump(vectorizer, f)

    print("✅ Model retrained successfully! Please run the script again.")

except Exception as e:
    print(f"❌ An error occurred: {e}")
