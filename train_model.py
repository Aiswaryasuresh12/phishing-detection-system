import pandas as pd
import re
import pickle
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# Load dataset
data = pd.read_csv("phishing_dataset.csv")

def extract_features(url):

    length = len(url)

    has_at = 1 if "@" in url else 0
    has_dash = 1 if "-" in url else 0
    has_login = 1 if "login" in url.lower() else 0

    https = 1 if url.startswith("https") else 0

    ip = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

    domain = urlparse(url).netloc
    domain_length = len(domain)

    suspicious_length = 1 if domain_length > 25 else 0

    subdomains = domain.count('.')
    many_subdomains = 1 if subdomains > 2 else 0

    shorteners = ["bit.ly","tinyurl","goo.gl","t.co","shorturl"]
    short_url = 1 if any(s in url for s in shorteners) else 0

    suspicious_tlds = [".tk",".ml",".ga",".cf",".gq"]
    tld_flag = 1 if any(url.endswith(t) for t in suspicious_tlds) else 0

    random_domain = 1 if domain_length > 30 else 0

    return pd.Series([
        length,
        has_at,
        has_dash,
        has_login,
        https,
        ip,
        suspicious_length,
        many_subdomains,
        short_url,
        tld_flag,
        random_domain
    ])

# Apply feature extraction
data[['length','has_at','has_dash','has_login','https','ip','suspicious_length',
      'many_subdomains','short_url','tld_flag','random_domain']] = data['url'].apply(extract_features)

X = data[['length','has_at','has_dash','has_login','https','ip','suspicious_length',
          'many_subdomains','short_url','tld_flag','random_domain']]

y = data['label']

# Train test split
X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2)

# Train model
model = RandomForestClassifier()
model.fit(X_train,y_train)

# Save model
pickle.dump(model,open("phishing_model.pkl","wb"))

print("Model trained successfully with 11 features")