import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression

data = pd.read_csv("phishing_dataset.csv")

X = data['url']
y = data['label']

vectorizer = CountVectorizer()
X_vector = vectorizer.fit_transform(X)

model = LogisticRegression()
model.fit(X_vector, y)

def predict_url(url):
    url_vector = vectorizer.transform([url])
    prediction = model.predict(url_vector)
    return prediction[0]
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

data = pd.read_csv("dataset.csv")

X = data[['length','has_at','has_dash','has_login']]
y = data['label']

X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2)

model = RandomForestClassifier()

model.fit(X_train,y_train)

pickle.dump(model, open("phishing_model.pkl","wb"))

print("Model Trained Successfully")