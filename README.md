# Phishing Website Detection – Machine Learning App

This project is a Streamlit web application that predicts whether a website is phishing or legitimate using a Random Forest model trained on a dataset of 30 handcrafted features.
The system extracts all required URL, domain, and webpage features automatically and performs real-time inference.

# 🚀 Features

Extracts all 30 phishing-detection features, including:

URL features (IP usage, “@”, redirects, prefix-suffix)

Domain/WHOIS/DNS features (age of domain, DNS record)

Webpage features (iframe, pop-ups)

Traffic & ranking features

Statistical blacklist features

Simple one-page Streamlit UI

Shows:

Extracted features

Final prediction (Phishing / Legitimate)

# 📁 Project Structure
phishing-detector/
│
├── 📄 app.py
├── ⚙️ feature_extract.py
├── 🤖 rf_model.pkl
├── 📦 requirements.txt
└── 📝 README.md


# 🔧 Installation
1. Clone the repository
`git clone <your-repo-url>
cd phishing-detector`

2. Install dependencies
`pip install -r requirements.txt`

4. Run the application
`streamlit run app.py`

# 🔍 How It Works

User enters a website URL

feature_extract.py extracts all 30 features

Features are placed in the correct order

## Model prediction is generated:

1 = Legitimate

-1 = Phishing

## The UI displays:

Prediction result

Extracted feature values

# Model

Model: RandomForestClassifier

Training: Done offline using the 30-feature phishing dataset

Output:

1 → Legitimate

-1 → Phishing

The trained model is saved as:

rf_model.pkl

# 📦 Requirements

All Python dependencies are listed in:

requirements.txt


Install using:

pip install -r requirements.txt

📚 References (Harvard Style)

Cloudflare (n.d.) What is a phishing attack? Available at: https://www.cloudflare.com/en-gb/learning/access-management/phishing-attack/
 (Accessed: DD Month YYYY).

UCI Machine Learning Repository (n.d.) Phishing Websites Dataset. Available at: https://archive.ics.uci.edu/
 (Accessed: DD Month YYYY).

Scikit-learn Developers (2024) Random Forest Classifier. Available at: https://scikit-learn.org/
 (Accessed: DD Month YYYY).

Streamlit Inc. (2024) Streamlit Documentation. Available at: https://docs.streamlit.io/
 (Accessed: DD Month YYYY).

✨ Author

Asilbek
Machine Learning Enthusiast
