🔍 Phishing Website Detection App
Overview

This project is a Machine Learning-based web application to detect phishing websites. Users can input a website URL, and the app predicts whether the site is legitimate or phishing.

The app leverages the UCI Phishing Websites dataset and trained models including:

RandomForestClassifier

XGBoostClassifier

CatBoostClassifier

GradientBoostingClassifier

K-Nearest Neighbors (KNN)

Support Vector Machine (SVM)

The app extracts 30 features from a given URL, similar to the dataset features, to perform real-time predictions.

Features

URL-based Feature Extraction: Automatically extracts all 30 UCI phishing dataset features from a URL.

Multiple ML Models: Supports several trained models for experimentation.

Real-time Prediction: Users can enter a URL and get a prediction immediately.

Streamlit Interface: Interactive, user-friendly web interface.

Model Evaluation: Full metrics (precision, recall, F1-score) available for each model.

Installation

Clone the repository

git clone <repository_url>
cd phishing-website-detection


Install dependencies

pip install -r requirements.txt


Ensure trained models are in models/ folder
For example: models/trained_model.pkl.

Usage

Run the Streamlit app

streamlit run app.py


Navigate to the Inference Page

Enter a website URL in the input box.

Click Predict.

The app will display:

⚠️ Phishing

✅ Legitimate

Dataset

Source: UCI Phishing Websites Dataset

Features: 30 URL and website-based features (numeric/categorical).

Labels: 1 = Phishing, -1 = Legitimate.

Model Details
Model	Type	Key Hyperparameters
RandomForestClassifier	Ensemble / Tree-based	n_estimators=200, class_weight='balanced'
XGBoostClassifier	Boosting / Tree-based	n_estimators=200, learning_rate=0.1
CatBoostClassifier	Boosting / Tree-based	iterations=200, learning_rate=0.1
GradientBoostingClassifier	Boosting / Tree-based	n_estimators=200, learning_rate=0.1
KNeighborsClassifier	Instance-Based	n_neighbors=7
SVM (Linear)	Margin-Based	kernel='linear', class_weight='balanced'

Evaluation Metrics: Precision, Recall, F1-score, Accuracy, TPR, TNR, AUC

Ethical Considerations

False Negatives: Some phishing websites may bypass detection. Users should not rely solely on the tool for security.

False Positives: Legitimate websites may be incorrectly flagged.

Disclaimer: This tool is for educational and research purposes and does not guarantee complete protection.

Future Improvements

Implement real-time WHOIS, web traffic, and PageRank features for more accurate predictions.

Add probability scores for phishing risk.

Deploy as a cloud-hosted web app for global accessibility.

Add logging and tracking of predictions for analysis.

Here is my link to the app: https://mldacw116886-ppmxruxbzeur9wbm59h8ur.streamlit.app/

References

UCI Phishing Websites Dataset: https://archive.ics.uci.edu/dataset/327/phishing+websites

Scikit-Learn: https://scikit-learn.org

Streamlit: https://streamlit.io
