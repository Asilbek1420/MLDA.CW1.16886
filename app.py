import streamlit as st
import pandas as pd
import pickle
import os
import numpy as np
from feature_extract import extract_features  

st.set_page_config(page_title="Phishing Detection", layout="centered")

# Custom CSS for aesthetics
st.markdown("""
<style>
    .stApp {
        background-color: #93b2d6;
    }
    .main-header {
        color: #0d47a1;
        text-align: center;
        margin-bottom: 1rem;
    }
    .stButton>button {
        background-color: #1976d2;
        color: white;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: bold;
        transition: background-color 0.3s;
        width: 100%;
    }
    .stButton>button:hover {
        background-color: #1565c0;
    }
    .prediction-result {
        padding: 15px;
        border-radius: 10px;
        font-size: 1.1rem;
        font-weight: bold;
        text-align: center;
        margin-top: 20px;
    }
    .stSuccess {
        background-color: #c8e6c9;
        color: #2e7d32;
        border: 1px solid #1b5e20;
    }
    .stError {
        background-color: #ef9a9a;
        color: #c62828;
        border: 1px solid #b71c1c;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 class='main-header'>🔍 Phishing Website Detection</h1>", unsafe_allow_html=True)
st.write("Enter a website URL below to check its likelihood of being a phishing site.")

# Load only RandomForest model
model_path = "models/randomforest.pkl"
if os.path.exists(model_path):
    try:
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        st.sidebar.success("RandomForest model loaded successfully!")
    except Exception as e:
        st.error(f"Error loading model: {e}")
        model = None
else:
    st.warning("Model file not found! Please place 'randomforest.pkl' in 'models/' directory.")
    model = None

# Input URL
url = st.text_input("Enter website URL:", placeholder="https://www.example.com")

if st.button("Predict"):
    if not url.strip():
        st.error("Please enter a valid URL.")
    elif model is None:
        st.info("⚠️ Prediction cannot be made: Model not loaded.")
    else:
        with st.spinner("Extracting features..."):
            feats = extract_features(url.strip())

        # Feature order and what the model expects
        feature_order = [
            "having_IP_Address","URL_Length","Shortening_Service","having_At_Symbol",
            "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
            "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
            "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
            "Redirect","On_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
            "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
            "Statistical_report"
        ]

        X = pd.DataFrame([[feats[k] for k in feature_order]], columns=feature_order)

        st.subheader("Extracted features (first 10 shown)")
        st.write(X.iloc[0].to_dict())

        # Predict and probabilities
        try:
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X)[0]
                classes = list(model.classes_)
                prob_map = {str(c): p for c, p in zip(classes, probs)}
            else:
                pred = model.predict(X)[0]
                prob_map = {str(pred): 1.0}
        except Exception as e:
            st.warning(f"Could not compute probabilities: {e}")
            pred = model.predict(X)[0]
            prob_map = {str(pred): 1.0}

        # Interpret probabilities
        p_phish = prob_map.get('1', prob_map.get(1, None))
        p_legit = prob_map.get('0', prob_map.get(0, None))

        if p_phish is not None and p_legit is not None:
            p_phish_pct = float(p_phish) * 100
            p_legit_pct = float(p_legit) * 100
            final = "Phishing" if p_phish_pct > 50 else "Legitimate"
            if final == "Phishing":
                st.error(f"⚠️ Model prediction: **{final}** ({p_phish_pct:.1f}% phishing, {p_legit_pct:.1f}% legitimate)")
            else:
                st.success(f"✅ Model prediction: **{final}** ({p_legit_pct:.1f}% legitimate, {p_phish_pct:.1f}% phishing)")
            st.progress(min(max(int(p_phish_pct), 0), 100))
            st.write(f"Phishing probability: **{p_phish_pct:.1f}%**")
            st.write(f"Legitimate probability: **{p_legit_pct:.1f}%**")
        else:
            st.write("Probability map returned by model:")
            st.json(prob_map)
            pred = model.predict(X)[0]
            if pred == 1:
                st.error("⚠️ Predicted: Phishing")
            else:
                st.success("✅ Predicted: Legitimate")

