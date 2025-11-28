import streamlit as st
import pandas as pd
import pickle
import numpy as np
import os
from feature_extract import extract_features

st.set_page_config(page_title="Phishing Detection", layout="centered")

# ──────────────────────────────
#   Custom Styling
# ──────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #93b2d6; }
    .main-header { color: #0d47a1; text-align: center; margin-bottom: 1rem; }
    .stButton>button {
        background-color: #1976d2; color: white; border-radius: 8px;
        padding: 0.5rem 1rem; font-weight: bold; width: 100%;
    }
    .stButton>button:hover { background-color: #1565c0; }
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 class='main-header'>🔍 Phishing Website Detection</h1>", unsafe_allow_html=True)
st.write("Enter a website URL below to evaluate if it's legitimate or phishing.")


# ──────────────────────────────
#   Model Selector
# ──────────────────────────────
model_map = {
    "RandomForest (trained)": "models/random_forest.pkl",
    "XGBoost (trained)": "models/xgboost.pkl"
}

sel = st.selectbox("Choose model to use for prediction", list(model_map.keys()))
model_path = model_map[sel]

# Load the selected model
try:
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    st.sidebar.success(f"Loaded: {sel}")
except Exception as e:
    st.error(f"Failed to load model: {e}")
    st.stop()


# ──────────────────────────────
#   URL Input
# ──────────────────────────────
url = st.text_input("Enter website URL:", placeholder="https://example.com/login")

# Feature order (corrected to match training)
feature_order = [
    "having_IP_Address","URL_Length","Shortening_Service","having_At_Symbol",
    "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
    "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
    "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
    "Redirect","On_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
    "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
    "Statistical_report"
]


# ──────────────────────────────
#   Prediction Logic
# ──────────────────────────────
if st.button("Predict"):
    if not url.strip():
        st.error("Please enter a valid URL.")
    else:
        with st.spinner("Extracting features..."):
            feats = extract_features(url.strip())

        # Convert to DataFrame in correct order
        try:
            X = pd.DataFrame([[feats[k] for k in feature_order]], columns=feature_order)
        except Exception as e:
            st.error(f"Feature mismatch: {e}")
            st.stop()

        st.subheader("Extracted Features (first 10 shown):")
        st.json({k: feats[k] for k in list(feats.keys())[:10]})

        # ─── Prediction & Probability Calculation ───
        try:
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X)[0]
                classes = list(model.classes_)
                prob_map = {str(c): float(p) for c, p in zip(classes, probs)}
            else:
                # Fallback
                pred = model.predict(X)[0]
                prob_map = {str(pred): 1.0}
        except Exception as e:
            st.warning(f"Probability estimation failed: {e}")
            pred = model.predict(X)[0]
            prob_map = {str(pred): 1.0}

        # Extract prob for phishing vs legit
        p_phish = prob_map.get("1", prob_map.get(1, None))
        p_legit = prob_map.get("0", prob_map.get(0, None))

        # ──────────────────────────────
        #   Final Classification
        # ──────────────────────────────
        st.subheader("Prediction Result")

        if p_phish is not None and p_legit is not None:
            p_phish_pct = p_phish * 100
            p_legit_pct = p_legit * 100

            final_label = "Phishing" if p_phish_pct > 50 else "Legitimate"

            if final_label == "Phishing":
                st.error(f"⚠️ **Phishing** ({p_phish_pct:.1f}% phishing, {p_legit_pct:.1f}% legit)")
            else:
                st.success(f"✅ **Legitimate** ({p_legit_pct:.1f}% legit, {p_phish_pct:.1f}% phishing)")

            # Probability bar
            st.write("Phishing Probability")
            st.progress(int(p_phish_pct))

        else:
            # Just prediction
            pred = model.predict(X)[0]
            if pred == 1:
                st.error("⚠️ Predicted: Phishing")
            else:
                st.success("✅ Predicted: Legitimate")

        st.write("---")
        st.write("Raw probability output:")
        st.json(prob_map)
