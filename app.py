import streamlit as st
import pandas as pd
import pickle
import os
from feature_extract import extract_features  # Import the feature extraction logic

st.set_page_config(page_title="Phishing Detection", layout="centered")

# Custom CSS for aesthetics
st.markdown("""
<style>
    .stApp {
        background-color: #f0f2f6;
    }
    .main-header {
        color: #1a73e8;
        text-align: center;
        margin-bottom: 1rem;
    }
    .stButton>button {
        background-color: #4285f4;
        color: white;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: bold;
        transition: background-color 0.3s;
        width: 100%;
    }
    .stButton>button:hover {
        background-color: #3367d6;
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
        background-color: #e6f4ea;
        color: #1e8449;
        border: 1px solid #c8e6c9;
    }
    .stError {
        background-color: #fce8e6;
        color: #c53929;
        border: 1px solid #f4c7c3;
    }
</style>
""", unsafe_allow_html=True)


st.markdown("<h1 class='main-header'>🔍 Phishing Website Detection</h1>", unsafe_allow_html=True)
st.write("Enter a website URL below to check its likelihood of being a phishing site.")


# Load the trained model from the 'models' directory
model = None
model_path = "models/randomforest.pkl"

if os.path.exists(model_path):
    try:
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        st.sidebar.success("Model loaded successfully!")
    except Exception as e:
        # Display error if file exists but loading fails (e.g., incorrect format)
        st.error(f"Error loading model: {e}. Please ensure the model file is valid.")
else:
    # Display warning if the file is missing
    st.warning("Model file not found! Please place 'randomforest.pkl' in the 'models/' directory to enable real predictions.")


url = st.text_input("Enter website URL:", placeholder="https://www.google.com/login", key="url_input")

if st.button("Predict"):
    if url.strip() == "":
        st.error("Please enter a valid URL.")
    elif model is None:
        # Fallback if model is not loaded
        st.info("⚠️ Prediction cannot be made: Model not loaded. Check the file path and format.")
    else:
        with st.spinner('Extracting features and predicting...'):
            # 1. Extract features using the function from feature_extract.py
            feats = extract_features(url)

            # 2. Define the exact feature order expected by the model
            feature_order = [
                "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
                "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
                "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
                "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
                "Redirect","On_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
                "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
                "Statistical_report"
            ]

            # 3. Convert to DataFrame
            input_df = pd.DataFrame([feats], columns=feature_order)

            # 4. Predict
            try:
                prediction = model.predict(input_df)[0]

                if prediction == 1:
                    st.markdown("<div class='prediction-result stError'>⚠️ This website is **Phishing**!</div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div class='prediction-result stSuccess'>✅ This website appears **Legitimate**.</div>", unsafe_allow_html=True)
            except Exception as e:
                st.error(f"Prediction failed. Check that your model expects 30 input features. Error: {e}")
