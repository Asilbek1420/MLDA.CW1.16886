import streamlit as st
import pandas as pd
import pickle
from feature_extract import extract_features  # import the function above

st.title("🔍 Phishing Website Detection")

# Load your trained model
with open("models/trained_model.pkl", "rb") as f:
    model = pickle.load(f)

url = st.text_input("Enter website URL:", placeholder="https://example.com")

if st.button("Predict"):
    if url.strip() == "":
        st.error("Please enter a valid URL.")
    else:
        # Extract features
        feats = extract_features(url)

        # Convert to DataFrame with correct column order
        feature_order = [
            "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
            "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
            "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
            "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
            "Redirect","On_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
            "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
            "Statistical_report"
        ]

        input_df = pd.DataFrame([feats], columns=feature_order)

        # Predict
        prediction = model.predict(input_df)[0]

        if prediction == 1:
            st.error("⚠️ This website is **Phishing**!")
        else:
            st.success("✅ This website appears **Legitimate**.")
