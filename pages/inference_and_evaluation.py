import streamlit as st
import pandas as pd
import pickle

st.title("🔮 Inference & Evaluation")

with open("data\Training Dataset.arff", "r") as f:
    data = arff.load(f)
df = pd.DataFrame(data['data'], columns=[attr[0] for attr in data['attributes']])

feature_cols = df.columns[:-1]

model = pickle.load(open("model/trained_model.pkl", "rb"))

scaler = None
try:
    scaler = pickle.load(open("model/preprocessor.pkl", "rb"))
except:
    st.info("No scaler found → using raw features.")

st.subheader("Enter Feature Values")

user_input = []
for col in feature_cols:
    val = st.number_input(col, value=float(df[col].mean()))
    user_input.append(val)

if st.button("Predict"):
    X = pd.DataFrame([user_input], columns=feature_cols)

    if scaler is not None:
        X = scaler.transform(X)

    pred = model.predict(X)[0]
    st.write(f"### Prediction: **{'Phishing' if pred==1 else 'Legit'}**")
