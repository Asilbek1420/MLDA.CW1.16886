import streamlit as st
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

with open("data\Training Dataset.arff", "r") as f:
    data = arff.load(f)
df = pd.DataFrame(data['data'], columns=[attr[0] for attr in data['attributes']])
st.title("📊 Data Exploration")

df = pd.read_csv("data/phishing.csv")

st.subheader("Preview of Dataset")
st.dataframe(df.head())

st.subheader("Shape")
st.write(df.shape)

st.subheader("Summary Statistics")
st.write(df.describe())

st.subheader("Target Distribution")
fig, ax = plt.subplots()
sns.countplot(x=df['class'], ax=ax)
st.pyplot(fig)

st.subheader("Correlation Heatmap")
fig, ax = plt.subplots(figsize=(12,6))
sns.heatmap(df.corr(), cmap="coolwarm")
st.pyplot(fig)
