import streamlit as st
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score
import pickle
from scipy.io import arff
from xgboost import XGBClassifier
from catboost import CatBoostClassifier

st.title("🧠 Model Training")

# ---- Load ARFF File ----
with open("data/Training Dataset.arff", "r") as f:
    data = arff.load(f)
df = pd.DataFrame(data['data'], columns=[attr[0] for attr in data['attributes']])

X = df.drop("class", axis=1)
y = df["class"]

# ---- UI Controls ----
test_size = st.slider("Test Size", 0.1, 0.4, 0.2)

model_choice = st.selectbox(
    "Choose Model",
    ["Random Forest", "XGBoost", "CatBoost", "SGD Classifier"]
)

# Additional hyperparameters per model
if model_choice == "Random Forest":
    n_estimators = st.slider("Number of Trees", 50, 300, 100)

elif model_choice == "XGBoost":
    xgb_lr = st.slider("Learning Rate", 0.01, 0.5, 0.1)
    xgb_n = st.slider("Number of Estimators", 50, 300, 100)

elif model_choice == "CatBoost":
    cb_depth = st.slider("Depth", 2, 10, 6)
    cb_lr = st.slider("Learning Rate", 0.01, 0.5, 0.1)

elif model_choice == "SGD Classifier":
    sgd_alpha = st.slider("Alpha", 0.0001, 0.01, 0.001)


# ---- Train Button ----
if st.button("Train Model"):

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42
    )

    # ---- Choose Model ----
    if model_choice == "Random Forest":
        model = RandomForestClassifier(n_estimators=n_estimators)

    elif model_choice == "XGBoost":
        model = XGBClassifier(learning_rate=xgb_lr, n_estimators=xgb_n)

    elif model_choice == "CatBoost":
        model = CatBoostClassifier(
            depth=cb_depth,
            learning_rate=cb_lr,
            verbose=False
        )

    elif model_choice == "SGD Classifier":
        model = SGDClassifier(alpha=sgd_alpha, max_iter=2000)

    # ---- Train ----
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)

    st.write(f"### Accuracy: **{acc:.4f}**")

    # ---- Save Model ----
    file_map = {
        "Random Forest": "rf_model.pkl",
        "XGBoost": "xgb_model.pkl",
        "CatBoost": "cat_model.pkl",
        "SGD Classifier": "sgd_model.pkl"
    }

    save_path = f"models/{file_map[model_choice]}"

    with open(save_path, "wb") as f:
        pickle.dump(model, f)

    st.success(f"{model_choice} trained and saved successfully!")
    st.info(f"Saved as: **{save_path}**")
