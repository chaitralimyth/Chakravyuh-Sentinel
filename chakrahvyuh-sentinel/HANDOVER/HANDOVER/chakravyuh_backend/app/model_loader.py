"""
Loader for URL-based ML pipeline.
Preserves lr_model, rf_model, xgb_model, and feature_order for backward compatibility,
while providing predict_url(features) for the unified security pipeline.
"""

import os
import pickle

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")

lr_path = os.path.join(MODEL_DIR, "logistic-regression-model.pkl")
rf_path = os.path.join(MODEL_DIR, "randomforest-model.pkl")
xgb_path = os.path.join(MODEL_DIR, "xgb_model.pkl")
feature_path = os.path.join(MODEL_DIR, "features-order.pkl")

# Load models
with open(lr_path, "rb") as f:
    lr_model = pickle.load(f)

with open(rf_path, "rb") as f:
    rf_model = pickle.load(f)

with open(xgb_path, "rb") as f:
    xgb_model = pickle.load(f)

with open(feature_path, "rb") as f:
    feature_order = pickle.load(f)

# Classes for RF model
RF_CLASSES = list(rf_model.classes_) if hasattr(rf_model, "classes_") else [0, 1]


def predict_url(features: list) -> dict:
    """
    Run URL Random Forest model prediction.

    Returns:
        {
            "prediction": "malicious" | "normal",
            "prediction_value": int,
            "attack_probability": float,
            "confidence": float
        }
    """
    if len(features) != len(feature_order):
        raise ValueError(
            f"URL feature vector length mismatch: expected {len(feature_order)}, received {len(features)}"
        )

    prediction = int(rf_model.predict([features])[0])
    probabilities = rf_model.predict_proba([features])[0]

    # Class 1 represents malicious attack
    malicious_index = RF_CLASSES.index(1) if 1 in RF_CLASSES else 1
    prediction_index = RF_CLASSES.index(prediction) if prediction in RF_CLASSES else 0

    attack_probability = float(probabilities[malicious_index])
    confidence = float(probabilities[prediction_index])

    prediction_name = "malicious" if prediction == 1 else "normal"

    return {
        "prediction": prediction_name,
        "prediction_value": prediction,
        "attack_probability": attack_probability,
        "confidence": confidence,
    }
