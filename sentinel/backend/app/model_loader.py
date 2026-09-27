"""
Loader for the URL-based ML pipeline.

The final Chakravyuh architecture uses:
    Random Forest -> URL threat detection

Logistic Regression and XGBoost are kept in the models directory
for experimentation/backward compatibility, but are not part of
the production security pipeline.
"""

import os
import pickle


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models",
)


RF_MODEL_PATH = os.path.join(
    MODEL_DIR,
    "randomforest-model.pkl",
)

FEATURE_ORDER_PATH = os.path.join(
    MODEL_DIR,
    "features-order.pkl",
)


# ---------------------------------------------------------
# Load Random Forest URL model
# ---------------------------------------------------------

with open(RF_MODEL_PATH, "rb") as f:
    rf_model = pickle.load(f)


# ---------------------------------------------------------
# Load feature order
# ---------------------------------------------------------

with open(FEATURE_ORDER_PATH, "rb") as f:
    feature_order = pickle.load(f)


# ---------------------------------------------------------
# Validate artifacts
# ---------------------------------------------------------

if not isinstance(feature_order, (list, tuple)):
    raise RuntimeError(
        "features-order.pkl must contain a list or tuple."
    )


if not hasattr(rf_model, "predict"):
    raise RuntimeError(
        "randomforest-model.pkl is not a valid ML model."
    )


if not hasattr(rf_model, "predict_proba"):
    raise RuntimeError(
        "Random Forest model must support predict_proba()."
    )


if hasattr(rf_model, "n_features_in_"):

    if rf_model.n_features_in_ != len(feature_order):

        raise RuntimeError(
            "Random Forest feature count does not match "
            "features-order.pkl: "
            f"model={rf_model.n_features_in_}, "
            f"features={len(feature_order)}."
        )


# ---------------------------------------------------------
# Model information
# ---------------------------------------------------------

RF_CLASSES = list(rf_model.classes_)

if len(RF_CLASSES) != 2:
    raise RuntimeError(
        "URL Random Forest model must be a binary classifier."
    )


def predict_url(features: list) -> dict:
    """
    Run URL model prediction.

    Returns:
        prediction
        prediction_value
        attack_probability
        confidence
    """

    if len(features) != len(feature_order):
        raise ValueError(
            "URL feature vector length does not match "
            f"model feature count. "
            f"Expected {len(feature_order)}, "
            f"received {len(features)}."
        )

    prediction = rf_model.predict([features])[0]

    probabilities = rf_model.predict_proba([features])[0]

    # Existing project assumes class 1 represents malicious.
    # Keep this explicit rather than silently guessing.
    if 1 not in RF_CLASSES:
        raise RuntimeError(
            "Expected URL model class 1 to represent the "
            "malicious class."
        )

    malicious_index = RF_CLASSES.index(1)
    prediction_index = RF_CLASSES.index(prediction)

    attack_probability = float(
        probabilities[malicious_index]
    )

    confidence = float(
        probabilities[prediction_index]
    )

    prediction_name = (
        "malicious"
        if int(prediction) == 1
        else "normal"
    )

    return {
        "prediction": prediction_name,
        "prediction_value": int(prediction),
        "attack_probability": attack_probability,
        "confidence": confidence,
    }