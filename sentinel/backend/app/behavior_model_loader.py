"""
Loader for the BEHAVIOR ML pipeline artifacts only.

This is deliberately separate from app/model_loader.py, which belongs
to the existing URL ML pipeline.

Behavior artifacts:
- sentinel_behavior_model.pkl
- feature_columns_behaviour.pkl
- label_encoder.pkl

All three are loaded using joblib.load().
"""

import os

import joblib


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "sentinel_behavior_model.pkl",
)

FEATURE_ORDER_PATH = os.path.join(
    MODEL_DIR,
    "feature_columns_behaviour.pkl",
)

LABEL_ENCODER_PATH = os.path.join(
    MODEL_DIR,
    "label_encoder.pkl",
)


# ---------------------------------------------------------
# Load behavior pipeline artifacts
# ---------------------------------------------------------

behavior_model = joblib.load(MODEL_PATH)

behavior_feature_order = joblib.load(FEATURE_ORDER_PATH)

behavior_label_encoder = joblib.load(LABEL_ENCODER_PATH)


# ---------------------------------------------------------
# Basic artifact validation
# ---------------------------------------------------------

if not isinstance(behavior_feature_order, (list, tuple)):
    raise RuntimeError(
        "feature_columns_behaviour.pkl must contain a list or tuple "
        "of feature names."
    )

if len(behavior_feature_order) != 28:
    raise RuntimeError(
        f"Behavior model expects exactly 28 features, but "
        f"feature_columns_behaviour.pkl contains "
        f"{len(behavior_feature_order)}."
    )

if "label" in behavior_feature_order:
    raise RuntimeError(
        "feature_columns_behaviour.pkl unexpectedly contains 'label'. "
        "The label must never be passed to the behavior model."
    )


if not hasattr(behavior_model, "n_features_in_"):
    raise RuntimeError(
        "Behavior model does not expose n_features_in_. "
        "Cannot verify its expected feature count."
    )

if behavior_model.n_features_in_ != len(behavior_feature_order):
    raise RuntimeError(
        "Behavior model feature count does not match "
        "feature_columns_behaviour.pkl: "
        f"model={behavior_model.n_features_in_}, "
        f"features={len(behavior_feature_order)}."
    )


if not hasattr(behavior_label_encoder, "classes_"):
    raise RuntimeError(
        "label_encoder.pkl does not contain a valid LabelEncoder."
    )


# ---------------------------------------------------------
# Prediction capability
# ---------------------------------------------------------

BEHAVIOR_MODEL_SUPPORTS_PROBA = hasattr(
    behavior_model,
    "predict_proba",
)