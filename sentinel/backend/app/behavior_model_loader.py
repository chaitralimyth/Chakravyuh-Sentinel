"""
Loader for the Sentinel behaviour ML pipeline.
"""

import os
import joblib

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models",
)

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

# =========================================================
# Load
# =========================================================

behavior_model = joblib.load(
    MODEL_PATH
)

behavior_feature_order = joblib.load(
    FEATURE_ORDER_PATH
)

behavior_label_encoder = joblib.load(
    LABEL_ENCODER_PATH
)

# =========================================================
# Validate feature order
# =========================================================

if not isinstance(
    behavior_feature_order,
    (list, tuple),
):

    raise RuntimeError(
        "feature_columns_behaviour.pkl must contain "
        "a list or tuple."
    )


if len(
    behavior_feature_order
) != 28:

    raise RuntimeError(
        "Behavior model expects exactly 28 features, "
        f"but feature_columns_behaviour.pkl contains "
        f"{len(behavior_feature_order)}."
    )


if "label" in behavior_feature_order:

    raise RuntimeError(
        "The label column must not be included "
        "in the behaviour feature vector."
    )


# =========================================================
# Validate model
# =========================================================

if not hasattr(
    behavior_model,
    "predict",
):

    raise RuntimeError(
        "Behaviour model does not support predict()."
    )

if not hasattr(
    behavior_model,
    "n_features_in_",
):

    raise RuntimeError(
        "Behaviour model does not expose n_features_in_."
    )

if (
    behavior_model.n_features_in_
    != len(behavior_feature_order)
):

    raise RuntimeError(
        "Behaviour model feature count does not match "
        "feature_columns_behaviour.pkl."
    )

# =========================================================
# Label validation
# =========================================================

if not hasattr(
    behavior_model,
    "classes_",
):

    raise RuntimeError(
        "Behaviour model does not expose classes_."
    )

if 0 not in behavior_model.classes_:

    raise RuntimeError(
        "Behaviour model must use class 0 for attacker."
    )

if 1 not in behavior_model.classes_:

    raise RuntimeError(
        "Behaviour model must use class 1 for normal."
    )

BEHAVIOR_MODEL_SUPPORTS_PROBA = hasattr(
    behavior_model,
    "predict_proba",
)