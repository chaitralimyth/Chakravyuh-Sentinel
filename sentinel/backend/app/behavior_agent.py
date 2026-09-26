"""
Deterministic behavior decision layer.

Behavior model:
    0 -> attacker
    1 -> normal

Decision:
    attacker -> BLOCK
    normal   -> ALLOW
"""

from app.behavior_model_loader import (
    behavior_model,
    behavior_feature_order,
    BEHAVIOR_MODEL_SUPPORTS_PROBA,
)

EXPECTED_FEATURE_COUNT = 28

ATTACKER_LABEL = 0
NORMAL_LABEL = 1


def decide_behavior(
    prediction: int,
    confidence: float | None,
) -> dict:
    """
    Convert the numeric behavior model prediction
    into a deterministic security decision.
    """

    if prediction == ATTACKER_LABEL:
        return {
            "prediction": "attacker",
            "prediction_value": 0,
            "confidence": confidence,
            "action": "BLOCK",
            "reason": "Session behavior classified as attacker",
        }

    if prediction == NORMAL_LABEL:
        return {
            "prediction": "normal",
            "prediction_value": 1,
            "confidence": confidence,
            "action": "ALLOW",
            "reason": "Session behavior classified as normal",
        }

    raise ValueError(
        f"Unexpected behavior model prediction: {prediction!r}. "
        "Expected 0 (attacker) or 1 (normal)."
    )


def run_behavior_prediction(feature_vector: list) -> dict:
    """
    Run the complete behavior ML pipeline:

        feature vector
             ↓
        RandomForest model
             ↓
        numeric prediction
             ↓
        confidence
             ↓
        deterministic security decision
    """

    # ---------------------------------------------------------
    # Validate feature vector
    # ---------------------------------------------------------

    if len(feature_vector) != EXPECTED_FEATURE_COUNT:
        raise ValueError(
            "Behavior feature vector must contain exactly "
            f"{EXPECTED_FEATURE_COUNT} values, but received "
            f"{len(feature_vector)}."
        )

    if len(feature_vector) != len(behavior_feature_order):
        raise ValueError(
            "Behavior feature vector length does not match "
            "feature_columns_behaviour.pkl: "
            f"vector={len(feature_vector)}, "
            f"feature_order={len(behavior_feature_order)}."
        )

    # ---------------------------------------------------------
    # Run RandomForest prediction
    # ---------------------------------------------------------

    numeric_prediction = int(
        behavior_model.predict([feature_vector])[0]
    )

    # ---------------------------------------------------------
    # Calculate confidence
    # ---------------------------------------------------------

    confidence = None

    if BEHAVIOR_MODEL_SUPPORTS_PROBA:
        probabilities = behavior_model.predict_proba(
            [feature_vector]
        )[0]

        class_index = list(
            behavior_model.classes_
        ).index(numeric_prediction)

        confidence = float(
            probabilities[class_index]
        )

    # ---------------------------------------------------------
    # Deterministic agent decision
    # ---------------------------------------------------------

    return decide_behavior(
        numeric_prediction,
        confidence,
    )