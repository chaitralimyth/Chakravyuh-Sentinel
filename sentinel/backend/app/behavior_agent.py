"""
Behaviour ML prediction layer.

The behaviour model uses:

    0 -> attacker
    1 -> normal

This module performs prediction only.

The FINAL security decision is handled by the main
security agent/risk engine.
"""

from app.behavior_model_loader import (
    behavior_model,
    behavior_feature_order,
    BEHAVIOR_MODEL_SUPPORTS_PROBA,
)


EXPECTED_FEATURE_COUNT = 28

ATTACKER_LABEL = 0
NORMAL_LABEL = 1


def run_behavior_prediction(
    feature_vector: list,
) -> dict:

    # ---------------------------------------------------------
    # Validate feature count
    # ---------------------------------------------------------

    if len(feature_vector) != EXPECTED_FEATURE_COUNT:

        raise ValueError(
            "Behavior feature vector must contain exactly "
            f"{EXPECTED_FEATURE_COUNT} values, but received "
            f"{len(feature_vector)}."
        )

    if len(feature_vector) != len(
        behavior_feature_order
    ):

        raise ValueError(
            "Behavior feature vector length does not match "
            "feature_columns_behaviour.pkl."
        )

    # ---------------------------------------------------------
    # Prediction
    # ---------------------------------------------------------

    numeric_prediction = int(
        behavior_model.predict(
            [feature_vector]
        )[0]
    )

    # ---------------------------------------------------------
    # Probabilities
    # ---------------------------------------------------------

    prediction_confidence = None
    attack_probability = None

    if BEHAVIOR_MODEL_SUPPORTS_PROBA:
        probabilities = behavior_model.predict_proba(
            [feature_vector]
        )[0]

        classes = list(
            behavior_model.classes_
        )

        # 0 = attacker
        if ATTACKER_LABEL in classes:

            attacker_index = classes.index(
                ATTACKER_LABEL
            )

            attack_probability = float(
                probabilities[attacker_index]
            )

        # Confidence for predicted class
        if numeric_prediction in classes:

            predicted_index = classes.index(
                numeric_prediction
            )

            prediction_confidence = float(
                probabilities[predicted_index]
            )

    # ---------------------------------------------------------
    # Human-readable prediction
    # ---------------------------------------------------------

    if numeric_prediction == ATTACKER_LABEL:
        prediction = "attacker"

    elif numeric_prediction == NORMAL_LABEL:
        prediction = "normal"

    else:
        raise ValueError(
            "Unexpected behavior model prediction: "
            f"{numeric_prediction}. "
            "Expected 0 (attacker) or 1 (normal)."
        )

    return {
        "prediction": prediction,
        "prediction_value": numeric_prediction,
        "confidence": prediction_confidence,
        "attack_probability": attack_probability,
    }